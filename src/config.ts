import { backgroundTimer } from "./timer.ts";
import { exec, execSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { CONFIG_DIR_NAME, getPackageDir } from "@earendil-works/pi-coding-agent";
import { parseClientCredentialsConfig, createClientCredentialsResolver } from "./oauth-client-credentials.ts";
import type { AuthResolver, ConfigLoadOptions, ConfigScope, ConfigWarning, McpExposure, ProviderTokenLookup, ResolvedHttpServer, ResolvedServer } from "./types.ts";

export type McpServerConfigValidator = (name: string, raw: unknown) => string | Record<string, any>;

const SERVER_NAME_RE = /^[A-Za-z0-9_-]+$/;
const MCP_EXPOSURES = ["codemode", "deferred", "direct", "hidden"] as const;
const MCP_EXPOSURE_ALIASES: Record<string, string> = { "codemode-deferred": "codemode" };
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function isStringRecord(value: unknown): value is Record<string, string> {
  return record(value) && Object.values(value).every((entry) => typeof entry === "string");
}

function isLoopbackRedirectUri(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname) && url.search === "" && url.hash === "";
}

function isClientMetadataDocumentCallback(callbackUrl: string | undefined): boolean {
  if (callbackUrl === undefined) return true;
  const url = new URL(callbackUrl);
  return url.hostname !== "[::1]" && url.pathname === "/callback";
}

function validateOAuthFallback(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (!record(value)) return "oauth must be an object";
  if (value.clientId !== undefined && typeof value.clientId !== "string") return "oauth.clientId must be a string";
  if (value.clientSecret !== undefined && typeof value.clientSecret !== "string") return "oauth.clientSecret must be a string";
  const port = value.callbackPort;
  if (port !== undefined && (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535)) {
    return "oauth.callbackPort must be a port number";
  }
  if (value.callbackUrl !== undefined) {
    if (typeof value.callbackUrl !== "string" || !isLoopbackRedirectUri(value.callbackUrl)) {
      return "oauth.callbackUrl must be an http URI on localhost, 127.0.0.1, or [::1] without query or fragment";
    }
    const urlPort = new URL(value.callbackUrl).port;
    if (urlPort && port !== undefined && Number(urlPort) !== port) {
      return "oauth.callbackUrl and oauth.callbackPort name different ports";
    }
  }
  if (value.scope !== undefined && typeof value.scope !== "string") return "oauth.scope must be a string";
  if (value.clientName !== undefined && (typeof value.clientName !== "string" || !value.clientName.trim())) {
    return "oauth.clientName must be a non-empty string";
  }
  const registration = value.clientRegistration;
  if (registration !== undefined && registration !== "auto" && registration !== "dcr") {
    if (registration !== "cimd") return 'oauth.clientRegistration must be "auto", "dcr", or "cimd"';
    if (value.clientId !== undefined || value.clientName !== undefined) {
      return 'oauth.clientRegistration "cimd" cannot be combined with oauth.clientId or oauth.clientName';
    }
    if (!isClientMetadataDocumentCallback(typeof value.callbackUrl === "string" ? value.callbackUrl : undefined)) {
      return 'oauth.clientRegistration "cimd" requires oauth.callbackUrl on localhost or 127.0.0.1 with path /callback';
    }
  }
  const metadataUrl = value.authServerMetadataUrl;
  if (metadataUrl !== undefined) {
    const url = typeof metadataUrl === "string" && URL.canParse(metadataUrl) ? new URL(metadataUrl) : undefined;
    if (!url || !(url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname)))) {
      return "oauth.authServerMetadataUrl must be an https URL, or http on localhost, 127.0.0.1, or [::1]";
    }
  }
  return undefined;
}

/**
 * Fallback validator matching Pi's `validateMcpServerConfig` when Pi's internal
 * `core/mcp-servers.js` is not available on disk (e.g. compiled Bun/SEA binaries).
 */
export function validateMcpServerConfigFallback(name: string, raw: unknown): string | Record<string, any> {
  if (!SERVER_NAME_RE.test(name)) return `invalid server name "${name}" (use letters, digits, "_" and "-")`;
  if (!record(raw)) return `server "${name}" must be an object`;

  const resolved: Record<string, any> = { ...raw };
  if (typeof resolved.exposure === "string" && resolved.exposure in MCP_EXPOSURE_ALIASES) {
    resolved.exposure = MCP_EXPOSURE_ALIASES[resolved.exposure];
  }
  if (record(resolved.toolExposure)) {
    resolved.toolExposure = Object.fromEntries(
      Object.entries(resolved.toolExposure).map(([tool, entry]) => [
        tool,
        typeof entry === "string" && entry in MCP_EXPOSURE_ALIASES ? MCP_EXPOSURE_ALIASES[entry] : entry,
      ]),
    );
  }

  if (resolved.enabled !== undefined && typeof resolved.enabled !== "boolean") {
    return `server "${name}": enabled must be a boolean`;
  }
  if (resolved.description !== undefined && typeof resolved.description !== "string") {
    return `server "${name}": description must be a string`;
  }
  if (resolved.timeout !== undefined && (typeof resolved.timeout !== "number" || !(resolved.timeout > 0))) {
    return `server "${name}": timeout must be a positive number of seconds`;
  }

  const { type, url, command } = resolved;
  if (type === "sse") {
    return `server "${name}": legacy SSE transport is not supported; use the streamable HTTP URL`;
  }

  let kind: "http" | "stdio" | undefined;
  if (typeof url === "string" && (type === undefined || type === "http" || type === "streamable-http")) {
    if (!URL.canParse(url) || !/^https?:$/.test(new URL(url).protocol)) {
      return `server "${name}": url must be an http or https URL`;
    }
    if (resolved.headers !== undefined && !isStringRecord(resolved.headers)) {
      return `server "${name}": headers must map names to strings`;
    }
    const oauthErr = validateOAuthFallback(resolved.oauth);
    if (oauthErr) return `server "${name}": ${oauthErr}`;
    kind = "http";
  } else if (typeof command === "string" && (type === undefined || type === "stdio")) {
    if (resolved.args !== undefined && !(Array.isArray(resolved.args) && resolved.args.every((arg: unknown) => typeof arg === "string"))) {
      return `server "${name}": args must be an array of strings`;
    }
    if (resolved.env !== undefined && !isStringRecord(resolved.env)) {
      return `server "${name}": env must map names to strings`;
    }
    if (resolved.cwd !== undefined && typeof resolved.cwd !== "string") {
      return `server "${name}": cwd must be a string`;
    }
    kind = "stdio";
  } else {
    return `server "${name}" needs either "command" (stdio) or "url" (streamable HTTP)`;
  }

  const exposures = MCP_EXPOSURES.map((value) => `"${value}"`).join(", ");
  if (resolved.exposure !== undefined && (typeof resolved.exposure !== "string" || !(MCP_EXPOSURES as readonly string[]).includes(resolved.exposure))) {
    return `server "${name}": exposure must be one of ${exposures}`;
  }
  if (resolved.toolExposure !== undefined) {
    if (!record(resolved.toolExposure)) {
      return `server "${name}": toolExposure must map tool names to exposures`;
    }
    for (const [tool, value] of Object.entries(resolved.toolExposure)) {
      if (typeof value !== "string" || !(MCP_EXPOSURES as readonly string[]).includes(value)) {
        return `server "${name}": toolExposure "${tool}" must be one of ${exposures}`;
      }
    }
  }

  if (kind === "http" && resolved.auth !== undefined) {
    if (!record(resolved.auth) || typeof resolved.auth.provider !== "string" || !resolved.auth.provider) {
      return `server "${name}": auth.provider must be a provider name`;
    }
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && !LOOPBACK_HOSTS.includes(parsed.hostname)) {
      return `server "${name}": auth requires an https URL, or http on localhost, 127.0.0.1, or [::1]`;
    }
  }

  return resolved;
}

/**
 * Resolve Pi's internal validator via `getPackageDir()` (which works through Pi's
 * jiti extension alias without requiring `@earendil-works/pi-coding-agent` in local
 * `node_modules`), falling back to `validateMcpServerConfigFallback` when internal
 * files are not present on disk (e.g. compiled Bun/SEA binaries).
 */
export async function resolveMcpServerValidator(packageDir?: string): Promise<McpServerConfigValidator> {
  let root: string | undefined = packageDir;
  if (!root) {
    try {
      root = getPackageDir();
    } catch {
      return validateMcpServerConfigFallback;
    }
  }
  const candidates = [
    join(root, "dist", "core", "mcp-servers.js"),
    join(root, "src", "core", "mcp-servers.ts"),
  ];
  for (const candidate of candidates) {
    try {
      const mod = await import(pathToFileURL(candidate).href) as { validateMcpServerConfig?: unknown };
      if (typeof mod.validateMcpServerConfig === "function") {
        return mod.validateMcpServerConfig as McpServerConfigValidator;
      }
    } catch {
      // Try next candidate or fall back.
    }
  }
  return validateMcpServerConfigFallback;
}

let cachedValidatorPromise: Promise<McpServerConfigValidator> | undefined;
function getMcpServerValidator(): Promise<McpServerConfigValidator> {
  cachedValidatorPromise ??= resolveMcpServerValidator();
  return cachedValidatorPromise;
}

export interface DeclaredSubscription {
  name: string;
  arguments?: Record<string, unknown>;
  delivery?: "auto" | "push" | "poll";
  maxAgeMs?: number;
  holdSettle?: boolean;
}
export type ConfiguredServer = ResolvedServer & { subscribe?: DeclaredSubscription[] };
export function expandHome(p: string): string {
  return p === "~" ? homedir() : p.startsWith("~/") || (process.platform === "win32" && p.startsWith("~\\")) ? join(homedir(), p.slice(2)) : p;
}
export function getAgentDir(): string {
  return process.env.PI_CODING_AGENT_DIR ? expandHome(process.env.PI_CODING_AGENT_DIR) : join(homedir(), CONFIG_DIR_NAME, "agent");
}
export function mcpNamespace(name: string): string { return "mcp__" + name.replace(/-/g, "_"); }
function expandEnvVars(value: string): string {
  return value.replace(/\$\$|\$!|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (match, braced, bare) => {
    if (match === "$$") return "$";
    if (match === "$!") return "!";
    const name = braced ?? bare;
    const result = process.env[name];
    if (!result) throw new Error(`Missing environment variable: ${name}`);
    return result;
  });
}

const COMMAND_CACHE_TTL_MS = 5_000;
const commandCache = new Map<string, { value: string; expiresAt: number }>();
const commandInflight = new Map<string, Promise<string>>();

export function invalidateConfigCommandCache(rawValue?: string): void {
  if (rawValue === undefined) {
    commandCache.clear();
  } else {
    commandCache.delete(rawValue);
  }
}

export function resolveConfigValue(value: string): string {
  if (value.startsWith("!")) {
    let output: string;
    try { output = execSync(value.slice(1), { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"], windowsHide: true }).trim(); }
    catch { throw new Error("Failed to resolve MCP config shell command"); }
    if (!output) throw new Error("MCP config shell command returned empty output");
    return output;
  }
  return expandEnvVars(value);
}

export async function resolveConfigValueAsync(value: string, opts?: { bypassCache?: boolean }): Promise<string> {
  if (!value.startsWith("!")) {
    return expandEnvVars(value);
  }
  if (!opts?.bypassCache) {
    const cached = commandCache.get(value);
    if (cached && Date.now() < cached.expiresAt) return cached.value;
    const inflight = commandInflight.get(value);
    if (inflight) return inflight;
  }
  const cmd = value.slice(1);
  const run = new Promise<string>((resolve, reject) => {
    exec(
      cmd,
      { encoding: "utf8", timeout: 10_000, windowsHide: true },
      (err, stdout) => {
        if (err) {
          reject(new Error("Failed to resolve MCP config shell command"));
          return;
        }
        const trimmed = stdout.trim();
        if (!trimmed) {
          reject(new Error("MCP config shell command returned empty output"));
          return;
        }
        commandCache.set(value, { value: trimmed, expiresAt: Date.now() + COMMAND_CACHE_TTL_MS });
        resolve(trimmed);
      },
    );
  }).finally(() => {
    commandInflight.delete(value);
  });
  commandInflight.set(value, run);
  return run;
}
function record(v: unknown): v is Record<string, any> { return typeof v === "object" && v !== null && !Array.isArray(v); }

/** Comma-separated server names: trim, drop empties. Unset or blank means no filter. */
export function serverNameSet(value: string | undefined): Set<string> | undefined {
  if (value === undefined) return undefined;
  const names = value.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
  return names.length > 0 ? new Set(names) : undefined;
}

/**
 * Whether this extension should open a client.
 * `ext: false` wins over `PI_MCP_EXT_INCLUDE`. `PI_MCP_EXT_EXCLUDE` always skips.
 * A non-empty include list skips names that are not listed. Unset env vars do not throw.
 */
export function shouldConnect(
  server: { name: string; ext?: boolean },
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (server.ext === false) return false;
  const exclude = serverNameSet(env.PI_MCP_EXT_EXCLUDE);
  if (exclude?.has(server.name)) return false;
  const include = serverNameSet(env.PI_MCP_EXT_INCLUDE);
  if (include && !include.has(server.name)) return false;
  return true;
}

/** Whether `PI_MCP_EXT_SKILL_AUTO_APPROVE` lists this server, so its skills load without the approval prompt. */
export function skillAutoApprove(server: string, env: NodeJS.ProcessEnv = process.env): boolean {
  return serverNameSet(env.PI_MCP_EXT_SKILL_AUTO_APPROVE)?.has(server) ?? false;
}

/** `ext` is read from the raw entry because validation strips unknown keys. */
function rawExt(raw: unknown): boolean | undefined {
  if (!record(raw) || !Object.prototype.hasOwnProperty.call(raw, "ext")) return undefined;
  if (typeof raw.ext !== "boolean") return undefined;
  return raw.ext;
}
function extIsInvalid(raw: unknown): boolean {
  return record(raw) && Object.prototype.hasOwnProperty.call(raw, "ext") && typeof raw.ext !== "boolean";
}
function withoutExt(raw: Record<string, any>): Record<string, any> {
  if (!Object.prototype.hasOwnProperty.call(raw, "ext")) return raw;
  const { ext: _ext, ...rest } = raw;
  return rest;
}
function subscriptions(value: unknown): DeclaredSubscription[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const result: DeclaredSubscription[] = [];
  for (const raw of value) {
    const v = typeof raw === "string" ? { name: raw } : raw;
    if (!record(v) || typeof v.name !== "string" || !v.name.trim() ||
      (v.arguments !== undefined && !record(v.arguments)) ||
      (v.delivery !== undefined && !["auto", "push", "poll"].includes(v.delivery)) ||
      (v.maxAgeMs !== undefined && (!Number.isInteger(v.maxAgeMs) || v.maxAgeMs < 0)) ||
      (v.holdSettle !== undefined && typeof v.holdSettle !== "boolean")) return undefined;
    result.push({ name: v.name, ...(v.arguments === undefined ? {} : { arguments: v.arguments }), ...(v.delivery === undefined ? {} : { delivery: v.delivery }), ...(v.maxAgeMs === undefined ? {} : { maxAgeMs: v.maxAgeMs }), ...(v.holdSettle === undefined ? {} : { holdSettle: v.holdSettle }) });
  }
  return result;
}
export async function loadServerConfigs(opts: ConfigLoadOptions): Promise<{ servers: ConfiguredServer[]; warnings: ConfigWarning[] }> {
  const validateMcpServerConfig = await getMcpServerValidator();
  const entries = new Map<string, { config: Record<string, any>; scope: ConfigScope; ext?: boolean }>();
  const warnings: ConfigWarning[] = [];
  function add(name: string, raw: unknown, scope: ConfigScope) {
    const warn = (message: string) => warnings.push({ scope, server: name, message });
    if (scope === "session" && [...entries.keys()].some(n => mcpNamespace(n) === mcpNamespace(name))) return;
    if (extIsInvalid(raw)) { warn("ext must be a boolean"); return; }
    const ext = rawExt(raw);
    if (scope === "project" && record(raw) && raw.command === undefined && raw.url === undefined && raw.type === undefined) {
      const base = entries.get(name);
      if (!base) { warn("Partial override needs a global server"); return; }
      if (Object.keys(raw).some(k => !["enabled", "exposure", "toolExposure", "ext"].includes(k))) { warn("An override can only set enabled, exposure, toolExposure, ext"); return; }
      const config = validateMcpServerConfig(name, { ...withoutExt(base.config), ...withoutExt(raw) });
      if (typeof config === "string") warn(config);
      else entries.set(name, { ...base, config, ...(ext !== undefined ? { ext } : {}) });
      return;
    }
    const config = validateMcpServerConfig(name, record(raw) ? withoutExt(raw) : raw);
    if (typeof config === "string") { warn(config); return; }
    if ([...entries.keys()].some(n => n !== name && mcpNamespace(n) === mcpNamespace(name))) { warn("Server namespace conflicts with an earlier entry"); return; }
    if (scope === "project" && "url" in config && config.auth) { warn("auth is only allowed in global or session scope"); return; }
    entries.set(name, { config, scope, ...(ext !== undefined ? { ext } : {}) });
  }
  function file(path: string, scope: ConfigScope) {
    let parsed: unknown;
    try { parsed = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")); }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") warnings.push({ scope, message: `${path}: ${String(e)}` }); return; }
    if (!record(parsed) || (parsed.mcpServers !== undefined && !record(parsed.mcpServers))) { warnings.push({ scope, message: `${path}: expected an mcpServers object` }); return; }
    for (const [name, raw] of Object.entries(parsed.mcpServers ?? {})) add(name, raw, scope);
  }
  file(join(getAgentDir(), "mcp.json"), "global");
  if (opts.isProjectTrusted) file(join(opts.cwd, CONFIG_DIR_NAME, "mcp.json"), "project");
  for (const s of opts.sessionServers) add(s.name, s.config, "session");
  const servers: ConfiguredServer[] = [];
  for (const [name, { config: c, scope, ext }] of entries) {
    const base = {
      name,
      namespace: mcpNamespace(name),
      scope,
      enabled: c.enabled !== false,
      timeoutMs: (c.timeout ?? 60) * 1000,
      ...(typeof c.description === "string" ? { description: c.description } : {}),
      ...(typeof c.exposure === "string" ? { exposure: c.exposure as McpExposure } : {}),
      ...(record(c.toolExposure) ? { toolExposure: c.toolExposure as Record<string, McpExposure> } : {}),
      ...(ext !== undefined ? { ext } : {}),
    };
    let server: ConfiguredServer;
    if (typeof c.url === "string" && c.type !== "stdio") {
      const cc = parseClientCredentialsConfig(c, c.url, scope);
      if (cc.warning) warnings.push({ scope, server: name, message: cc.warning });
      server = {
        ...base,
        transport: "http",
        url: c.url,
        headers: c.headers ?? {},
        ...(c.auth ? { authProvider: c.auth.provider } : {}),
        ...(cc.config ? { clientCredentials: cc.config } : {}),
      };
    } else {
      server = {
        ...base,
        transport: "stdio",
        command: c.command,
        args: c.args ?? [],
        env: c.env ?? {},
        ...(c.cwd === undefined ? {} : { cwd: c.cwd }),
      };
    }
    if (c.subscribe !== undefined) {
      const sub = subscriptions(c.subscribe);
      if (sub) server.subscribe = sub;
      else warnings.push({ scope, server: name, message: "Invalid subscribe value; ignored" });
    }
    servers.push(server);
  }
  return { servers, warnings };
}
function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    backgroundTimer(timer);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function createAuthResolver(server: ResolvedHttpServer, providerToken: ProviderTokenLookup, fetchOverride?: typeof fetch): AuthResolver {
  const ccResolver = server.clientCredentials
    ? createClientCredentialsResolver(server, { fetch: fetchOverride, resolveValue: resolveConfigValueAsync })
    : undefined;
  const path = join(getAgentDir(), "mcp-auth.json");
  let signature = "", states: Record<string, any> = {}, last: string | undefined;
  function stored(): string | undefined {
    try {
      const st = statSync(path), sig = `${st.mtimeMs}:${st.size}`;
      if (sig !== signature) {
        const parsed = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
        states = record(parsed) ? parsed : {}; signature = sig;
      }
    } catch { states = {}; signature = ""; }
    const url = String(new URL(server.url));
    const token = (states[`${server.namespace}|${url}`] ?? states[url])?.tokens?.access_token;
    return typeof token === "string" && token ? `Bearer ${token}` : undefined;
  }
  async function resolve(signal?: AbortSignal, bypassCommandCache = false): Promise<string | undefined> {
    const header = Object.entries(server.headers).find(([key]) => key.toLowerCase() === "authorization");
    if (header) return resolveConfigValueAsync(header[1], { bypassCache: bypassCommandCache });
    if (server.authProvider) { const token = await providerToken(server.authProvider); return token ? `Bearer ${token}` : undefined; }
    if (ccResolver) return ccResolver.authorization(signal);
    return stored();
  }
  return {
    async authorization(signal?: AbortSignal) { last = await resolve(signal); return last; },
    async refreshAfterUnauthorized(signal?: AbortSignal) {
      const header = Object.entries(server.headers).find(([key]) => key.toLowerCase() === "authorization");
      if (header) {
        if (!header[1].startsWith("!")) return false;
        const before = last;
        invalidateConfigCommandCache(header[1]);
        last = await resolve(signal, true);
        return last !== before;
      }
      if (!server.authProvider && ccResolver) {
        return ccResolver.refreshAfterUnauthorized(signal);
      }
      const before = last;
      await abortableDelay(250, signal);
      if (signal?.aborted) return false;
      last = await resolve(signal);
      return last !== before;
    },
  };
}
