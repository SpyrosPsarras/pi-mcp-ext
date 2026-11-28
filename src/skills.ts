/**
 * Skills over MCP (`io.modelcontextprotocol/skills`, `SEP-2640` / `extensions/skills/overview.md`).
 *
 * Implements `skills/list` and `skills/get` without eager file fetches, manifest-bound user
 * approval (revoked automatically when any file URI/digest/frontmatter changes, and never
 * persisted across loads for `"dynamic"` manifests), strict SHA-256 + byte-size + YAML
 * frontmatter + parent-segment verification, origin-bound supporting-file reads, optional
 * `resources/directory/read`, and an isolated read-only verified cache for Pi's `resources_discover`.
 */

import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { parseFrontmatter } from "@earendil-works/pi-coding-agent";
import { canonicalJson } from "./events.ts";
import { frameMcpTag, paginateMcp } from "./framing.ts";
import { createPrivateSubdir } from "./temp-files.ts";
import { backgroundTimer } from "./timer.ts";
import { CUSTOM_SKILL_APPROVALS } from "./types.ts";
import type {
  EngineHost,
  JsonObject,
  McpLogLevel,
  McpLogMessage,
  ServerClient,
} from "./types.ts";

const MAX_SKILL_FILES = 512;
const MAX_SKILL_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_PROMPT_SKILLS_PER_SERVER = 100;
const MAX_PROMPT_DESCRIPTION_CHARS = 1024;

export interface SkillResourceManifestItem {
  uri: string;
  digest: string;
  size: number;
}

export interface SkillEntry {
  uri: string;
  frontmatter: JsonObject & { name: string; description: string };
  resources: SkillResourceManifestItem[] | "dynamic";
}

export interface LoadedSkillResult {
  server: string;
  uri: string;
  name: string;
  description: string;
  frontmatter: JsonObject;
  content: string;
  cacheDir?: string;
  supportingUris: string[];
}

type LogOpts = { logLevel?: McpLogLevel; onLog?: (entry: McpLogMessage) => void };

export interface ListedSkills {
  server: string;
  skills: SkillEntry[];
}

export function formatSkillsPromptSection(listed: readonly ListedSkills[]): string | undefined {
  const lines: string[] = [];
  for (const { server, skills } of listed) {
    const visible = skills.filter((s) => s.frontmatter["disable-model-invocation"] !== true);
    for (const skill of visible.slice(0, MAX_PROMPT_SKILLS_PER_SERVER)) {
      lines.push(
        frameMcpTag(
          "mcp_skill",
          { server, name: skill.frontmatter.name, uri: skill.uri },
          skill.frontmatter.description.slice(0, MAX_PROMPT_DESCRIPTION_CHARS),
        ),
      );
    }
  }
  if (lines.length === 0) return undefined;
  return [
    'These skills come from MCP servers. When a task matches a skill\'s description, load it with the mcp_skills tool (action "load" with its server and uri) and follow it.',
    ...lines,
  ].join("\n");
}

export interface SkillsEngineApi {
  restore(allEntries: readonly unknown[]): void;
  serverReady(server: string): Promise<void>;
  serverRemoved(server: string): void;
  listed(): ListedSkills[];
  refreshStale(waitMs: number): Promise<void>;
  onSkillsListed(listener: (server: string, skills: SkillEntry[]) => void): () => void;
  list(server: string, opts?: LogOpts): Promise<SkillEntry[]>;
  get(server: string, uri: string, opts?: LogOpts): Promise<SkillEntry>;
  load(
    server: string,
    uri: string,
    opts?: LogOpts & {
      autoApprove?: boolean;
      approve?: (info: {
        server: string;
        entry: SkillEntry;
        fileCount: number | "dynamic";
        totalBytes: number | "dynamic";
      }) => Promise<boolean>;
    },
  ): Promise<LoadedSkillResult>;
  readFile(server: string, skillUri: string, fileUriOrRelativePath: string, opts?: LogOpts): Promise<{
    server: string;
    skillUri: string;
    uri: string;
    content: string;
    size: number;
  }>;
  directory(
    server: string,
    uri: string,
    cursor?: string,
    opts?: LogOpts,
  ): Promise<{ resources: Array<{ uri: string; name: string; mimeType?: string }>; nextCursor?: string }>;
  verifiedSkillPaths(): string[];
  shutdown(): Promise<void>;
}

function isRecord(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function sha256Digest(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function shortHash(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

function toReqOpts(opts?: LogOpts) {
  return opts?.logLevel || opts?.onLog
    ? {
        ...(opts.logLevel ? { logLevel: opts.logLevel } : {}),
        ...(opts.onLog ? { onLog: opts.onLog } : {}),
      }
    : undefined;
}

/** Parse YAML frontmatter at the start of a `SKILL.md` document using full YAML 1.2 parsing. */
export function parseSkillFrontmatter(markdown: string): JsonObject | undefined {
  if (!/^---\r?\n/.test(markdown)) return undefined;
  try {
    const { frontmatter } = parseFrontmatter<Record<string, unknown>>(markdown);
    if (!isRecord(frontmatter) || Object.keys(frontmatter).length === 0) return undefined;
    return frontmatter;
  } catch {
    return undefined;
  }
}

function parentSegmentOfSkillUri(uri: string): string | undefined {
  const withoutQuery = uri.split(/[?#]/, 1)[0];
  const schemeSep = withoutQuery.indexOf("://");
  const pathPart = schemeSep >= 0 ? withoutQuery.slice(schemeSep + 3) : withoutQuery;
  const segments = pathPart.split("/").filter((s) => s.length > 0);
  // e.g. skill://code-review/SKILL.md -> segments ["code-review", "SKILL.md"]
  if (segments.length < 2) return undefined;
  if (segments[segments.length - 1] !== "SKILL.md") return undefined;
  try {
    return decodeURIComponent(segments[segments.length - 2]);
  } catch {
    return undefined;
  }
}

function skillRootPrefix(skillUri: string): string {
  const idx = skillUri.lastIndexOf("/SKILL.md");
  return idx >= 0 ? skillUri.slice(0, idx) : skillUri;
}

function isWithinSkillRoot(skillUri: string, targetUri: string): boolean {
  if (targetUri === skillUri) return true;
  const root = skillRootPrefix(skillUri);
  if (!targetUri.startsWith(`${root}/`)) return false;
  const rel = targetUri.slice(root.length + 1);
  if (!rel || rel.split("/").some((seg) => seg === ".." || seg === "." || seg.length === 0)) {
    return false;
  }
  return true;
}

function resolveSkillChildUri(skillUri: string, ref: string): string {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(ref)) {
    if (!isWithinSkillRoot(skillUri, ref)) {
      throw new Error(`Skill file URI "${ref}" is outside skill root "${skillRootPrefix(skillUri)}"`);
    }
    return ref;
  }
  const root = skillRootPrefix(skillUri);
  const normalizedRel = posix.normalize(ref).replace(/^\/+/, "");
  if (!normalizedRel || normalizedRel === "." || normalizedRel.startsWith("..")) {
    throw new Error(`Relative skill path "${ref}" escapes skill root`);
  }
  const resolved = `${root}/${normalizedRel}`;
  if (!isWithinSkillRoot(skillUri, resolved)) {
    throw new Error(`Skill file URI "${resolved}" escapes skill root`);
  }
  return resolved;
}

function parseSkillEntry(raw: unknown): SkillEntry {
  if (!isRecord(raw) || typeof raw.uri !== "string" || !isRecord(raw.frontmatter)) {
    throw new Error("Invalid MCP skill entry: missing uri or frontmatter");
  }
  const fm = raw.frontmatter;
  if (typeof fm.name !== "string" || !fm.name || typeof fm.description !== "string") {
    throw new Error(`Invalid MCP skill entry "${raw.uri}": frontmatter requires name and description`);
  }
  const parentSeg = parentSegmentOfSkillUri(raw.uri);
  if (parentSeg !== fm.name) {
    throw new Error(
      `Invalid MCP skill entry "${raw.uri}": parent directory "${parentSeg ?? ""}" does not match frontmatter.name "${fm.name}"`,
    );
  }

  if (raw.resources === "dynamic") {
    return {
      uri: raw.uri,
      frontmatter: fm as JsonObject & { name: string; description: string },
      resources: "dynamic",
    };
  }

  if (!Array.isArray(raw.resources) || raw.resources.length === 0) {
    throw new Error(`Invalid MCP skill entry "${raw.uri}": resources manifest must be non-empty or "dynamic"`);
  }
  if (raw.resources.length > MAX_SKILL_FILES) {
    throw new Error(
      `MCP skill "${raw.uri}" exceeds maximum file limit (${raw.resources.length} > ${MAX_SKILL_FILES})`,
    );
  }

  let totalBytes = 0;
  let hasSkillMd = false;
  const manifest: SkillResourceManifestItem[] = [];
  for (const item of raw.resources) {
    if (
      !isRecord(item) ||
      typeof item.uri !== "string" ||
      typeof item.digest !== "string" ||
      !item.digest.startsWith("sha256:") ||
      typeof item.size !== "number" ||
      !Number.isInteger(item.size) ||
      item.size < 0
    ) {
      throw new Error(`Invalid manifest item in MCP skill "${raw.uri}"`);
    }
    if (!isWithinSkillRoot(raw.uri, item.uri)) {
      throw new Error(`Invalid manifest item "${item.uri}" outside skill root "${skillRootPrefix(raw.uri)}"`);
    }
    totalBytes += item.size;
    if (totalBytes > MAX_SKILL_BYTES) {
      throw new Error(`MCP skill "${raw.uri}" exceeds 16 MiB limit`);
    }
    if (item.uri === raw.uri) hasSkillMd = true;
    manifest.push({ uri: item.uri, digest: item.digest, size: item.size });
  }
  if (!hasSkillMd) {
    throw new Error(`Invalid MCP skill "${raw.uri}": manifest does not include SKILL.md`);
  }

  return {
    uri: raw.uri,
    frontmatter: fm as JsonObject & { name: string; description: string },
    resources: manifest,
  };
}

function approvalFingerprint(server: string, entry: SkillEntry): string | undefined {
  if (entry.resources === "dynamic") return undefined;
  return sha256Digest(
    Buffer.from(
      canonicalJson({
        server,
        uri: entry.uri,
        frontmatter: entry.frontmatter,
        resources: entry.resources,
      }),
      "utf8",
    ),
  );
}

function writeReadOnlyFile(filePath: string, bytes: Buffer): void {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (existsSync(filePath)) {
    try {
      chmodSync(filePath, 0o600);
    } catch {
      /* ignore */
    }
  }
  writeFileSync(filePath, bytes, { mode: 0o444 });
  try {
    chmodSync(filePath, 0o444);
  } catch {
    /* ignore */
  }
}

export function createSkillsEngine(host: EngineHost): SkillsEngineApi {
  const retained = new Map<string, SkillEntry>(); // key: `${server}\0${uri}`
  const loadedSkills = new Set<string>(); // key: `${server}\0${uri}`
  const approvedFingerprints = new Set<string>();
  const listings = new Map<string, { skills: SkillEntry[]; freshUntil: number }>();
  const refreshes = new Map<string, Promise<void>>();
  const listedListeners = new Set<(server: string, skills: SkillEntry[]) => void>();
  let cacheRoot: string | undefined;
  let shutDown = false;

  function getCacheRoot(): string {
    if (!cacheRoot) {
      cacheRoot = createPrivateSubdir("skills");
    }
    return cacheRoot;
  }

  const entryKey = (server: string, uri: string) => `${server}\0${uri}`;
  const onAbort = () => void shutdown();
  host.signal?.addEventListener?.("abort", onAbort, { once: true });

  function requireSkillsClient(server: string): ServerClient {
    const client = host.getClient(server);
    if (!client) throw new Error(`Unknown or not-ready MCP server: ${server}`);
    if (!client.state.skills) {
      throw new Error(
        `MCP server "${server}" does not advertise both resources and io.modelcontextprotocol/skills.`,
      );
    }
    return client;
  }

  function restore(allEntries: readonly unknown[]): void {
    for (const raw of allEntries) {
      if (!isRecord(raw) || raw.customType !== CUSTOM_SKILL_APPROVALS || !isRecord(raw.data)) {
        continue;
      }
      const fp = raw.data.fingerprint;
      if (typeof fp === "string" && fp.startsWith("sha256:")) {
        approvedFingerprints.add(fp);
      }
    }
  }

  async function list(server: string, opts?: LogOpts): Promise<SkillEntry[]> {
    const client = requireSkillsClient(server);
    let ttlMs: number | undefined;
    const skills = await paginateMcp(
      client,
      "skills/list",
      (res) => {
        const pageTtl = typeof res.ttlMs === "number" && res.ttlMs > 0 ? res.ttlMs : 0;
        ttlMs = Math.min(ttlMs ?? pageTtl, pageTtl);
        const page: SkillEntry[] = [];
        const rawSkills = Array.isArray(res.skills) ? res.skills : [];
        for (const raw of rawSkills) {
          try {
            page.push(parseSkillEntry(raw));
          } catch (err) {
            host.log("warn", `[${server}] Skipping invalid MCP skill entry: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
        return page;
      },
      {},
      toReqOpts(opts),
    );
    for (const entry of skills) retain(server, entry);
    if (shutDown) return skills;
    listings.set(server, { skills, freshUntil: Date.now() + (ttlMs ?? 0) });
    for (const fn of [...listedListeners]) {
      try {
        fn(server, skills);
      } catch {
        /* ignore */
      }
    }
    return skills;
  }

  function startRefresh(server: string): Promise<void> {
    const existing = refreshes.get(server);
    if (existing) return existing;
    const refresh: Promise<void> = list(server)
      .then(
        () => {},
        (err) => {
          host.log("warn", `MCP server "${server}" skills listing failed: ${err instanceof Error ? err.message : String(err)}`);
        },
      )
      .finally(() => {
        if (refreshes.get(server) === refresh) refreshes.delete(server);
      });
    refreshes.set(server, refresh);
    return refresh;
  }

  function serverReady(server: string): Promise<void> {
    if (shutDown || !host.getClient(server)?.state.skills) return Promise.resolve();
    listings.set(server, { skills: [], freshUntil: 0 });
    return startRefresh(server);
  }

  function serverRemoved(server: string): void {
    listings.delete(server);
    refreshes.delete(server);
  }

  function listed(): ListedSkills[] {
    const out: ListedSkills[] = [];
    for (const [server, { skills }] of listings) {
      if (host.getClient(server)) out.push({ server, skills });
    }
    return out;
  }

  async function refreshStale(waitMs: number): Promise<void> {
    const now = Date.now();
    const pending: Promise<void>[] = [];
    for (const [server, listing] of listings) {
      if (listing.freshUntil > now || !host.getClient(server)) continue;
      pending.push(startRefresh(server));
    }
    if (pending.length === 0) return;
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      Promise.all(pending),
      new Promise<void>((resolve) => {
        timer = backgroundTimer(setTimeout(resolve, waitMs));
      }),
    ]);
    clearTimeout(timer);
  }

  async function get(server: string, uri: string, opts?: LogOpts): Promise<SkillEntry> {
    const client = requireSkillsClient(server);
    const res = await client.request<JsonObject>("skills/get", { uri }, toReqOpts(opts));
    return retain(server, parseSkillEntry(res.skill));
  }

  function retain(server: string, entry: SkillEntry): SkillEntry {
    const key = entryKey(server, entry.uri);
    const previous = retained.get(key);
    if (previous && canonicalJson(previous) === canonicalJson(entry)) return previous;
    loadedSkills.delete(key);
    retained.set(key, entry);
    return entry;
  }

  async function fetchRawResourceBytes(
    client: ServerClient,
    uri: string,
    opts?: LogOpts,
  ): Promise<{ bytes: Buffer; text: string }> {
    const res = await client.request<JsonObject>("resources/read", { uri }, toReqOpts(opts));
    const contents = Array.isArray(res.contents) ? res.contents.filter(isRecord) : [];
    const first = contents[0];
    if (!first) {
      throw new Error(`Empty resources/read response for skill resource "${uri}"`);
    }
    if (typeof first.text === "string") {
      return { bytes: Buffer.from(first.text, "utf8"), text: first.text };
    }
    if (typeof first.blob === "string") {
      const bytes = Buffer.from(first.blob, "base64");
      return { bytes, text: bytes.toString("utf8") };
    }
    throw new Error(`Skill resource "${uri}" contained neither text nor blob`);
  }

  async function refreshOnVerificationFailure(server: string, uri: string): Promise<void> {
    loadedSkills.delete(entryKey(server, uri));
    try {
      await get(server, uri);
    } catch {
      retained.delete(entryKey(server, uri));
    }
  }

  async function load(
    server: string,
    uri: string,
    opts?: LogOpts & {
      autoApprove?: boolean;
      approve?: (info: {
        server: string;
        entry: SkillEntry;
        fileCount: number | "dynamic";
        totalBytes: number | "dynamic";
      }) => Promise<boolean>;
    },
  ): Promise<LoadedSkillResult> {
    const client = requireSkillsClient(server);
    const k = entryKey(server, uri);
    const entry = retained.get(k) ?? (await get(server, uri, opts));
    if (opts?.autoApprove && entry.uri !== uri) {
      throw new Error(
        `MCP server "${server}" returned "${entry.uri}" for "${uri}"; auto-approval covers only the requested skill.`,
      );
    }

    const fp = approvalFingerprint(server, entry);
    const alreadyApproved = fp !== undefined && approvedFingerprints.has(fp);
    if (!alreadyApproved && !opts?.autoApprove) {
      if (!opts?.approve) {
        throw new Error(
          `Cannot load unapproved MCP skill "${entry.frontmatter.name}" from "${server}": interactive user approval is required.`,
        );
      }
      const fileCount = entry.resources === "dynamic" ? "dynamic" : entry.resources.length;
      const totalBytes =
        entry.resources === "dynamic"
          ? "dynamic"
          : entry.resources.reduce((acc, item) => acc + item.size, 0);
      const approved = await opts.approve({ server, entry, fileCount, totalBytes });
      if (!approved) {
        throw new Error(`User declined loading MCP skill "${entry.frontmatter.name}" from "${server}".`);
      }
      if (fp !== undefined) {
        approvedFingerprints.add(fp);
        host.appendEntry(CUSTOM_SKILL_APPROVALS, {
          server,
          uri: entry.uri,
          fingerprint: fp,
          approvedAt: new Date().toISOString(),
        });
      }
    }

    const { bytes, text } = await fetchRawResourceBytes(client, entry.uri, opts);
    if (bytes.length > MAX_SKILL_BYTES) {
      await refreshOnVerificationFailure(server, entry.uri);
      throw new Error(`MCP skill "${entry.uri}" exceeded 16 MiB byte limit`);
    }

    if (entry.resources !== "dynamic") {
      const manifestItem = entry.resources.find((r) => r.uri === entry.uri);
      if (!manifestItem) {
        await refreshOnVerificationFailure(server, entry.uri);
        throw new Error(`MCP skill "${entry.uri}" missing SKILL.md in retained manifest`);
      }
      if (bytes.length !== manifestItem.size) {
        await refreshOnVerificationFailure(server, entry.uri);
        throw new Error(
          `MCP skill "${entry.uri}" size mismatch: expected ${manifestItem.size} bytes, got ${bytes.length}; refreshed entry`,
        );
      }
      const actualDigest = sha256Digest(bytes);
      if (actualDigest !== manifestItem.digest) {
        await refreshOnVerificationFailure(server, entry.uri);
        throw new Error(
          `MCP skill "${entry.uri}" SHA-256 digest mismatch: expected ${manifestItem.digest}, got ${actualDigest}; refreshed entry`,
        );
      }
    }

    const parsedFm = parseSkillFrontmatter(text);
    if (!parsedFm || canonicalJson(parsedFm) !== canonicalJson(entry.frontmatter)) {
      await refreshOnVerificationFailure(server, entry.uri);
      throw new Error(
        `MCP skill "${entry.uri}" frontmatter mismatch against retained entry; refreshed entry`,
      );
    }

    const current = retained.get(k) === entry;
    let cacheDir: string | undefined;
    if (current && entry.resources !== "dynamic") {
      const skillParent = join(getCacheRoot(), shortHash(server), shortHash(entry.uri), entry.frontmatter.name);
      const skillMdPath = join(skillParent, "SKILL.md");
      writeReadOnlyFile(skillMdPath, bytes);
      cacheDir = skillParent;
    }
    if (current) loadedSkills.add(k);

    const supportingUris =
      entry.resources === "dynamic"
        ? []
        : entry.resources.filter((r) => r.uri !== entry.uri).map((r) => r.uri);

    return {
      server,
      uri: entry.uri,
      name: entry.frontmatter.name,
      description: entry.frontmatter.description,
      frontmatter: entry.frontmatter,
      content: text,
      ...(cacheDir ? { cacheDir } : {}),
      supportingUris,
    };
  }

  async function readFile(
    server: string,
    skillUri: string,
    fileUriOrRelativePath: string,
    opts?: LogOpts,
  ): Promise<{ server: string; skillUri: string; uri: string; content: string; size: number }> {
    const client = requireSkillsClient(server);
    const k = entryKey(server, skillUri);
    const entry = retained.get(k);
    if (!entry || !loadedSkills.has(k)) {
      throw new Error(
        `MCP skill "${skillUri}" on server "${server}" must be approved and loaded before reading supporting files.`,
      );
    }
    const targetUri = resolveSkillChildUri(skillUri, fileUriOrRelativePath);

    if (entry.resources !== "dynamic") {
      const manifestItem = entry.resources.find((r) => r.uri === targetUri);
      if (!manifestItem) {
        throw new Error(
          `URI "${targetUri}" is not in the retained manifest of skill "${skillUri}" on "${server}"`,
        );
      }
      const { bytes, text } = await fetchRawResourceBytes(client, targetUri, opts);
      if (bytes.length !== manifestItem.size) {
        await refreshOnVerificationFailure(server, skillUri);
        throw new Error(
          `Supporting file "${targetUri}" size mismatch (expected ${manifestItem.size}, got ${bytes.length}); refreshed skill entry`,
        );
      }
      const actualDigest = sha256Digest(bytes);
      if (actualDigest !== manifestItem.digest) {
        await refreshOnVerificationFailure(server, skillUri);
        throw new Error(
          `Supporting file "${targetUri}" SHA-256 mismatch (expected ${manifestItem.digest}, got ${actualDigest}); refreshed skill entry`,
        );
      }
      return { server, skillUri, uri: targetUri, content: text, size: bytes.length };
    }

    const { bytes, text } = await fetchRawResourceBytes(client, targetUri, opts);
    if (bytes.length > MAX_SKILL_BYTES) {
      throw new Error(`Supporting file "${targetUri}" exceeded 16 MiB limit`);
    }
    return { server, skillUri, uri: targetUri, content: text, size: bytes.length };
  }

  async function directory(
    server: string,
    uri: string,
    cursor?: string,
    opts?: LogOpts,
  ): Promise<{ resources: Array<{ uri: string; name: string; mimeType?: string }>; nextCursor?: string }> {
    const client = requireSkillsClient(server);
    const cleanUri = uri.length > 1 && uri.endsWith("/") ? uri.slice(0, -1) : uri;

    // Answer directly from retained static manifest when available (`skills/overview.md` §Reading Directories)
    for (const [k, entry] of retained) {
      if (!k.startsWith(`${server}\0`) || entry.resources === "dynamic") continue;
      const root = skillRootPrefix(entry.uri);
      if (cleanUri === root || cleanUri.startsWith(`${root}/`)) {
        const prefix = `${cleanUri}/`;
        const children = new Map<string, { uri: string; name: string; mimeType?: string }>();
        for (const item of entry.resources) {
          if (!item.uri.startsWith(prefix)) continue;
          const rest = item.uri.slice(prefix.length);
          const slashIdx = rest.indexOf("/");
          if (slashIdx === -1) {
            children.set(rest, { uri: item.uri, name: rest });
          } else {
            const dirName = rest.slice(0, slashIdx);
            children.set(dirName, {
              uri: `${prefix}${dirName}`,
              name: dirName,
              mimeType: "inode/directory",
            });
          }
        }
        return { resources: [...children.values()] };
      }
    }

    if (!client.state.skillsDirectoryRead) {
      throw new Error(
        `MCP server "${server}" does not declare directoryRead: true in io.modelcontextprotocol/skills.`,
      );
    }
    const res = await client.request<JsonObject>(
      "resources/directory/read",
      { uri: cleanUri, ...(cursor ? { cursor } : {}) },
      toReqOpts(opts),
    );
    const rawList = Array.isArray(res.resources) ? res.resources : [];
    const resources = rawList
      .filter(isRecord)
      .filter((r) => typeof r.uri === "string" && typeof r.name === "string")
      .map((r) => ({
        uri: r.uri as string,
        name: r.name as string,
        ...(typeof r.mimeType === "string" ? { mimeType: r.mimeType } : {}),
      }));
    return {
      resources,
      ...(typeof res.nextCursor === "string" ? { nextCursor: res.nextCursor } : {}),
    };
  }

  function verifiedSkillPaths(): string[] {
    // Per `extensions/skills/overview.md` §Integrity and Verification:
    // "Hosts MUST exclude cached files from filesystem-skill discovery paths and preserve their MCP origin".
    return [];
  }

  async function shutdown(): Promise<void> {
    if (shutDown) return;
    shutDown = true;
    host.signal?.removeEventListener?.("abort", onAbort);
    loadedSkills.clear();
    retained.clear();
    listings.clear();
    refreshes.clear();
    listedListeners.clear();
    if (cacheRoot) {
      try {
        rmSync(cacheRoot, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
      cacheRoot = undefined;
    }
  }

  return {
    restore,
    serverReady,
    serverRemoved,
    listed,
    refreshStale,
    onSkillsListed: (listener) => {
      listedListeners.add(listener);
      return () => {
        listedListeners.delete(listener);
      };
    },
    list,
    get,
    load,
    readFile,
    directory,
    verifiedSkillPaths,
    shutdown,
  };
}
