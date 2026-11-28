import assert from "node:assert/strict";
import { createHash, createVerify, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildMeta, createServerClient, extractTraceMeta } from "../src/client.ts";
import { createAuthResolver } from "../src/config.ts";
import {
  inspectElicitationUrl,
  openExternalBrowser,
  runElicitationPrompt,
  type ElicitationUi,
} from "../src/elicitation.ts";
import { parseClientCredentialsConfig } from "../src/oauth-client-credentials.ts";
import {
  EXT_OAUTH_CLIENT_CREDENTIALS,
  EXT_SKILLS,
  META_CLIENT_CAPABILITIES,
  type JsonObject,
  type ResolvedHttpServer,
} from "../src/types.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(testDir, "..");

function piDir(): string {
  const pkgName = (dir: string): string | undefined => {
    try {
      return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).name;
    } catch {
      return undefined;
    }
  };
  let dir = dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent")));
  while (pkgName(dir) !== "@earendil-works/pi-coding-agent") {
    const parent = dirname(dir);
    if (parent === dir) throw new Error("Cannot locate @earendil-works/pi-coding-agent");
    dir = parent;
  }
  return dir;
}

function sha256Digest(text: string): { digest: string; size: number } {
  const buf = Buffer.from(text, "utf8");
  return {
    digest: `sha256:${createHash("sha256").update(buf).digest("hex")}`,
    size: buf.length,
  };
}

test("1. OpenTelemetry trace context propagation validates W3C format and merges into _meta", () => {
  const validTp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  const invalidZeroTrace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";

  assert.deepEqual(
    extractTraceMeta({
      TRACEPARENT: validTp,
      TRACESTATE: "rojo=00f067aa0ba902b7",
      BAGGAGE: "userId=alice",
    }),
    {
      traceparent: validTp,
      tracestate: "rojo=00f067aa0ba902b7",
      baggage: "userId=alice",
    },
  );
  assert.deepEqual(extractTraceMeta({ TRACEPARENT: invalidZeroTrace }), {});

  const meta = buildMeta({
    skills: true,
    oauthClientCredentials: true,
    elicitation: true,
    traceContext: { TRACEPARENT: validTp },
  });
  assert.equal(meta.traceparent, validTp);
  const caps = meta[META_CLIENT_CAPABILITIES] as JsonObject;
  const exts = caps.extensions as JsonObject;
  assert.deepEqual(exts[EXT_SKILLS], {});
  assert.deepEqual(exts[EXT_OAUTH_CLIENT_CREDENTIALS], {});
});

test("2. OAuth 2.0 Client Credentials: RFC 9728 + RFC 8414 discovery, ES256 private_key_jwt (RFC 7523/10070), 401 refresh, and issuer pinning", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  let currentToken = "tok-v1";
  let tokenRequests = 0;
  let lastAssertionAud: unknown;
  let mcpForced401Once = false;

  const httpServer = createHttpServer(async (req, res) => {
    const host = req.headers.host ?? "127.0.0.1";
    const baseUrl = `http://${host}`;
    const url = new URL(req.url ?? "/", baseUrl);

    if (url.pathname === "/.well-known/oauth-protected-resource/mcp") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          resource: `${baseUrl}/mcp`,
          authorization_servers: [`${baseUrl}/auth`],
          scopes_supported: ["mcp:tools", "mcp:events"],
        }),
      );
      return;
    }

    if (url.pathname === "/.well-known/oauth-authorization-server/auth") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          issuer: `${baseUrl}/auth`,
          token_endpoint: `${baseUrl}/auth/token`,
          token_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic"],
        }),
      );
      return;
    }

    if (url.pathname === "/auth/token" && req.method === "POST") {
      tokenRequests += 1;
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      assert.equal(form.get("grant_type"), "client_credentials");
      assert.equal(form.get("resource"), `${baseUrl}/mcp`);
      assert.equal(form.get("scope"), "mcp:tools mcp:events");

      const assertion = form.get("client_assertion");
      if (assertion) {
        assert.equal(
          form.get("client_assertion_type"),
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        const [h64, p64, s64] = assertion.split(".");
        const header = JSON.parse(Buffer.from(h64, "base64url").toString("utf8"));
        const payload = JSON.parse(Buffer.from(p64, "base64url").toString("utf8"));
        assert.equal(header.alg, "ES256");
        assert.equal(header.kid, "key-1");
        assert.equal(payload.iss, "bot-svc");
        assert.equal(payload.sub, "bot-svc");
        lastAssertionAud = payload.aud;

        const verifier = createVerify("SHA256");
        verifier.update(`${h64}.${p64}`, "utf8");
        verifier.end();
        const sigOk = verifier.verify(
          { key: publicKey, dsaEncoding: "ieee-p1363" },
          Buffer.from(s64, "base64url"),
        );
        assert.equal(sigOk, true, "ES256 IEEE-P1363 JWT signature must verify");
      }

      if (tokenRequests > 1) currentToken = `tok-v${tokenRequests}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: currentToken, token_type: "Bearer", expires_in: 300 }));
      return;
    }

    if (url.pathname === "/mcp" && req.method === "POST") {
      const authHeader = req.headers.authorization;
      if (!mcpForced401Once && tokenRequests === 1 && authHeader === "Bearer tok-v1") {
        // First request succeeds, second forces 401 rotation below
      }
      if (authHeader !== `Bearer ${currentToken}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_token" }));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const rpc = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      res.writeHead(200, { "Content-Type": "application/json" });
      if (rpc.method === "server/discover") {
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: rpc.id,
            result: {
              resultType: "complete",
              supportedVersions: ["2026-07-28"],
              capabilities: {
                extensions: {
                  [EXT_OAUTH_CLIENT_CREDENTIALS]: {},
                  "io.modelcontextprotocol/events": {},
                },
              },
            },
          }),
        );
        return;
      }
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            resultType: "complete",
            events: [{ name: "audit.ok", delivery: ["poll"] }],
            seenExt: Boolean(
              rpc.params?._meta?.[META_CLIENT_CAPABILITIES]?.extensions?.[EXT_OAUTH_CLIENT_CREDENTIALS],
            ),
          },
        }),
      );
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolveListen) => httpServer.listen(0, "127.0.0.1", resolveListen));
  const port = (httpServer.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const serverCfg: ResolvedHttpServer = {
      name: "m2m",
      namespace: "mcp__m2m",
      scope: "global",
      enabled: true,
      timeoutMs: 5_000,
      transport: "http",
      url: `${baseUrl}/mcp`,
      headers: {},
      clientCredentials: {
        clientId: "bot-svc",
        privateKey: privatePem,
        algorithm: "ES256",
        kid: "key-1",
        issuer: `${baseUrl}/auth`,
      },
    };
    const auth = createAuthResolver(serverCfg, async () => undefined);
    const client = createServerClient(serverCfg, {
      cwd: process.cwd(),
      auth,
      meta: () => buildMeta({ oauthClientCredentials: true }),
    });

    const state = await client.discover();
    assert.equal(state.era, "modern");
    assert.equal(lastAssertionAud, `${baseUrl}/auth`, "RFC 10070: aud must equal exact AS issuer");
    assert.equal(tokenRequests, 1);

    // Rotate server token to trigger HTTP 401 -> refreshAfterUnauthorized() -> retry
    mcpForced401Once = true;
    currentToken = "tok-rotated";
    const listOut = await client.request<JsonObject>("events/list");
    assert.equal(tokenRequests, 2);
    assert.equal(listOut.seenExt, true);
    await client.close();

    // Issuer mismatch must fail before redeeming credentials
    const wrongIssuerCfg: ResolvedHttpServer = {
      ...serverCfg,
      clientCredentials: {
        ...serverCfg.clientCredentials!,
        issuer: "https://wrong-issuer.example.com",
      },
    };
    const badAuth = createAuthResolver(wrongIssuerCfg, async () => undefined);
    await assert.rejects(() => badAuth.authorization(), /issuer mismatch|Could not discover/i);
  } finally {
    await new Promise<void>((r) => httpServer.close(() => r()));
  }
});

test("3. Interactive Elicitation: form mode (edit/review, enum/multi-enum, URL neutralization) and URL mode (Punycode warning, scheme guard)", async () => {
  assert.equal(inspectElicitationUrl("javascript:alert(1)").valid, false);
  assert.equal(inspectElicitationUrl("https://user:pass@example.com/login").valid, false);
  const puny = inspectElicitationUrl("https://xn--80ak6aa92e.com/connect");
  assert.equal(puny.valid, true);
  assert.equal(puny.warnings.length, 1);
  assert.match(puny.warnings[0], /Punycode/i);

  const openedUrls: string[] = [];
  const selectPrompts: string[] = [];
  const urlUi: ElicitationUi = {
    async select(title, options) {
      selectPrompts.push(title);
      return options[0]; // Accept
    },
    async confirm() {
      return true;
    },
    async input() {
      return undefined;
    },
    notify() {},
  };
  const urlRes = await runElicitationPrompt(
    urlUi,
    "billing-mcp",
    {
      mode: "url",
      url: "https://xn--80ak6aa92e.com/oauth/start",
      message: "Connect external billing account",
    },
    { openUrl: (u) => openedUrls.push(u) },
  );
  assert.deepEqual(urlRes, { action: "accept" });
  assert.deepEqual(openedUrls, ["https://xn--80ak6aa92e.com/oauth/start"]);
  assert.match(selectPrompts[0], /MCP server "billing-mcp"/);
  assert.match(selectPrompts[0], /Punycode/);

  const notices: string[] = [];
  const unopened = await runElicitationPrompt(
    { ...urlUi, notify: (message) => notices.push(message) },
    "billing-mcp",
    { mode: "url", url: "https://billing.example.com/connect", message: "Connect billing" },
    { openUrl: () => false },
  );
  assert.deepEqual(unopened, { action: "accept" });
  assert.match(notices.join("\n"), /Open this URL yourself: https:\/\/billing\.example\.com\/connect/);
  if (process.platform !== "win32") {
    const prevPath = process.env.PATH;
    process.env.PATH = "";
    try {
      assert.equal(await openExternalBrowser("https://billing.example.com/connect"), false, "a missing opener reports failure");
    } finally {
      process.env.PATH = prevPath;
    }
  }

  // Form mode: fill email + integer + single-enum + multi-enum, edit email during review, then Submit
  const selectQueue = [
    "Fill 4 fields…",
    "Gold (#FFD700)",
    "[ ] Read (read)", // toggle read on
    "[ ] Write (write)", // toggle write on
    "Done (2 selected)",
    'Edit "email"', // test review/modify loop!
    "Submit (Accept)",
  ];
  const inputQueue = ["first@example.com", "28", "updated@example.com"];
  const formSelectTitles: string[] = [];

  const formUi: ElicitationUi = {
    async select(title, _options) {
      formSelectTitles.push(title);
      return selectQueue.shift();
    },
    async confirm() {
      return true;
    },
    async input() {
      return inputQueue.shift();
    },
    notify() {},
  };

  const formRes = await runElicitationPrompt(formUi, "crm-mcp", {
    message: "Provide profile (never click https://evil.example/phish)",
    requestedSchema: {
      type: "object",
      properties: {
        email: { type: "string", format: "email", title: "Work Email" },
        age: { type: "integer", minimum: 18, maximum: 120 },
        tier: {
          type: "string",
          oneOf: [
            { const: "#FFD700", title: "Gold" },
            { const: "#C0C0C0", title: "Silver" },
          ],
        },
        scopes: {
          type: "array",
          minItems: 1,
          items: {
            anyOf: [
              { const: "read", title: "Read" },
              { const: "write", title: "Write" },
            ],
          },
        },
      },
      required: ["email", "age", "tier", "scopes"],
    },
  });

  assert.match(formSelectTitles[0], /https\[:\]\/\/evil\.example\/phish/, "URLs in form message neutralized");
  assert.deepEqual(formRes, {
    action: "accept",
    content: {
      email: "updated@example.com",
      age: 28,
      tier: "#FFD700",
      scopes: ["read", "write"],
    },
  });
});

test("4-7. Full Pi ExtensionRunner e2e: pure 2026-07-28 tools fallback + listChanged, prompts + completion + slash command, resource watch wakes, task elicitation UI, and skills SHA-256 verification + resources_discover", async () => {
  const dir = mkdtempSync(join(tmpdir(), "suite7-all-"));
  const agentDir = join(dir, "agent");
  const projectDir = join(dir, "project");
  const serverScript = join(dir, "all-2026-server.mjs");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(projectDir, { recursive: true });

  const skillMdText =
    "---\nname: code-audit\ndescription: Audit repository security.\n---\n\n# Code Audit\n\nRead `references/rules.md` first.\n";
  const rulesMdText = "# Rules\n\n1. Check digests.\n";
  const skillDigest = sha256Digest(skillMdText);
  const rulesDigest = sha256Digest(rulesMdText);

  writeFileSync(
    serverScript,
    `
import { createInterface } from "node:readline";

const SUB_ID = "io.modelcontextprotocol/subscriptionId";
let listenSubId = null;
let extraToolEnabled = false;
let tamperNextSkillRead = false;
let taskPolls = 0;
let taskAnswered = null;
let skillResourcesReads = 0;

const SKILL_MD = ${JSON.stringify(skillMdText)};
const RULES_MD = ${JSON.stringify(rulesMdText)};
const SKILL_ENTRY = {
  uri: "skill://code-audit/SKILL.md",
  frontmatter: {
    name: "code-audit",
    description: "Audit repository security.",
  },
  resources: [
    { uri: "skill://code-audit/SKILL.md", digest: ${JSON.stringify(skillDigest.digest)}, size: ${skillDigest.size} },
    { uri: "skill://code-audit/references/rules.md", digest: ${JSON.stringify(rulesDigest.digest)}, size: ${rulesDigest.size} },
  ],
};

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\\n");
}

createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (!("id" in req)) return;

  // Strict 2026-07-28 server: reject 2025-11-25 initialize!
  if (req.method === "initialize") {
    send({ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: "initialize removed in 2026-07-28" } });
    return;
  }

  if (req.method === "server/discover") {
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        supportedVersions: ["2026-07-28"],
        instructions: "Pure 2026-07-28 fixture server",
        capabilities: {
          tools: { listChanged: true },
          resources: { subscribe: true, listChanged: true },
          prompts: { listChanged: true },
          completions: {},
          extensions: {
            "io.modelcontextprotocol/events": { listChanged: true },
            "io.modelcontextprotocol/tasks": {},
            "io.modelcontextprotocol/skills": { directoryRead: true },
          },
        },
      },
    });
    return;
  }

  if (req.method === "subscriptions/listen") {
    listenSubId = req.id;
    send({
      jsonrpc: "2.0",
      method: "notifications/subscriptions/acknowledged",
      params: {
        notifications: req.params?.notifications ?? {},
        _meta: { [SUB_ID]: req.id },
      },
    });
    return;
  }

  if (req.method === "tools/list") {
    const tools = [
      {
        name: "trigger_changes",
        description: "Trigger dynamic tool + resource notifications",
        inputSchema: { type: "object", properties: { action: { type: "string" } } },
      },
      {
        name: "ask_approval_task",
        description: "Task that requests elicitation/create",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    if (extraToolEnabled) {
      tools.push({
        name: "newly_added",
        description: "Dynamically added 2026-07-28 tool",
        inputSchema: { type: "object", properties: { msg: { type: "string" } } },
      });
    }
    send({ jsonrpc: "2.0", id: req.id, result: { resultType: "complete", tools } });
    return;
  }

  if (req.method === "tools/call") {
    const name = req.params?.name;
    const args = req.params?.arguments ?? {};
    if (name === "trigger_changes") {
      if (args.action === "add_tool") {
        extraToolEnabled = true;
        if (listenSubId !== null) {
          send({
            jsonrpc: "2.0",
            method: "notifications/tools/list_changed",
            params: { _meta: { [SUB_ID]: listenSubId } },
          });
        }
      } else if (args.action === "touch_resource") {
        if (listenSubId !== null) {
          send({
            jsonrpc: "2.0",
            method: "notifications/resources/updated",
            params: { uri: "file:///config/live.json", _meta: { [SUB_ID]: listenSubId } },
          });
        }
      } else if (args.action === "tamper_skill") {
        tamperNextSkillRead = true;
      }
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "complete",
          content: [{ type: "text", text: "ok:" + String(args.action) + ":tp=" + String(req.params?._meta?.traceparent ?? "none") + ":reads=" + skillResourcesReads }],
        },
      });
      return;
    }
    if (name === "newly_added") {
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: { resultType: "complete", content: [{ type: "text", text: "echo:" + String(args.msg) }] },
      });
      return;
    }
    if (name === "ask_approval_task") {
      const now = new Date().toISOString();
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "task",
          taskId: "t-elicit-1",
          status: "input_required",
          createdAt: now,
          lastUpdatedAt: now,
          ttlMs: 60000,
          pollIntervalMs: 50,
        },
      });
      return;
    }
  }

  if (req.method === "tasks/get") {
    taskPolls += 1;
    const now = new Date().toISOString();
    if (!taskAnswered) {
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "complete",
          taskId: "t-elicit-1",
          status: "input_required",
          createdAt: now,
          lastUpdatedAt: now,
          ttlMs: 60000,
          pollIntervalMs: 50,
          inputRequests: {
            "req-1": {
              method: "elicitation/create",
              params: {
                mode: "form",
                message: "Confirm deployment target",
                requestedSchema: {
                  type: "object",
                  properties: { env: { type: "string", enum: ["staging", "prod"] } },
                  required: ["env"],
                },
              },
            },
          },
        },
      });
      return;
    }
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        taskId: "t-elicit-1",
        status: "completed",
        createdAt: now,
        lastUpdatedAt: now,
        ttlMs: 60000,
        result: { content: [{ type: "text", text: "deployed:" + JSON.stringify(taskAnswered) }] },
      },
    });
    return;
  }

  if (req.method === "tasks/update") {
    taskAnswered = req.params?.inputResponses?.["req-1"] ?? null;
    send({ jsonrpc: "2.0", id: req.id, result: { resultType: "complete" } });
    return;
  }

  if (req.method === "prompts/list") {
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        prompts: [
          {
            name: "review",
            description: "Review code in a language",
            arguments: [{ name: "language", required: true }],
          },
        ],
      },
    });
    return;
  }

  if (req.method === "prompts/get") {
    const lang = req.params?.arguments?.language ?? "unknown";
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        description: "Review prompt",
        messages: [
          { role: "user", content: { type: "text", text: "Review " + lang + " carefully." } },
        ],
      },
    });
    return;
  }

  if (req.method === "completion/complete") {
    const val = req.params?.argument?.value ?? "";
    const candidates = ["python", "rust", "typescript"].filter((c) => c.startsWith(val));
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        completion: { values: candidates, total: candidates.length, hasMore: false },
      },
    });
    return;
  }

  if (req.method === "resources/list") {
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        resources: [
          { uri: "file:///config/live.json", name: "live.json", mimeType: "application/json", icons: [{ src: "https://example.com/i.png" }] },
          { uri: "ui://dashboard/app", name: "dashboard", mimeType: "text/html;profile=mcp-app" },
        ],
      },
    });
    return;
  }

  if (req.method === "resources/templates/list") {
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        resourceTemplates: [{ uriTemplate: "file:///logs/{service}.log", name: "Service Logs" }],
      },
    });
    return;
  }

  if (req.method === "resources/read") {
    const uri = req.params?.uri;
    if (uri === "file:///config/live.json") {
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "complete",
          contents: [{ uri, mimeType: "application/json", text: '{"ok":true}' }],
        },
      });
      return;
    }
    if (uri === "skill://code-audit/SKILL.md") {
      skillResourcesReads += 1;
      const body = tamperNextSkillRead ? SKILL_MD + "TAMPERED" : SKILL_MD;
      tamperNextSkillRead = false;
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "complete",
          contents: [{ uri, mimeType: "text/markdown", text: body }],
        },
      });
      return;
    }
    if (uri === "skill://code-audit/references/rules.md") {
      skillResourcesReads += 1;
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          resultType: "complete",
          contents: [{ uri, mimeType: "text/markdown", text: RULES_MD }],
        },
      });
      return;
    }
    send({ jsonrpc: "2.0", id: req.id, error: { code: -32602, message: "Resource not found" } });
    return;
  }

  if (req.method === "skills/list") {
    send({
      jsonrpc: "2.0",
      id: req.id,
      result: { resultType: "complete", skills: [SKILL_ENTRY] },
    });
    return;
  }

  if (req.method === "skills/get") {
    if (req.params?.uri === SKILL_ENTRY.uri) {
      send({ jsonrpc: "2.0", id: req.id, result: { resultType: "complete", skill: SKILL_ENTRY } });
    } else {
      send({ jsonrpc: "2.0", id: req.id, error: { code: -32602, message: "Unknown skill" } });
    }
    return;
  }

  send({ jsonrpc: "2.0", id: req.id, result: { resultType: "complete" } });
});
`,
  );

  writeFileSync(
    join(agentDir, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        pure26: {
          command: process.execPath,
          args: [serverScript],
          exposure: "direct",
        },
      },
    }),
  );

  const pi = piDir();
  const loader: any = await import(pathToFileURL(join(pi, "dist/core/extensions/loader.js")).href);
  const runnerMod: any = await import(pathToFileURL(join(pi, "dist/core/extensions/runner.js")).href);
  const runtime = loader.createExtensionRuntime();
  const loaded = await loader.loadExtensions([resolve(rootDir, "src/index.ts")], projectDir, undefined, runtime);
  assert.deepEqual(loaded.errors, []);
  const ext = loaded.extensions[0];

  const sessionEntries: any[] = [];
  const sentMessages: any[] = [];
  const userMessages: any[] = [];
  const uiSelectQueue: string[] = [];
  let skillConfirmApprove = true;

  const sessionManager: any = {
    getBranch: () => [...sessionEntries],
    getEntries: () => [...sessionEntries],
    getSessionFile: () => undefined,
  };
  const modelRegistry: any = {
    getProviderAuth: async () => undefined,
    registerProvider: () => {},
  };
  const runner = new runnerMod.ExtensionRunner(
    loaded.extensions,
    runtime,
    projectDir,
    sessionManager,
    modelRegistry,
  );
  runner.bindCore(
    {
      sendMessage: (message: any, options: any) => {
        sentMessages.push({ message, options });
      },
      sendUserMessage: (content: any) => {
        userMessages.push(content);
      },
      appendEntry: (customType: string, data: unknown) => {
        sessionEntries.push({ type: "custom", customType, data });
      },
      setSessionName: () => {},
      getSessionName: () => undefined,
      setLabel: () => {},
      getActiveTools: () => [...ext.tools.keys()],
      getAllTools: () =>
        [...ext.tools.values()].map((t: any) => ({
          name: t.definition.name,
          description: t.definition.description,
          parameters: t.definition.parameters,
          exposure: t.definition.exposure ?? "direct",
          sourceInfo: t.sourceInfo,
        })),
      getSettings: () => ({}),
      setActiveTools: () => {},
      refreshTools: () => {},
      getCommands: () => [],
      setModel: async () => false,
      getThinkingLevel: () => "off",
      setThinkingLevel: () => {},
    },
    {
      getModel: () => undefined,
      getScopedModels: () => [],
      isIdle: () => true,
      isProjectTrusted: () => false,
      getSignal: () => undefined,
      abort: () => {},
      hasPendingMessages: () => sentMessages.length > 0,
      shutdown: () => {},
      getContextUsage: () => undefined,
      compact: () => {},
      getSystemPrompt: () => "",
      executeTool: async () => {
        throw new Error("unused");
      },
    },
  );

  // Bind an interactive mock UI so elicitation + skill approval run live!
  runner.setUIContext(
    {
      select: async (_title: string, options: string[]) => uiSelectQueue.shift() ?? options[0],
      confirm: async () => skillConfirmApprove,
      input: async () => "rust",
      notify: () => {},
      setStatus: () => {},
    } as any,
    "interactive",
  );

  const prevAgentDir = process.env.PI_CODING_AGENT_DIR;
  const prevTraceparent = process.env.TRACEPARENT;
  const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  process.env.PI_CODING_AGENT_DIR = agentDir;
  process.env.TRACEPARENT = tp;

  try {
    await runner.emit({ type: "session_start", reason: "startup" });

    // Wait for pure26 discovery + fallback tools registration
    for (let i = 0; i < 60 && !ext.tools.has("mcp__pure26__trigger_changes"); i += 1) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(ext.tools.has("mcp__pure26__trigger_changes"), true, "pure 2026-07-28 fallback tool registered");
    assert.equal(ext.commands.has("mcp-prompt:pure26:review"), true, "per-prompt slash command registered");
    for (let i = 0; i < 40 && !ext.commands.has("mcp-skill:pure26:code-audit"); i += 1) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(ext.commands.has("mcp-skill:pure26:code-audit"), true, "per-skill slash command registered");

    const { systemPromptOptions } = await runner.emitBeforeAgentStart(
      { messageType: "user", prompt: "audit this repo" },
      { cwd: projectDir },
    );
    assert.match(
      systemPromptOptions.sections.mcp_skills,
      /<mcp_skill server="pure26" name="code-audit" uri="skill:\/\/code-audit\/SKILL\.md">Audit repository security\.<\/mcp_skill>/,
      "listed skills reach the system prompt before each run",
    );

    const ctx = runner.createToolContext("c-1", undefined);

    // A. Verify OpenTelemetry traceparent arrived in _meta + dynamic toolsListChanged adds mcp__pure26__newly_added
    const triggerTool = ext.tools.get("mcp__pure26__trigger_changes").definition;
    const tRes = await triggerTool.execute("c-1", { action: "add_tool" }, undefined, undefined, ctx);
    assert.match(tRes.content[0].text, new RegExp(`tp=${tp}`));

    for (let i = 0; i < 40 && !ext.tools.has("mcp__pure26__newly_added"); i += 1) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(ext.tools.has("mcp__pure26__newly_added"), true, "toolsListChanged dynamically registered newly_added");
    const addedRes = await ext.tools
      .get("mcp__pure26__newly_added")
      .definition.execute("c-2", { msg: "live" }, undefined, undefined, ctx);
    assert.equal(addedRes.content[0].text, "echo:live");

    // B. Prompts + Completion + Slash command
    const promptsTool = ext.tools.get("mcp_prompts").definition;
    const compOut = JSON.parse(
      (
        await promptsTool.execute(
          "c-3",
          { action: "complete", server: "pure26", name: "review", argumentName: "language", argumentValue: "ru" },
          undefined,
          undefined,
          ctx,
        )
      ).content[0].text,
    );
    assert.deepEqual(compOut.values, ["rust"]);

    const promptCmd = ext.commands.get("mcp-prompt:pure26:review");
    const slashCompletions = await promptCmd.getArgumentCompletions("language=py");
    assert.deepEqual(slashCompletions, [
      { value: "language=python", label: "python", description: "language" },
    ]);
    await promptCmd.handler("language=rust", runner.createCommandContext());
    assert.equal(userMessages.at(-1), "Review rust carefully.");

    // C. Resources (ui:// filtered, icons stripped) + Live Resource Subscription wake
    const resourcesTool = ext.tools.get("mcp_resources").definition;
    const resList = JSON.parse(
      (await resourcesTool.execute("c-4", { action: "list", server: "pure26" }, undefined, undefined, ctx)).content[0].text,
    );
    assert.equal(resList.resources.length, 1, "ui:// MCP App resource filtered out");
    assert.equal("icons" in resList.resources[0], false, "icons stripped");

    const readOut = await resourcesTool.execute(
      "c-5",
      { action: "read", server: "pure26", uri: "file:///config/live.json" },
      undefined,
      undefined,
      ctx,
    );
    assert.equal(readOut.content[0].text, '{"ok":true}');

    await resourcesTool.execute(
      "c-6",
      { action: "subscribe", server: "pure26", uri: "file:///config/live.json" },
      undefined,
      undefined,
      ctx,
    );
    // Allow subscriptions/listen replacement ack before firing notification
    await new Promise((r) => setTimeout(r, 60));
    await triggerTool.execute("c-7", { action: "touch_resource" }, undefined, undefined, ctx);

    for (let i = 0; i < 40 && !sentMessages.some((m) => m.message.customType === "mcp-resource"); i += 1) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const resWake = sentMessages.find((m) => m.message.customType === "mcp-resource");
    assert.ok(resWake, "notifications/resources/updated triggered mcp-resource wake");
    assert.match(resWake.message.content, /file:\/\/\/config\/live\.json/);

    // D. Interactive Elicitation fulfilling SEP-2663 input_required task automatically via ctx.ui -> tasks/update
    uiSelectQueue.push("Fill 1 field…", "prod", "Submit (Accept)");
    const tasksTool = ext.tools.get("mcp_tasks").definition;
    await tasksTool.execute(
      "c-8",
      { action: "call", server: "pure26", tool: "ask_approval_task" },
      undefined,
      undefined,
      ctx,
    );
    for (
      let i = 0;
      i < 60 && !sentMessages.some((m) => m.message.customType === "mcp-task" && /deployed:/.test(m.message.content));
      i += 1
    ) {
      await new Promise((r) => setTimeout(r, 30));
    }
    const taskWake = sentMessages.find(
      (m) => m.message.customType === "mcp-task" && /deployed:/.test(m.message.content),
    );
    assert.ok(taskWake, "task completed after interactive elicitation UI answered tasks/update");
    assert.match(taskWake.message.content, /\\"env\\":\\"prod\\"/);

    // E. Skills over MCP: list does NOT eagerly read SKILL.md; load approves, verifies SHA-256 + frontmatter, writes 0444 cache, and exposes via resources_discover
    const skillsTool = ext.tools.get("mcp_skills").definition;
    const listedSkills = JSON.parse(
      (await skillsTool.execute("c-9", { action: "list", server: "pure26" }, undefined, undefined, ctx)).content[0].text,
    );
    assert.equal(listedSkills.skills.length, 1);
    const probeReads = await triggerTool.execute("c-10", { action: "noop" }, undefined, undefined, ctx);
    assert.match(probeReads.content[0].text, /reads=0/, "skills/list must NOT eagerly fetch skill files");

    const dirListing = JSON.parse(
      (
        await skillsTool.execute(
          "c-11",
          { action: "directory", server: "pure26", uri: "skill://code-audit" },
          undefined,
          undefined,
          ctx,
        )
      ).content[0].text,
    );
    assert.deepEqual(
      dirListing.resources.map((r: any) => r.name).sort(),
      ["SKILL.md", "references"],
    );

    process.env.PI_MCP_EXT_SKILL_AUTO_APPROVE = "pure26";
    skillConfirmApprove = false;
    const autoLoaded = JSON.parse(
      (
        await skillsTool.execute(
          "c-12a",
          { action: "load", server: "pure26", uri: "skill://code-audit/SKILL.md" },
          undefined,
          undefined,
          ctx,
        )
      ).content[0].text,
    );
    assert.equal(autoLoaded.name, "code-audit", "a listed server loads without the confirm dialog");
    assert.equal(
      sessionEntries.filter((e) => e.customType === "mcp-ext:skill-approvals").length,
      0,
      "auto-approved loads are not recorded as session approvals",
    );
    delete process.env.PI_MCP_EXT_SKILL_AUTO_APPROVE;
    await assert.rejects(
      () =>
        skillsTool.execute(
          "c-12b",
          { action: "load", server: "pure26", uri: "skill://code-audit/SKILL.md" },
          undefined,
          undefined,
          ctx,
        ),
      /User declined/,
      "removing the server from the list brings the prompt back",
    );
    skillConfirmApprove = true;

    skillConfirmApprove = false;
    await assert.rejects(
      () =>
        skillsTool.execute(
          "c-10b",
          { action: "load", server: "pure26", uri: "skill://code-audit/SKILL.md" },
          undefined,
          undefined,
          ctx,
        ),
      /User declined/,
      "a model load still asks for approval",
    );
    await ext.commands.get("mcp-skill:pure26:code-audit").handler("  src/  ", runner.createCommandContext());
    skillConfirmApprove = true;
    assert.equal(
      sessionEntries.filter((e) => e.customType === "mcp-ext:skill-approvals").length,
      1,
      "the typed command records the approval",
    );
    const skillMessage = userMessages.at(-1);
    assert.match(skillMessage, /<mcp_skill server="pure26" uri="skill:\/\/code-audit\/SKILL\.md" name="code-audit">/);
    assert.match(skillMessage, /# Code Audit/, "typing the command loads the skill without the approval prompt");
    assert.match(skillMessage, /action "read_file"/, "points the model at the supporting files");
    assert.ok(skillMessage.endsWith("\n\nsrc/"), "arguments follow the skill");

    const loadedSkill = await skillsTool.execute(
      "c-12",
      { action: "load", server: "pure26", uri: "skill://code-audit/SKILL.md" },
      undefined,
      undefined,
      ctx,
    );
    const loadMeta = JSON.parse(loadedSkill.content[0].text);
    assert.equal(loadMeta.name, "code-audit");
    assert.ok(loadMeta.cacheDir);
    const cachedSkillFile = join(loadMeta.cacheDir, "SKILL.md");
    assert.equal(readFileSync(cachedSkillFile, "utf8"), skillMdText);
    if (process.platform !== "win32") {
      assert.equal(statSync(cachedSkillFile).mode & 0o222, 0, "cached SKILL.md must be read-only (0444)");
    }

    const discovered = await runner.emitResourcesDiscover(projectDir, "reload");
    assert.equal(
      discovered.skillPaths.length,
      0,
      "cached MCP skills MUST be excluded from filesystem skill discovery to preserve MCP origin",
    );

    const supportFile = JSON.parse(
      (
        await skillsTool.execute(
          "c-13",
          {
            action: "read_file",
            server: "pure26",
            uri: "skill://code-audit/SKILL.md",
            path: "references/rules.md",
          },
          undefined,
          undefined,
          ctx,
        )
      ).content[0].text,
    );
    assert.equal(supportFile.content, rulesMdText);

    await assert.rejects(
      () =>
        skillsTool.execute(
          "c-14",
          {
            action: "read_file",
            server: "pure26",
            uri: "skill://code-audit/SKILL.md",
            path: "references/unlisted.md",
          },
          undefined,
          undefined,
          ctx,
        ),
      /not in the retained manifest/,
    );

    // Tampered SKILL.md bytes must fail SHA-256 verification!
    await triggerTool.execute("c-15", { action: "tamper_skill" }, undefined, undefined, ctx);
    await assert.rejects(
      () =>
        skillsTool.execute(
          "c-16",
          { action: "load", server: "pure26", uri: "skill://code-audit/SKILL.md" },
          undefined,
          undefined,
          ctx,
        ),
      /size mismatch|SHA-256 digest mismatch/,
    );
  } finally {
    delete process.env.PI_MCP_EXT_SKILL_AUTO_APPROVE;
    await runnerMod.emitSessionShutdownEvent(runner, { type: "session_shutdown", reason: "quit" });
    if (prevAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = prevAgentDir;
    if (prevTraceparent === undefined) delete process.env.TRACEPARENT;
    else process.env.TRACEPARENT = prevTraceparent;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("8. Dual-stack coexistence: when builtin:mcp already owns mcp__<server>__*, toolsFallback stands down and parks idle stdio child", async () => {
  const dir = mkdtempSync(join(tmpdir(), "suite7-dual-"));
  const agentDir = join(dir, "agent");
  const projectDir = join(dir, "project");
  const pidFile = join(dir, "dual.pid");
  const serverScript = join(dir, "dual-server.mjs");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(projectDir, { recursive: true });

  writeFileSync(
    serverScript,
    `
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (!("id" in req)) return;
  if (req.method === "server/discover") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        resultType: "complete",
        supportedVersions: ["2026-07-28", "2025-11-25"],
        capabilities: { tools: {} },
      },
    }) + "\\n");
    return;
  }
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { resultType: "complete", tools: [{ name: "dup", inputSchema: { type: "object" } }] } }) + "\\n");
});
`,
  );

  writeFileSync(
    join(agentDir, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        dual: { command: process.execPath, args: [serverScript] },
      },
    }),
  );

  const pi = piDir();
  const loader: any = await import(pathToFileURL(join(pi, "dist/core/extensions/loader.js")).href);
  const runnerMod: any = await import(pathToFileURL(join(pi, "dist/core/extensions/runner.js")).href);
  const runtime = loader.createExtensionRuntime();
  const loaded = await loader.loadExtensions([resolve(rootDir, "src/index.ts")], projectDir, undefined, runtime);
  const ext = loaded.extensions[0];

  const runner = new runnerMod.ExtensionRunner(
    loaded.extensions,
    runtime,
    projectDir,
    { getBranch: () => [], getEntries: () => [], getSessionFile: () => undefined } as any,
    { getProviderAuth: async () => undefined, registerProvider: () => {} } as any,
  );
  runner.bindCore(
    {
      sendMessage: () => {},
      sendUserMessage: () => {},
      appendEntry: () => {},
      setSessionName: () => {},
      getSessionName: () => undefined,
      setLabel: () => {},
      getActiveTools: () => ["mcp__dual__existing"],
      // Simulate builtin:mcp having already registered mcp__dual__existing
      getAllTools: () => [
        {
          name: "mcp__dual__existing",
          description: "Owned by builtin:mcp",
          parameters: {},
          exposure: "direct",
          sourceInfo: { path: "builtin:mcp", source: "builtin:mcp", scope: "user", origin: "package" },
        },
      ],
      getSettings: () => ({}),
      setActiveTools: () => {},
      refreshTools: () => {},
      getCommands: () => [],
      setModel: async () => false,
      getThinkingLevel: () => "off",
      setThinkingLevel: () => {},
    },
    {
      getModel: () => undefined,
      getScopedModels: () => [],
      isIdle: () => true,
      isProjectTrusted: () => false,
      getSignal: () => undefined,
      abort: () => {},
      hasPendingMessages: () => false,
      shutdown: () => {},
      getContextUsage: () => undefined,
      compact: () => {},
      getSystemPrompt: () => "",
      executeTool: async () => {
        throw new Error("unused");
      },
    },
  );
  runner.setUIContext(undefined, "print");

  const prevAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    await runner.emit({ type: "session_start", reason: "startup" });
    // Trigger servers probe wait so startServerProbe completes (including park())
    const eventsTool = ext.tools.get("mcp_events").definition;
    await eventsTool.execute("c-1", { action: "servers" }, undefined, undefined, runner.createToolContext("c-1", undefined));

    assert.equal(ext.tools.has("mcp__dual__dup"), false, "must not overwrite or duplicate builtin:mcp tools");
    const pid = Number(readFileSync(pidFile, "utf8").trim());
    for (let i = 0; i < 40; i += 1) {
      try {
        process.kill(pid, 0);
        await new Promise((r) => setTimeout(r, 25));
      } catch {
        break;
      }
    }
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch {
      alive = false;
    }
    assert.equal(alive, false, "idle dual-stack stdio server parked/reaped so builtin:mcp is the sole owner");
  } finally {
    await runnerMod.emitSessionShutdownEvent(runner, { type: "session_shutdown", reason: "quit" });
    if (prevAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = prevAgentDir;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("9. Adversarial review regressions: synchronous MRTR input_required (requestState + new request id), fail-closed headless skills, dynamic read_file confinement, OAuth mandatory issuer + SSRF block, and x-mcp-header validation", async () => {
  // A. URL control-char / cmd-injection guard
  assert.equal(inspectElicitationUrl("https://example.com/ok?x=1\n2").valid, false);
  assert.equal(inspectElicitationUrl("https://example.com/ok?x=1 2").valid, false);

  // B. OAuth clientCredentials requires pinned issuer and blocks remote -> loopback SSRF
  const missingIssuer = parseClientCredentialsConfig(
    { clientCredentials: { clientId: "id", clientSecret: "sec" } },
    "https://mcp.example.com/mcp",
    "global",
  );
  assert.equal(missingIssuer.config, undefined);
  assert.match(missingIssuer.warning ?? "", /pinned issuer/i);

  const loopbackSsrf = parseClientCredentialsConfig(
    { clientCredentials: { clientId: "id", clientSecret: "sec", issuer: "http://127.0.0.1:9999" } },
    "https://mcp.example.com/mcp",
    "global",
  );
  assert.equal(loopbackSsrf.config, undefined);

  // C. Full YAML 1.2 frontmatter parsing (multiline block scalars + nested metadata)
  const { parseSkillFrontmatter, createSkillsEngine } = await import("../src/skills.ts");
  const parsedYaml = parseSkillFrontmatter(
    "---\nname: deep-skill\ndescription: |\n  First line\n  Second line\nmetadata:\n  author: sec-team\n---\n# Body\n",
  );
  assert.equal(parsedYaml?.name, "deep-skill");
  assert.match(String(parsedYaml?.description), /First line\nSecond line/);
  assert.deepEqual(parsedYaml?.metadata, { author: "sec-team" });

  // D. Strict x-mcp-header validation rejects disallowed keywords ($ref, oneOf, items, float number)
  const { validateXMcpHeaders } = await import("../src/transport-http.ts");
  assert.equal(
    validateXMcpHeaders({
      type: "object",
      properties: { ok: { type: "string", "x-mcp-header": "Region" } },
    }).valid,
    true,
  );
  assert.equal(
    validateXMcpHeaders({
      type: "object",
      oneOf: [{ properties: { bad: { type: "string", "x-mcp-header": "Region" } } }],
    }).valid,
    false,
  );
  assert.equal(
    validateXMcpHeaders({
      type: "object",
      properties: { badNum: { type: "number", "x-mcp-header": "Score" } },
    }).valid,
    false,
  );

  // E. Synchronous MRTR input_required loop on prompts/get + fail-closed headless skills + dynamic read_file confinement
  const seenIds: Array<string | number> = [];
  let mrtrRound = 0;
  const httpSrv = createHttpServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    seenIds.push(body.id);

    if (body.method === "server/discover") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            resultType: "complete",
            supportedVersions: ["2026-07-28"],
            capabilities: {
              prompts: {},
              resources: {},
              extensions: { "io.modelcontextprotocol/skills": {} },
            },
          },
        }),
      );
      return;
    }

    if (body.method === "prompts/get") {
      mrtrRound += 1;
      if (mrtrRound === 1) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              resultType: "input_required",
              requestState: { opaqueToken: "st-99" },
              inputRequests: {
                "ask-1": {
                  method: "elicitation/create",
                  params: {
                    message: "Confirm target branch",
                    requestedSchema: {
                      type: "object",
                      properties: { branch: { type: "string" } },
                      required: ["branch"],
                    },
                  },
                },
              },
            },
          }),
        );
        return;
      }
      assert.deepEqual(body.params.requestState, { opaqueToken: "st-99" });
      assert.deepEqual(body.params.inputResponses, {
        "ask-1": { action: "accept", content: { branch: "main" } },
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            resultType: "complete",
            messages: [
              { role: "user", content: { type: "text", text: `Deploying ${body.params.inputResponses["ask-1"].content.branch}` } },
            ],
          },
        }),
      );
      return;
    }

    if (body.method === "skills/get") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            resultType: "complete",
            skill: {
              uri: "skill://dyn-skill/SKILL.md",
              frontmatter: { name: "dyn-skill", description: "Dynamic test skill" },
              resources: "dynamic",
            },
          },
        }),
      );
      return;
    }

    if (body.method === "resources/read") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            resultType: "complete",
            contents: [
              {
                uri: body.params.uri,
                text: "---\nname: dyn-skill\ndescription: Dynamic test skill\n---\n# Dyn\n",
              },
            ],
          },
        }),
      );
      return;
    }

    res.writeHead(404).end();
  });

  await new Promise<void>((resolveListen) => httpSrv.listen(0, "127.0.0.1", () => resolveListen()));
  const port = (httpSrv.address() as AddressInfo).port;
  const cfg: ResolvedHttpServer = {
    name: "mrtr-srv",
    namespace: "mcp__mrtr_srv",
    scope: "global",
    enabled: true,
    timeoutMs: 5_000,
    transport: "http",
    url: `http://127.0.0.1:${port}/mcp`,
    headers: {},
  };

  const mrtrClient = createServerClient(cfg, {
    cwd: process.cwd(),
    meta: () => buildMeta({ elicitation: true, skills: true }),
    fulfillInputRequests: async (_srv, reqs) => {
      assert.ok("ask-1" in reqs);
      return { "ask-1": { action: "accept", content: { branch: "main" } } };
    },
  });

  try {
    await mrtrClient.discover();
    const promptRes = await mrtrClient.request<JsonObject>("prompts/get", { name: "deploy" });
    assert.equal((promptRes.messages as any[])[0].content.text, "Deploying main");
    assert.notEqual(seenIds[1], seenIds[2], "MRTR continuation MUST use a fresh JSON-RPC request ID");

    // Fail-closed headless skill load (no approve callback) + dynamic read_file URI confinement
    const skills = createSkillsEngine({
      getClient: (s) => (s === "mrtr-srv" ? mrtrClient : undefined),
      appendEntry: () => {},
      wake: () => {},
      log: () => {},
      signal: new AbortController().signal,
    });
    await assert.rejects(
      () => skills.load("mrtr-srv", "skill://dyn-skill/SKILL.md"),
      /interactive user approval is required/,
    );
    await assert.rejects(
      () => skills.load("mrtr-srv", "skill://other-skill/SKILL.md", { autoApprove: true }),
      /auto-approval covers only the requested skill/,
    );
    const autoLoaded = await skills.load("mrtr-srv", "skill://dyn-skill/SKILL.md", { autoApprove: true });
    assert.equal(autoLoaded.uri, "skill://dyn-skill/SKILL.md");
    await skills.load("mrtr-srv", "skill://dyn-skill/SKILL.md", {
      approve: async () => true,
    });
    await assert.rejects(
      () => skills.readFile("mrtr-srv", "skill://dyn-skill/SKILL.md", "file:///etc/passwd"),
      /outside skill root/,
    );
    await skills.shutdown();
  } finally {
    await mrtrClient.close();
    await new Promise<void>((r) => httpSrv.close(() => r()));
  }
});
