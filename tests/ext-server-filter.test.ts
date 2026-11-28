import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { CONFIG_DIR_NAME, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";

import { loadServerConfigs, serverNameSet, shouldConnect, skillAutoApprove } from "../src/config.ts";
import { createMcpSession, shouldKeepConnection, type McpSession } from "../src/session.ts";
import type { ConfigLoadOptions, ServerEra } from "../src/types.ts";

test("PI_MCP_EXT_SKILL_AUTO_APPROVE lists the servers whose skills load without approval", () => {
  const env = { PI_MCP_EXT_SKILL_AUTO_APPROVE: " skills, team ," } as NodeJS.ProcessEnv;
  assert.equal(skillAutoApprove("skills", env), true);
  assert.equal(skillAutoApprove("team", env), true);
  assert.equal(skillAutoApprove("other", env), false);
  assert.equal(skillAutoApprove("skills", {} as NodeJS.ProcessEnv), false);
  assert.equal(skillAutoApprove("skills", { PI_MCP_EXT_SKILL_AUTO_APPROVE: " , " } as NodeJS.ProcessEnv), false);
});

test("ext is carried from raw JSON, project overrides, and include/exclude filters", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-ext-filter-"));
  const oldAgentDir = process.env.PI_CODING_AGENT_DIR;
  const oldInclude = process.env.PI_MCP_EXT_INCLUDE;
  const oldExclude = process.env.PI_MCP_EXT_EXCLUDE;
  delete process.env.PI_MCP_EXT_INCLUDE;
  delete process.env.PI_MCP_EXT_EXCLUDE;
  process.env.PI_CODING_AGENT_DIR = root;
  const cwd = join(root, "project");
  mkdirSync(join(cwd, CONFIG_DIR_NAME), { recursive: true });
  try {
    writeFileSync(join(root, "mcp.json"), JSON.stringify({
      mcpServers: {
        alpha: { command: "alpha" },
        beta: { command: "beta", ext: false },
        gamma: { command: "gamma", ext: true },
        delta: { command: "delta", ext: false },
        badExt: { command: "bad", ext: "no" },
      },
    }));
    writeFileSync(join(cwd, CONFIG_DIR_NAME, "mcp.json"), JSON.stringify({
      mcpServers: {
        alpha: { ext: false },
        delta: { ext: true },
      },
    }));

    const opts = {
      cwd,
      isProjectTrusted: false,
      sessionServers: [
        { name: "sessOn", config: { command: "sess-on", ext: true } },
        { name: "sessOff", config: { command: "sess-off", ext: false } },
      ],
    };

    let res = await loadServerConfigs(opts);
    const byName = new Map(res.servers.map((s) => [s.name, s]));
    assert.equal(byName.get("beta")?.ext, false);
    assert.equal(byName.get("beta")?.enabled, true);
    assert.equal(byName.get("alpha")?.ext, undefined);
    assert.equal(byName.get("gamma")?.ext, true);
    assert.equal(byName.get("sessOff")?.ext, false);
    assert.equal(byName.get("sessOff")?.enabled, true);
    assert.equal(byName.has("badExt"), false);
    assert.ok(res.warnings.some((w) => w.server === "badExt" && w.message.includes("ext must be a boolean")));

    const env = {} as NodeJS.ProcessEnv;
    assert.equal(shouldConnect(byName.get("beta")!, env), false);
    assert.equal(shouldConnect(byName.get("alpha")!, env), true);
    assert.equal(shouldConnect(byName.get("gamma")!, env), true);
    assert.equal(shouldConnect(byName.get("sessOff")!, env), false);
    assert.equal(shouldConnect(byName.get("sessOn")!, env), true);

    res = await loadServerConfigs({ ...opts, isProjectTrusted: true });
    const trusted = new Map(res.servers.map((s) => [s.name, s]));
    assert.equal(trusted.get("alpha")?.ext, false);
    assert.equal(trusted.get("alpha")?.enabled, true);
    assert.equal(trusted.get("delta")?.ext, true);
    assert.equal(trusted.get("delta")?.enabled, true);
    assert.equal(trusted.get("beta")?.ext, false);

    const include = { PI_MCP_EXT_INCLUDE: " alpha, gamma, delta , ," } as NodeJS.ProcessEnv;
    assert.deepEqual([...(serverNameSet(include.PI_MCP_EXT_INCLUDE) ?? [])].sort(), ["alpha", "delta", "gamma"]);
    assert.equal(shouldConnect(trusted.get("gamma")!, include), true);
    assert.equal(shouldConnect(trusted.get("beta")!, include), false);
    assert.equal(shouldConnect(trusted.get("delta")!, include), true);
    assert.equal(shouldConnect(trusted.get("sessOn")!, include), false);
    assert.equal(shouldConnect(trusted.get("alpha")!, include), false);

    const exclude = { PI_MCP_EXT_EXCLUDE: "gamma, sessOn, " } as NodeJS.ProcessEnv;
    assert.equal(shouldConnect(trusted.get("gamma")!, exclude), false);
    assert.equal(shouldConnect(trusted.get("delta")!, exclude), true);
    assert.equal(shouldConnect(trusted.get("sessOn")!, exclude), false);
    assert.equal(serverNameSet(undefined), undefined);
    assert.equal(serverNameSet("  ,  "), undefined);
    assert.equal(shouldConnect({ name: "delta", ext: true }, {} as NodeJS.ProcessEnv), true);

    process.env.PI_MCP_EXT_INCLUDE = "delta";
    process.env.PI_MCP_EXT_EXCLUDE = "delta";
    assert.equal(shouldConnect(trusted.get("delta")!), false);
    delete process.env.PI_MCP_EXT_EXCLUDE;
    assert.equal(shouldConnect(trusted.get("delta")!), true);
    assert.equal(shouldConnect(trusted.get("gamma")!), false);
  } finally {
    if (oldAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = oldAgentDir;
    if (oldInclude === undefined) delete process.env.PI_MCP_EXT_INCLUDE;
    else process.env.PI_MCP_EXT_INCLUDE = oldInclude;
    if (oldExclude === undefined) delete process.env.PI_MCP_EXT_EXCLUDE;
    else process.env.PI_MCP_EXT_EXCLUDE = oldExclude;
    rmSync(root, { recursive: true, force: true });
  }
});

test("shouldKeepConnection closes only legacy and unsupported-modern-version", () => {
  const keep: ServerEra[] = ["modern", "modern-dormant", "needs-auth", "error", "disabled", "unknown", "probing"];
  for (const era of keep) assert.equal(shouldKeepConnection(era), true, era);
  assert.equal(shouldKeepConnection("legacy"), false);
  assert.equal(shouldKeepConnection("unsupported-modern-version"), false);
});

function probeScript(reply: string): string {
  return `
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
writeFileSync(process.env.FIXTURE_PID_FILE, String(process.pid));
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (!("id" in req)) return;
  if (req.method === "server/discover") {
    process.stdout.write(JSON.stringify(${reply}) + "\\n");
  }
});
`;
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForDeath(pid: number): Promise<boolean> {
  for (let i = 0; i < 50 && isPidAlive(pid); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  return !isPidAlive(pid);
}

test("filtered servers are not connected, and legacy or unsupported probes are closed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-ext-session-"));
  const agentDir = join(dir, "agent");
  const projectDir = join(dir, "project");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(projectDir, { recursive: true });
  const oldAgentDir = process.env.PI_CODING_AGENT_DIR;
  const oldInclude = process.env.PI_MCP_EXT_INCLUDE;
  const oldExclude = process.env.PI_MCP_EXT_EXCLUDE;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  delete process.env.PI_MCP_EXT_INCLUDE;
  delete process.env.PI_MCP_EXT_EXCLUDE;

  const legacyPid = join(dir, "legacy.pid");
  const unsupportedPid = join(dir, "unsupported.pid");
  const dormantPid = join(dir, "dormant.pid");
  const optedPid = join(dir, "opted.pid");
  const excludedPid = join(dir, "excluded.pid");
  const legacyScript = join(dir, "legacy.mjs");
  const unsupportedScript = join(dir, "unsupported.mjs");
  const dormantScript = join(dir, "dormant.mjs");
  const modernScript = join(dir, "modern.mjs");
  writeFileSync(legacyScript, probeScript('{ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: "Method not found" } }'));
  writeFileSync(unsupportedScript, probeScript('{ jsonrpc: "2.0", id: req.id, error: { code: -32022, message: "UnsupportedProtocolVersion", data: { supported: ["2025-11-25"] } } }'));
  writeFileSync(dormantScript, probeScript('{ jsonrpc: "2.0", id: req.id, result: { resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: {} } }'));
  writeFileSync(modernScript, probeScript('{ jsonrpc: "2.0", id: req.id, result: { resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: { resources: {} } } }'));

  const pi = {
    appendEntry: () => {},
    sendMessage: () => {},
    sendUserMessage: () => {},
    getAllTools: () => [],
    getActiveTools: () => [],
    setActiveTools: () => {},
    registerTool: () => {},
    registerCommand: () => {},
    getMcpServers: () => [],
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd: projectDir,
    hasUI: false,
    mode: "print",
    signal: undefined,
    isProjectTrusted: () => false,
    hasPendingMessages: () => false,
    modelRegistry: { getProviderAuth: async () => undefined },
    sessionManager: { getBranch: () => [], getEntries: () => [] },
  } as unknown as ExtensionContext;
  const loadOptions = (): ConfigLoadOptions => ({ cwd: projectDir, isProjectTrusted: false, sessionServers: [] });

  const writeConfig = (optedExt: false | undefined) => {
    writeFileSync(join(agentDir, "mcp.json"), JSON.stringify({
      mcpServers: {
        legacy: { command: process.execPath, args: [legacyScript], env: { FIXTURE_PID_FILE: legacyPid } },
        unsupported: { command: process.execPath, args: [unsupportedScript], env: { FIXTURE_PID_FILE: unsupportedPid } },
        dormant: { command: process.execPath, args: [dormantScript], env: { FIXTURE_PID_FILE: dormantPid } },
        opted: { command: process.execPath, args: [modernScript], env: { FIXTURE_PID_FILE: optedPid }, ...(optedExt === false ? { ext: false } : {}) },
        excluded: { command: process.execPath, args: [modernScript], env: { FIXTURE_PID_FILE: excludedPid } },
        off: { command: process.execPath, args: [modernScript], env: { FIXTURE_PID_FILE: join(dir, "off.pid") }, enabled: false },
      },
    }));
  };

  let session: McpSession | undefined;
  try {
    writeConfig(false);
    process.env.PI_MCP_EXT_EXCLUDE = "excluded";
    process.env.PI_MCP_EXT_INCLUDE = "legacy, unsupported, dormant, opted, excluded, off";
    session = createMcpSession(pi, ctx);
    await session.reconcile(loadOptions());
    let states = await session.servers();
    const eras = Object.fromEntries(states.map((s) => [s.name, s.era]));
    assert.equal(eras.legacy, "legacy");
    assert.equal(eras.unsupported, "unsupported-modern-version");
    assert.equal(eras.dormant, "modern-dormant");
    assert.equal(eras.off, "disabled");
    assert.equal(eras.opted, undefined);
    assert.equal(eras.excluded, undefined);
    assert.equal(existsSync(optedPid), false);
    assert.equal(existsSync(excludedPid), false);

    const legacyPidNum = Number(readFileSync(legacyPid, "utf8").trim());
    const unsupportedPidNum = Number(readFileSync(unsupportedPid, "utf8").trim());
    assert.equal(await waitForDeath(legacyPidNum), true);
    assert.equal(await waitForDeath(unsupportedPidNum), true);

    await assert.rejects(session.withServer({ server: "legacy" }, async () => "ran"), {
      message: 'MCP server "legacy" speaks legacy MCP (pre-2026-07-28); use its standard MCP tools instead.',
    });
    await assert.rejects(session.withServer({ server: "opted" }, async () => "ran"), /Unknown MCP server "opted"/);
    await assert.rejects(session.withServer({ server: "off" }, async () => "ran"), {
      message: 'MCP server "off" is disabled.',
    });

    await session.reconcile(loadOptions());
    assert.equal(Number(readFileSync(legacyPid, "utf8").trim()), legacyPidNum);
    assert.equal(isPidAlive(legacyPidNum), false);

    delete process.env.PI_MCP_EXT_EXCLUDE;
    delete process.env.PI_MCP_EXT_INCLUDE;
    writeConfig(undefined);
    await session.reconcile(loadOptions());
    states = await session.servers();
    const again = Object.fromEntries(states.map((s) => [s.name, s.era]));
    assert.equal(again.opted, "modern");
    assert.equal(again.excluded, "modern");
    assert.equal(again.legacy, "legacy");
    assert.equal(isPidAlive(legacyPidNum), false);
    assert.equal(existsSync(optedPid), true);
    assert.equal(existsSync(excludedPid), true);
  } finally {
    await session?.shutdown();
    if (oldAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = oldAgentDir;
    if (oldInclude === undefined) delete process.env.PI_MCP_EXT_INCLUDE;
    else process.env.PI_MCP_EXT_INCLUDE = oldInclude;
    if (oldExclude === undefined) delete process.env.PI_MCP_EXT_EXCLUDE;
    else process.env.PI_MCP_EXT_EXCLUDE = oldExclude;
    rmSync(dir, { recursive: true, force: true });
  }
});
