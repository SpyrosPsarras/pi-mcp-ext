/**
 * Pi extension entry for @jangmanj/pi-mcp-ext.
 *
 * Runs alongside builtin:mcp without replacing /mcp or registering built-in MCP tool names.
 * Registers mcp_events, mcp_tasks, mcp_resources, mcp_prompts, mcp_skills, message renderers,
 * and session lifecycle handlers. Per-session runtime coordination lives in `./session.ts`.
 */

import { StringEnum, type ImageContent, type TextContent } from "@earendil-works/pi-ai";
import type {
  AgentBeforeSettleEvent,
  AgentBeforeSettleEventResult,
  AgentToolResult,
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
  ExtensionToolContext,
  MessageRenderOptions,
  MessageRenderer,
  RegisteredMcpServer,
  Theme,
  ToolResultEvent,
  ToolResultEventResult,
} from "@earendil-works/pi-coding-agent";
import type { AutocompleteItem } from "@earendil-works/pi-tui";
import { Type, type Static, type TUnsafe } from "typebox";

import { mcpNamespace, skillAutoApprove } from "./config.ts";
import { parseSlashPromptInput, type PromptDescriptor } from "./prompts.ts";
import {
  clearMcpStatus,
  createMcpSession,
  unknownServerError,
  type McpSession,
} from "./session.ts";
import { frameMcpTag } from "./framing.ts";
import { formatSkillsPromptSection, type LoadedSkillResult, type SkillEntry } from "./skills.ts";
import {
  EXT_TASKS,
  MESSAGE_EVENT,
  MESSAGE_RESOURCE,
  MESSAGE_TASK,
  type JsonObject,
  type PollEventsParams,
  type ServerState,
  type SubscribeRequest,
} from "./types.ts";

function stringEnum<const T extends readonly string[]>(
  values: T,
  options?: { description?: string; default?: T[number] },
): TUnsafe<T[number]> {
  return Type.Unsafe<T[number]>(StringEnum(values, options));
}

const McpEventsParams = Type.Object(
  {
    action: stringEnum(["servers", "list", "subscribe", "unsubscribe", "subscriptions", "poll"], {
      description: "Events operation to perform.",
    }),
    server: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Target MCP server name (required for list, subscribe, unsubscribe, poll).",
      }),
    ),
    name: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Event type name (required for subscribe, unsubscribe, poll).",
      }),
    ),
    arguments: Type.Optional(
      Type.Record(Type.String(), Type.Unknown(), {
        description: "Subscription filter or event arguments.",
      }),
    ),
    delivery: Type.Optional(
      stringEnum(["auto", "push", "poll"], {
        description: "Delivery mode preference (default: auto).",
      }),
    ),
    cursor: Type.Optional(
      Type.Union([Type.String(), Type.Null()], {
        description: "Starting cursor (null starts from now; omit to use persisted cursor).",
      }),
    ),
    maxAgeMs: Type.Optional(
      Type.Integer({
        minimum: 0,
        description: "Replay age limit in integer milliseconds.",
      }),
    ),
    maxEvents: Type.Optional(
      Type.Integer({
        minimum: 1,
        description: "Maximum events to return in a single poll batch.",
      }),
    ),
    holdSettle: Type.Optional(
      Type.Boolean({
        description:
          "Hold print/json settlement open until an event arrives or unsubscribe is called.",
      }),
    ),
    logLevel: Type.Optional(
      stringEnum(
        ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"],
        {
          description:
            "Per-request MCP log level (SEP-2575 io.modelcontextprotocol/logLevel) for list/poll.",
        },
      ),
    ),
  },
  { additionalProperties: false },
);

type McpEventsInput = Static<typeof McpEventsParams>;

const McpTasksParams = Type.Object(
  {
    action: stringEnum(["call", "get", "update", "cancel", "active"], {
      description: "Task operation to perform.",
    }),
    server: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Target MCP server name (required for call, get, update, cancel).",
      }),
    ),
    tool: Type.Optional(
      Type.String({
        minLength: 1,
        description: "MCP tool name on the server (required for call).",
      }),
    ),
    arguments: Type.Optional(
      Type.Record(Type.String(), Type.Unknown(), {
        description: "Tool call arguments for action 'call'.",
      }),
    ),
    taskId: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Task identifier (required for get, update, cancel).",
      }),
    ),
    inputResponses: Type.Optional(
      Type.Record(Type.String(), Type.Unknown(), {
        description: "Responses keyed by inputRequests identifier (for action 'update').",
      }),
    ),
    logLevel: Type.Optional(
      stringEnum(
        ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"],
        {
          description:
            "Per-request MCP log level (SEP-2575 io.modelcontextprotocol/logLevel) for call/get/update/cancel.",
        },
      ),
    ),
  },
  { additionalProperties: false },
);

type McpTasksInput = Static<typeof McpTasksParams>;

const LOG_LEVEL_SCHEMA = Type.Optional(
  stringEnum(
    ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"],
    {
      description:
        "Per-request MCP log level (SEP-2575 io.modelcontextprotocol/logLevel).",
    },
  ),
);

const McpResourcesParams = Type.Object(
  {
    action: stringEnum(
      ["list", "templates", "read", "directory", "subscribe", "unsubscribe", "subscriptions"],
      { description: "Resource or resource-subscription operation to perform." },
    ),
    server: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Target MCP server name (required except for 'subscriptions').",
      }),
    ),
    uri: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Resource or directory URI (required for read, directory, subscribe, unsubscribe).",
      }),
    ),
    cursor: Type.Optional(
      Type.String({
        description: "Pagination cursor for list, templates, or directory.",
      }),
    ),
    holdSettle: Type.Optional(
      Type.Boolean({
        description: "Hold headless print/json runs open while this resource watch is active.",
      }),
    ),
    logLevel: LOG_LEVEL_SCHEMA,
  },
  { additionalProperties: false },
);

type McpResourcesInput = Static<typeof McpResourcesParams>;

const McpPromptsParams = Type.Object(
  {
    action: stringEnum(["list", "get", "complete"], {
      description: "Prompt discovery, retrieval, or argument completion.",
    }),
    server: Type.String({
      minLength: 1,
      description: "Target MCP server name.",
    }),
    name: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Prompt name (required for get, or complete with refType='prompt').",
      }),
    ),
    uri: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Resource URI or template (for complete with refType='resource').",
      }),
    ),
    refType: Type.Optional(
      stringEnum(["prompt", "resource"], {
        description: "Completion reference type (default: 'prompt', or 'resource' when uri is given).",
      }),
    ),
    arguments: Type.Optional(
      Type.Record(Type.String(), Type.String(), {
        description: "Prompt arguments for 'get', or already-resolved context.arguments for 'complete'.",
      }),
    ),
    argumentName: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Argument name being completed (required for 'complete').",
      }),
    ),
    argumentValue: Type.Optional(
      Type.String({
        description: "Current partial argument value (for 'complete', default '').",
      }),
    ),
    logLevel: LOG_LEVEL_SCHEMA,
  },
  { additionalProperties: false },
);

type McpPromptsInput = Static<typeof McpPromptsParams>;

const McpSkillsParams = Type.Object(
  {
    action: stringEnum(["list", "get", "load", "read_file", "directory"], {
      description: "Skills over MCP (io.modelcontextprotocol/skills) operation.",
    }),
    server: Type.String({
      minLength: 1,
      description: "Target MCP server name.",
    }),
    uri: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Skill SKILL.md URI (required for get, load, read_file) or directory URI (for directory).",
      }),
    ),
    path: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Relative path or URI inside the retained skill manifest (required for read_file).",
      }),
    ),
    cursor: Type.Optional(
      Type.String({
        description: "Pagination cursor for action 'directory'.",
      }),
    ),
    logLevel: LOG_LEVEL_SCHEMA,
  },
  { additionalProperties: false },
);

type McpSkillsInput = Static<typeof McpSkillsParams>;

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function jsonResult<T>(data: T, logs?: readonly string[]): AgentToolResult<T> {
  const content: TextContent[] = [{ type: "text", text: JSON.stringify(data, null, 2) }];
  if (logs && logs.length > 0) {
    content.push({ type: "text", text: logs.join("\n") });
  }
  return {
    content,
    details: data,
  };
}

function toSessionServers(
  entries: readonly RegisteredMcpServer[],
): Array<{ name: string; config: JsonObject }> {
  return entries.map((entry: RegisteredMcpServer) => ({
    name: entry.name,
    config: { ...(entry.config as unknown as JsonObject) },
  }));
}

// ---------------------------------------------------------------------------------------------
// Custom message rendering ('mcp-event' & 'mcp-task')
// ---------------------------------------------------------------------------------------------

const ANSI_ESCAPE_RE = /\x1b(?:\[[0-9;]*[A-Za-z]|_.*?\x07|\].*?(?:\x07|\x1b\\))/g;

type RenderedCustomMessage = Parameters<MessageRenderer>[0];

function stripAnsi(text: string): string {
  return text.replace(ANSI_ESCAPE_RE, "");
}

function extractMessageText(content: RenderedCustomMessage["content"]): string {
  if (typeof content === "string") return content;
  return content
    .filter((block): block is TextContent => block.type === "text")
    .map((block: TextContent) => block.text)
    .join("\n");
}

function singleLineFallback(content: RenderedCustomMessage["content"]): string {
  const first = extractMessageText(content)
    .split(/\r?\n/)
    .map((line: string) => line.trim())
    .find((line: string) => line.length > 0);
  return first ?? "delivery";
}

function summarizeEventDetails(message: RenderedCustomMessage): string {
  const details = message.details;
  if (Array.isArray(details) && details.length > 0) {
    let count = 0;
    const sources: string[] = [];
    for (const entry of details) {
      if (isPlainObject(entry)) {
        const occ = Array.isArray(entry.occurrences) ? entry.occurrences.length : 1;
        count += occ;
        if (typeof entry.server === "string" && typeof entry.name === "string") {
          sources.push(`${entry.server}/${entry.name}`);
        }
      }
    }
    if (sources.length > 0) {
      return `${sources.join(", ")} (${count} ${count === 1 ? "event" : "events"})`;
    }
  }
  if (isPlainObject(details)) {
    if (Array.isArray(details.deliveries) && details.deliveries.length > 0) {
      let count = 0;
      const names: string[] = [];
      for (const d of details.deliveries) {
        if (isPlainObject(d)) {
          count += Array.isArray(d.occurrences) ? d.occurrences.length : 1;
          if (typeof d.server === "string" && typeof d.name === "string") {
            names.push(`${d.server}/${d.name}`);
          }
        }
      }
      if (names.length > 0) {
        return `${names.join(", ")} (${count} ${count === 1 ? "event" : "events"})`;
      }
    }
    const server = typeof details.server === "string" ? details.server : undefined;
    const name = typeof details.name === "string" ? details.name : undefined;
    if (Array.isArray(details.occurrences)) {
      const count = details.occurrences.length;
      const target = server && name ? `${server}/${name}` : (name ?? server ?? "stream");
      const trunc = details.truncated === true ? ", truncated" : "";
      return `${target}: ${count} ${count === 1 ? "event" : "events"}${trunc}`;
    }
    if (server || name) {
      const target = server && name ? `${server}/${name}` : (server ?? name ?? "event");
      const note =
        typeof details.reason === "string"
          ? ` (${details.reason})`
          : typeof details.message === "string"
            ? `: ${details.message}`
            : "";
      return `${target}${note}`;
    }
  }
  return singleLineFallback(message.content).replace(/\s+/g, " ");
}

function summarizeTaskDetails(message: RenderedCustomMessage): string {
  const details = message.details;
  if (isPlainObject(details)) {
    const taskObj = isPlainObject(details.task) ? details.task : details;
    const server = typeof details.server === "string" ? details.server : undefined;
    const tool =
      typeof details.toolName === "string"
        ? details.toolName
        : typeof details.tool === "string"
          ? details.tool
          : undefined;
    const taskId =
      typeof details.taskId === "string"
        ? details.taskId
        : typeof taskObj.taskId === "string"
          ? taskObj.taskId
          : undefined;
    const status =
      typeof details.status === "string"
        ? details.status
        : typeof taskObj.status === "string"
          ? taskObj.status
          : undefined;

    if (server || tool || taskId || status) {
      const head =
        server && tool ? `${server}/${tool}` : (server ?? tool ?? "task");
      const idPart = taskId ? ` #${taskId}` : "";
      const statusPart = status ? ` -> ${status}` : "";
      return `${head}${idPart}${statusPart}`;
    }
  }
  return singleLineFallback(message.content).replace(/\s+/g, " ");
}

function summarizeResourceDetails(message: RenderedCustomMessage): string {
  const details = message.details;
  if (isPlainObject(details) && Array.isArray(details.resources)) {
    const parts: string[] = [];
    for (const item of details.resources) {
      if (!isPlainObject(item) || typeof item.server !== "string") continue;
      const uris = Array.isArray(item.updatedUris)
        ? item.updatedUris.filter((u): u is string => typeof u === "string")
        : [];
      if (uris.length > 0) parts.push(`${item.server}: ${uris.join(", ")}`);
      else if (item.listChanged === true) parts.push(`${item.server}: list changed`);
    }
    if (parts.length > 0) return parts.join(" · ");
  }
  return singleLineFallback(message.content).replace(/\s+/g, " ");
}

function clampPlainText(text: string, maxCols: number): string {
  if (maxCols <= 0) return "";
  if (text.length <= maxCols) return text;
  if (maxCols === 1) return "…";
  return `${text.slice(0, maxCols - 1)}…`;
}

function splitPlainWidth(line: string, maxCols: number): string[] {
  const safeWidth = Math.max(1, maxCols);
  if (line.length <= safeWidth) return [line];
  const chunks: string[] = [];
  for (let offset = 0; offset < line.length; offset += safeWidth) {
    chunks.push(line.slice(offset, offset + safeWidth));
  }
  return chunks;
}

function createExpandableJsonRenderer(
  badgeLabel: string,
  summarize: (message: RenderedCustomMessage) => string,
): MessageRenderer {
  return (
    message: RenderedCustomMessage,
    options: MessageRenderOptions,
    theme: Theme,
  ): NonNullable<ReturnType<MessageRenderer>> => {
    const summaryPlain = summarize(message).replace(/[\r\n\t]+/g, " ").trim();
    const jsonSource =
      message.details !== undefined
        ? message.details
        : { customType: message.customType, content: extractMessageText(message.content) };
    const jsonFormatted = JSON.stringify(jsonSource, null, 2) ?? "null";

    return {
      invalidate(): void {},
      render(width: number): string[] {
        const totalWidth = Math.max(1, width);
        const padCount = Math.min(
          Math.max(0, options.outputPad ?? 0),
          Math.max(0, Math.floor((totalWidth - 1) / 2)),
        );
        const pad = " ".repeat(padCount);
        const innerWidth = Math.max(1, totalWidth - padCount * 2);
        const rawBadge = `[${badgeLabel}]`;

        if (!options.expanded) {
          const expandHint = options.keyHint("app.tools.expand", "to expand");
          const hintVisible = stripAnsi(expandHint);
          const hintSuffixPlain = hintVisible.length > 0 ? ` (${hintVisible})` : "";
          const badgeAndSpace = rawBadge.length + 1;

          if (innerWidth <= rawBadge.length) {
            const clipped = clampPlainText(rawBadge, innerWidth);
            return [
              theme.bg(
                "customMessageBg",
                pad + theme.fg("customMessageLabel", theme.bold(clipped)) + " ".repeat(Math.max(0, totalWidth - padCount - clipped.length)),
              ),
            ];
          }

          const includeHint =
            hintSuffixPlain.length > 0 &&
            innerWidth > badgeAndSpace + hintSuffixPlain.length + 4;
          const summaryBudget =
            innerWidth - badgeAndSpace - (includeHint ? hintSuffixPlain.length : 0);
          const clampedSummary = clampPlainText(summaryPlain, summaryBudget);
          const hintRendered = includeHint
            ? ` ${theme.fg("muted", "(")}${expandHint}${theme.fg("muted", ")")}`
            : "";
          const visibleContentLen =
            rawBadge.length +
            1 +
            clampedSummary.length +
            (includeHint ? hintSuffixPlain.length : 0);
          const trailingSpaces = " ".repeat(Math.max(0, totalWidth - padCount - visibleContentLen));
          const styledLine =
            pad +
            theme.fg("customMessageLabel", theme.bold(rawBadge)) +
            " " +
            theme.fg("customMessageText", clampedSummary) +
            hintRendered +
            trailingSpaces;
          return [theme.bg("customMessageBg", styledLine)];
        }

        const lines: string[] = [];
        const headerSummary = clampPlainText(
          summaryPlain,
          Math.max(0, innerWidth - rawBadge.length - 1),
        );
        const headerVisibleLen =
          rawBadge.length + (headerSummary.length > 0 ? 1 + headerSummary.length : 0);
        const headerTrailing = " ".repeat(Math.max(0, totalWidth - padCount - headerVisibleLen));
        const headerLine =
          pad +
          theme.fg("customMessageLabel", theme.bold(rawBadge)) +
          (headerSummary.length > 0 ? ` ${theme.fg("customMessageText", headerSummary)}` : "") +
          headerTrailing;
        lines.push(theme.bg("customMessageBg", headerLine));

        for (const rawJsonLine of jsonFormatted.replace(/\t/g, "  ").split("\n")) {
          for (const chunk of splitPlainWidth(rawJsonLine, innerWidth)) {
            const rightPad = " ".repeat(Math.max(0, totalWidth - padCount - chunk.length));
            lines.push(
              theme.bg(
                "customMessageBg",
                `${pad}${theme.fg("customMessageText", chunk)}${rightPad}`,
              ),
            );
          }
        }
        return lines;
      },
    };
  };
}

// ---------------------------------------------------------------------------------------------
// Extension entry
// ---------------------------------------------------------------------------------------------

const SKILL_REFRESH_WAIT_MS = 2_000;

function skillCommandMessage(loaded: LoadedSkillResult, args: string): string {
  const framed = frameMcpTag(
    "mcp_skill",
    { server: loaded.server, uri: loaded.uri, name: loaded.name },
    `\n${loaded.content}\n`,
  );
  const files =
    loaded.supportingUris.length > 0
      ? `\n\nRead its supporting files with the mcp_skills tool (action "read_file", server "${loaded.server}", uri "${loaded.uri}", path relative to the skill).`
      : "";
  return `${framed}${files}${args ? `\n\n${args}` : ""}`;
}

export default function extension(pi: ExtensionAPI): void {
  let currentSession: McpSession | undefined;
  const registeredPromptCommandNames = new Set<string>();
  const registeredSkillCommandNames = new Set<string>();

  function activeSession(): McpSession | undefined {
    return currentSession && !currentSession.signal.aborted ? currentSession : undefined;
  }

  function requireActiveSession(): McpSession {
    const session = activeSession();
    if (!session) {
      throw new Error("MCP extension session is not active.");
    }
    return session;
  }

  async function executeSlashPrompt(
    serverName: string,
    promptName: string,
    rawArgs: string,
    ctx: ExtensionCommandContext,
  ): Promise<void> {
    const session = requireActiveSession();
    await session.withServer({ server: serverName, capability: "prompts", ctx }, async () => {
      const descriptors = await session.prompts.list(serverName);
      const descriptor = descriptors.find((d) => d.name === promptName);
      const parsed = parseSlashPromptInput(rawArgs, descriptor?.arguments);
      const resolvedArgs = { ...parsed.resolved };

      // Prompt interactively for any missing required arguments when UI is available.
      if (ctx.hasUI && descriptor?.arguments) {
        for (const argDef of descriptor.arguments) {
          if (argDef.required && !(argDef.name in resolvedArgs)) {
            const val = await ctx.ui.input(
              `[${serverName}/${promptName}] ${argDef.title ?? argDef.name}${argDef.description ? ` — ${argDef.description}` : ""}`,
              "Required argument",
            );
            if (val === undefined) return;
            resolvedArgs[argDef.name] = val;
          }
        }
      }

      const promptRes = await session.prompts.get(serverName, promptName, resolvedArgs);
      if (promptRes.images.length > 0) {
        const blocks: Array<TextContent | ImageContent> = [];
        if (promptRes.renderedText) blocks.push({ type: "text", text: promptRes.renderedText });
        blocks.push(...promptRes.images);
        pi.sendUserMessage(blocks);
      } else {
        pi.sendUserMessage(promptRes.renderedText || `Run prompt ${serverName}/${promptName}`);
      }
    });
  }

  function ensurePerPromptCommand(serverName: string, prompt: PromptDescriptor): void {
    const cmdName = `mcp-prompt:${serverName}:${prompt.name}`;
    if (registeredPromptCommandNames.has(cmdName)) return;
    registeredPromptCommandNames.add(cmdName);
    pi.registerCommand(cmdName, {
      description: prompt.description ?? prompt.title ?? `MCP prompt ${prompt.name} (${serverName})`,
      getArgumentCompletions: async (prefix: string): Promise<AutocompleteItem[] | null> => {
        const session = activeSession();
        if (!session) return null;
        const latestDesc = session.prompts
          .cachedPrompts()
          .find((p) => p.server === serverName && p.prompt.name === prompt.name)?.prompt;
        if (!latestDesc) return null;
        const parsed = parseSlashPromptInput(prefix, latestDesc.arguments);
        if (!parsed.completing) return null;
        try {
          const comp = await session.prompts.complete(
            serverName,
            { type: "ref/prompt", name: prompt.name },
            { name: parsed.completing.name, value: parsed.completing.value },
            parsed.resolved,
          );
          if (comp.values.length === 0) return null;
          return comp.values.map((v) => {
            const quoted = /\s/.test(v) ? JSON.stringify(v) : v;
            const fullVal = `${parsed.completing!.replacePrefix}${quoted}`;
            return { value: fullVal, label: v, description: `${parsed.completing!.name}` };
          });
        } catch {
          return null;
        }
      },
      handler: async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
        try {
          await executeSlashPrompt(serverName, prompt.name, args, ctx);
        } catch (err) {
          if (ctx.hasUI) ctx.ui.notify(errorMessage(err), "error");
          else throw err;
        }
      },
    });
  }

  async function executeSkillCommand(
    serverName: string,
    skillName: string,
    rawArgs: string,
    ctx: ExtensionCommandContext,
  ): Promise<void> {
    const session = requireActiveSession();
    await session.withServer({ server: serverName, capability: "skills", ctx }, async () => {
      const skill = session.skills
        .listed()
        .find((l) => l.server === serverName)
        ?.skills.find((s) => s.frontmatter.name === skillName);
      if (!skill) throw new Error(`MCP server "${serverName}" no longer offers skill "${skillName}".`);
      const loaded = await session.skills.load(serverName, skill.uri, { approve: async () => true });
      pi.sendUserMessage(skillCommandMessage(loaded, rawArgs.trim()));
    });
  }

  function ensureSkillCommand(serverName: string, skill: SkillEntry): void {
    const cmdName = `mcp-skill:${serverName}:${skill.frontmatter.name}`;
    if (registeredSkillCommandNames.has(cmdName)) return;
    registeredSkillCommandNames.add(cmdName);
    pi.registerCommand(cmdName, {
      description: skill.frontmatter.description,
      handler: async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
        try {
          await executeSkillCommand(serverName, skill.frontmatter.name, args, ctx);
        } catch (err) {
          if (ctx.hasUI) ctx.ui.notify(errorMessage(err), "error");
          else throw err;
        }
      },
    });
  }

  pi.registerCommand("mcp-prompt", {
    description: "Invoke an MCP 2026-07-28 server prompt (/mcp-prompt <server>/<prompt> [key=value ...])",
    getArgumentCompletions: async (prefix: string): Promise<AutocompleteItem[] | null> => {
      const session = activeSession();
      if (!session) return null;
      const all = session.prompts.cachedPrompts();
      if (all.length === 0) return null;

      const firstSpace = prefix.indexOf(" ");
      if (firstSpace === -1) {
        const matches = all
          .map(({ server, prompt }) => ({
            target: `${server}/${prompt.name}`,
            desc: prompt.description ?? prompt.title,
          }))
          .filter((item) => item.target.startsWith(prefix));
        return matches.length > 0
          ? matches.map((m) => ({
              value: `${m.target} `,
              label: m.target,
              ...(m.desc ? { description: m.desc } : {}),
            }))
          : null;
      }

      const head = prefix.slice(0, firstSpace);
      const slash = head.indexOf("/");
      if (slash <= 0) return null;
      const serverName = head.slice(0, slash);
      const promptName = head.slice(slash + 1);
      const found = all.find((p) => p.server === serverName && p.prompt.name === promptName);
      if (!found) return null;

      const tail = prefix.slice(firstSpace + 1);
      const parsed = parseSlashPromptInput(tail, found.prompt.arguments);
      if (!parsed.completing) return null;
      try {
        const comp = await session.prompts.complete(
          serverName,
          { type: "ref/prompt", name: promptName },
          { name: parsed.completing.name, value: parsed.completing.value },
          parsed.resolved,
        );
        if (comp.values.length === 0) return null;
        return comp.values.map((v) => {
          const quoted = /\s/.test(v) ? JSON.stringify(v) : v;
          return {
            value: `${head} ${parsed.completing!.replacePrefix}${quoted}`,
            label: v,
            description: parsed.completing!.name,
          };
        });
      } catch {
        return null;
      }
    },
    handler: async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
      const session = requireActiveSession();
      await session.servers(undefined, ctx);

      const trimmed = args.trim();
      if (!trimmed) {
        const available = session.prompts.cachedPrompts();
        if (available.length === 0) {
          if (ctx.hasUI) ctx.ui.notify("No MCP 2026-07-28 prompts discovered on connected servers.", "info");
          return;
        }
        if (!ctx.hasUI) return;
        const labels = available.map(
          ({ server, prompt }) =>
            `${server}/${prompt.name}${prompt.description ? ` — ${prompt.description}` : ""}`,
        );
        const picked = await ctx.ui.select("Select an MCP prompt", labels);
        if (!picked) return;
        const idx = labels.indexOf(picked);
        if (idx < 0) return;
        const chosen = available[idx];
        await executeSlashPrompt(chosen.server, chosen.prompt.name, "", ctx);
        return;
      }

      const spaceIdx = trimmed.indexOf(" ");
      const head = spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx);
      const rest = spaceIdx === -1 ? "" : trimmed.slice(spaceIdx + 1);
      const slashIdx = head.indexOf("/");
      if (slashIdx <= 0 || slashIdx === head.length - 1) {
        if (ctx.hasUI) ctx.ui.notify("Usage: /mcp-prompt <server>/<prompt> [key=value ...]", "warning");
        return;
      }
      await executeSlashPrompt(head.slice(0, slashIdx), head.slice(slashIdx + 1), rest, ctx);
    },
  });

  pi.registerMessageRenderer(
    MESSAGE_EVENT,
    createExpandableJsonRenderer(MESSAGE_EVENT, summarizeEventDetails),
  );
  pi.registerMessageRenderer(
    MESSAGE_TASK,
    createExpandableJsonRenderer(MESSAGE_TASK, summarizeTaskDetails),
  );
  pi.registerMessageRenderer(
    MESSAGE_RESOURCE,
    createExpandableJsonRenderer(MESSAGE_RESOURCE, summarizeResourceDetails),
  );

  pi.registerTool({
    name: "mcp_events",
    label: "MCP Events",
    description:
      "Inspect MCP 2026-07-28 servers, list event types, manage event subscriptions, or poll events once.",
    exposure: "direct",
    parameters: McpEventsParams,
    async execute(
      _toolCallId: string,
      params: McpEventsInput,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      ctx: ExtensionToolContext,
    ): Promise<AgentToolResult<unknown>> {

      switch (params.action) {
        case "servers": {
          const session = activeSession();
          if (!session) return jsonResult<ServerState[]>([]);
          const states = await session.servers(signal, ctx);
          return jsonResult(states);
        }

        case "subscriptions": {
          const session = activeSession();
          if (!session) return jsonResult([]);
          await session.servers(signal, ctx);
          const all = session.events.subscriptions();
          const filtered = params.server
            ? all.filter((sub) => sub.server === params.server)
            : all;
          return jsonResult(filtered);
        }

        case "list": {
          if (!params.server) {
            throw new Error('mcp_events action "list" requires parameter "server".');
          }
          const server = params.server;
          const session = requireActiveSession();
          const { value, logs } = await session.withServer(
            { server, capability: "events", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              const list = await session.events.list(server, logOpts);
              return list;
            },
          );
          return jsonResult(value, logs);
        }

        case "subscribe": {
          if (!params.server) {
            throw new Error('mcp_events action "subscribe" requires parameter "server".');
          }
          if (!params.name) {
            throw new Error('mcp_events action "subscribe" requires parameter "name".');
          }
          const server = params.server;
          const name = params.name;
          const session = requireActiveSession();
          const { value } = await session.withServer(
            { server, capability: "events", signal, ctx },
            async () => {
              const mode = ctx?.mode;
              const defaultHoldSettle = mode === "print" || mode === "json";
              const req: SubscribeRequest = {
                server,
                name,
                ...(params.arguments !== undefined ? { arguments: params.arguments } : {}),
                delivery: params.delivery ?? "auto",
                ...(params.cursor !== undefined ? { cursor: params.cursor } : {}),
                ...(params.maxAgeMs !== undefined ? { maxAgeMs: params.maxAgeMs } : {}),
                holdSettle: params.holdSettle ?? defaultHoldSettle,
              };
              const subscription = await session.events.subscribe(req);
              return subscription;
            },
          );
          return jsonResult(value);
        }

        case "unsubscribe": {
          if (!params.server) {
            throw new Error('mcp_events action "unsubscribe" requires parameter "server".');
          }
          if (!params.name) {
            throw new Error('mcp_events action "unsubscribe" requires parameter "name".');
          }
          const session = requireActiveSession();
          const states = await session.servers(signal, ctx);
          const hasPersisted = session.events
            .subscriptions()
            .some((sub) => sub.server === params.server);
          if (!states.some((state) => state.name === params.server) && !hasPersisted) {
            throw unknownServerError(
              params.server,
              states.map((state) => state.name),
            );
          }
          const removed = await session.events.unsubscribe(
            params.server,
            params.name,
            params.arguments,
          );
          return jsonResult({
            server: params.server,
            name: params.name,
            removed,
          });
        }

        case "poll": {
          if (!params.server) {
            throw new Error('mcp_events action "poll" requires parameter "server".');
          }
          if (!params.name) {
            throw new Error('mcp_events action "poll" requires parameter "name".');
          }
          const server = params.server;
          const session = requireActiveSession();
          const pollParams: PollEventsParams = {
            name: params.name,
            ...(params.arguments !== undefined ? { arguments: params.arguments } : {}),
            cursor: params.cursor ?? null,
            ...(params.maxAgeMs !== undefined ? { maxAgeMs: params.maxAgeMs } : {}),
            ...(params.maxEvents !== undefined ? { maxEvents: params.maxEvents } : {}),
          };
          const { value, logs } = await session.withServer(
            { server, capability: "events", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              const result = await session.events.poll(server, pollParams, logOpts);
              return result;
            },
          );
          return jsonResult(value, logs);
        }
      }
    },
  });

  pi.registerTool({
    name: "mcp_tasks",
    label: "MCP Tasks",
    description:
      "Call MCP tools with 2026-07-28 task support, inspect or answer inputRequests, cancel tasks, or list active session tasks.",
    exposure: "direct",
    parameters: McpTasksParams,
    async execute(
      _toolCallId: string,
      params: McpTasksInput,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      ctx: ExtensionToolContext,
    ): Promise<AgentToolResult<unknown>> {

      switch (params.action) {
        case "active": {
          const session = activeSession();
          if (!session) return jsonResult([]);
          const active = session.tasks.active();
          const filtered = params.server
            ? active.filter((task) => task.server === params.server)
            : active;
          return jsonResult(filtered);
        }

        case "call": {
          if (!params.server) {
            throw new Error('mcp_tasks action "call" requires parameter "server".');
          }
          if (!params.tool) {
            throw new Error('mcp_tasks action "call" requires parameter "tool".');
          }
          const server = params.server;
          const tool = params.tool;
          const session = requireActiveSession();
          const { value, logs } = await session.withServer(
            { server, capability: "tasks", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              const outcome = await session.tasks.call(server, tool, params.arguments, signal, logOpts);
              return outcome;
            },
          );
          return jsonResult(value, logs);
        }

        case "get": {
          if (!params.server) {
            throw new Error('mcp_tasks action "get" requires parameter "server".');
          }
          if (!params.taskId) {
            throw new Error('mcp_tasks action "get" requires parameter "taskId".');
          }
          const server = params.server;
          const taskId = params.taskId;
          const session = requireActiveSession();
          const { value, logs } = await session.withServer(
            { server, capability: "tasks", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              const task = await session.tasks.get(server, taskId, logOpts);
              return task;
            },
          );
          return jsonResult(value, logs);
        }

        case "update": {
          if (!params.server) {
            throw new Error('mcp_tasks action "update" requires parameter "server".');
          }
          if (!params.taskId) {
            throw new Error('mcp_tasks action "update" requires parameter "taskId".');
          }
          if (!params.inputResponses) {
            throw new Error(
              'mcp_tasks action "update" requires parameter "inputResponses".',
            );
          }
          const server = params.server;
          const taskId = params.taskId;
          const inputResponses = params.inputResponses;
          const session = requireActiveSession();
          const { logs } = await session.withServer(
            { server, capability: "tasks", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              await session.tasks.update(server, taskId, inputResponses, logOpts);
            },
          );
          return jsonResult({ server, taskId, updated: true }, logs);
        }

        case "cancel": {
          if (!params.server) {
            throw new Error('mcp_tasks action "cancel" requires parameter "server".');
          }
          if (!params.taskId) {
            throw new Error('mcp_tasks action "cancel" requires parameter "taskId".');
          }
          const server = params.server;
          const taskId = params.taskId;
          const session = requireActiveSession();
          const { logs } = await session.withServer(
            { server, capability: "tasks", logLevel: params.logLevel, signal, ctx },
            async ({ logOpts }) => {
              await session.tasks.cancel(server, taskId, logOpts);
            },
          );
          return jsonResult({ server, taskId, cancelled: true }, logs);
        }
      }
    },
  });

  pi.registerTool({
    name: "mcp_resources",
    label: "MCP Resources",
    description:
      "List, read, browse directories, or subscribe to live updates on MCP 2026-07-28 server resources.",
    exposure: "direct",
    parameters: McpResourcesParams,
    async execute(
      _toolCallId: string,
      params: McpResourcesInput,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      ctx: ExtensionToolContext,
    ): Promise<AgentToolResult<unknown>> {

      if (params.action === "subscriptions") {
        const session = activeSession();
        if (!session) return jsonResult([]);
        await session.servers(signal, ctx);
        return jsonResult(session.resources.subscriptions(params.server));
      }

      if (!params.server) {
        throw new Error(`mcp_resources action "${params.action}" requires parameter "server".`);
      }
      const server = params.server;
      const session = requireActiveSession();

      if (params.action === "unsubscribe") {
        if (!params.uri) {
          throw new Error('mcp_resources action "unsubscribe" requires parameter "uri".');
        }
        const removed = session.resources.unsubscribe(server, params.uri);
        return jsonResult({ server, uri: params.uri, removed });
      }

      const action = params.action;
      const { value: build, logs } = await session.withServer(
        { server, capability: "resources", logLevel: params.logLevel, signal, ctx },
        async ({ logOpts }): Promise<(logs: string[]) => AgentToolResult<unknown>> => {
          switch (action) {
            case "list": {
              const out = await session.resources.list(server, params.cursor, logOpts);
              return (logs) => jsonResult({ server, ...out }, logs);
            }
            case "templates": {
              const out = await session.resources.templates(server, params.cursor, logOpts);
              return (logs) => jsonResult({ server, ...out }, logs);
            }
            case "read": {
              if (!params.uri) {
                throw new Error('mcp_resources action "read" requires parameter "uri".');
              }
              const uri = params.uri;
              const out = await session.resources.read(server, uri, logOpts);
              return (logs) => {
                const content: Array<TextContent | ImageContent> = [...out.blocks];
                if (logs.length > 0) {
                  content.push({ type: "text", text: logs.join("\n") });
                }
                return {
                  content,
                  structuredContent: { server, uri, contents: out.contents },
                  details: { server, uri, contents: out.contents },
                } as AgentToolResult<unknown>;
              };
            }
            case "directory": {
              if (!params.uri) {
                throw new Error('mcp_resources action "directory" requires parameter "uri".');
              }
              const uri = params.uri;
              const out = await session.resources.directory(server, uri, params.cursor, logOpts);
              return (logs) => jsonResult({ server, uri, ...out }, logs);
            }
            case "subscribe": {
              if (!params.uri) {
                throw new Error('mcp_resources action "subscribe" requires parameter "uri".');
              }
              const mode = ctx?.mode;
              const defaultHold = mode === "print" || mode === "json";
              const rec = session.resources.subscribe(server, params.uri, params.holdSettle ?? defaultHold);
              return () => jsonResult(rec);
            }
          }
        },
      );
      return build(logs);
    },
  });

  pi.registerTool({
    name: "mcp_prompts",
    label: "MCP Prompts",
    description:
      "List MCP 2026-07-28 prompts, retrieve rendered prompt messages, or autocomplete prompt/resource arguments.",
    exposure: "direct",
    parameters: McpPromptsParams,
    async execute(
      _toolCallId: string,
      params: McpPromptsInput,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      ctx: ExtensionToolContext,
    ): Promise<AgentToolResult<unknown>> {
      const session = requireActiveSession();
      const server = params.server;
      const logLevel = params.logLevel;

      switch (params.action) {
        case "list": {
          const { value: prompts, logs } = await session.withServer(
            { server, capability: "prompts", logLevel, signal, ctx },
            ({ logOpts }) => session.prompts.list(server, logOpts),
          );
          return jsonResult({ server, prompts }, logs);
        }
        case "get": {
          if (!params.name) {
            throw new Error('mcp_prompts action "get" requires parameter "name".');
          }
          const name = params.name;
          const { value: res, logs } = await session.withServer(
            { server, capability: "prompts", logLevel, signal, ctx },
            ({ logOpts }) => session.prompts.get(server, name, params.arguments, logOpts),
          );
          const content: Array<TextContent | ImageContent> = [
            {
              type: "text",
              text: JSON.stringify(
                {
                  server,
                  name,
                  ...(res.description ? { description: res.description } : {}),
                  messages: res.messages,
                  renderedText: res.renderedText,
                },
                null,
                2,
              ),
            },
            ...res.images,
          ];
          if (logs.length > 0) {
            content.push({ type: "text", text: logs.join("\n") });
          }
          return {
            content,
            details: { server, name, messages: res.messages },
          };
        }
        case "complete": {
          if (!params.argumentName) {
            throw new Error('mcp_prompts action "complete" requires parameter "argumentName".');
          }
          const argument = { name: params.argumentName, value: params.argumentValue ?? "" };
          const { value: out, logs } = await session.withServer(
            { server, capability: "completions", logLevel, signal, ctx },
            async ({ logOpts }) => {
              const isResource = params.refType === "resource" || Boolean(params.uri && !params.name);
              if (isResource) {
                if (!params.uri) {
                  throw new Error('mcp_prompts resource completion requires parameter "uri".');
                }
                return session.prompts.complete(
                  server,
                  { type: "ref/resource", uri: params.uri },
                  argument,
                  params.arguments,
                  logOpts,
                );
              }
              if (!params.name) {
                throw new Error('mcp_prompts prompt completion requires parameter "name".');
              }
              return session.prompts.complete(
                server,
                { type: "ref/prompt", name: params.name },
                argument,
                params.arguments,
                logOpts,
              );
            },
          );
          return jsonResult(out, logs);
        }
      }
    },
  });

  pi.registerTool({
    name: "mcp_skills",
    label: "MCP Skills",
    description:
      "Discover, verify, approve, and load Agent Skills over MCP (io.modelcontextprotocol/skills) and their supporting files.",
    exposure: "direct",
    parameters: McpSkillsParams,
    async execute(
      _toolCallId: string,
      params: McpSkillsInput,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      ctx: ExtensionToolContext,
    ): Promise<AgentToolResult<unknown>> {
      const session = requireActiveSession();
      const server = params.server;

      const { value: build, logs } = await session.withServer(
        { server, capability: "skills", logLevel: params.logLevel, signal, ctx },
        async ({ logOpts }): Promise<(logs: string[]) => AgentToolResult<unknown>> => {
          switch (params.action) {
            case "list": {
              const skills = await session.skills.list(server, logOpts);
              return (logs) => jsonResult({ server, skills }, logs);
            }
            case "get": {
              if (!params.uri) {
                throw new Error('mcp_skills action "get" requires parameter "uri".');
              }
              const skill = await session.skills.get(server, params.uri, logOpts);
              return (logs) => jsonResult({ server, skill }, logs);
            }
            case "load": {
              if (!params.uri) {
                throw new Error('mcp_skills action "load" requires parameter "uri".');
              }
              const loaded = await session.skills.load(server, params.uri, {
                ...logOpts,
                autoApprove: skillAutoApprove(server),
                approve: ctx?.hasUI
                  ? async ({ server, entry, fileCount, totalBytes }) => {
                      const dynamicNote =
                        entry.resources === "dynamic"
                          ? "\nWARNING: Dynamic skill (content has no pinned SHA-256 manifest; approval applies to this load only)."
                          : `\nManifest: ${fileCount} file(s), ${totalBytes} bytes (SHA-256 verified).`;
                      const allowedToolsNote =
                        entry.frontmatter["allowed-tools"] !== undefined
                          ? `\nRequested allowed-tools: ${JSON.stringify(entry.frontmatter["allowed-tools"])}`
                          : "";
                      return ctx.ui.confirm(
                        `Approve MCP skill "${entry.frontmatter.name}" from "${server}"?`,
                        `URI: ${entry.uri}\nDescription: ${entry.frontmatter.description}${dynamicNote}${allowedToolsNote}`,
                      );
                    }
                  : undefined,
              });
              return (logs) => {
                const framed = frameMcpTag(
                  "mcp_skill",
                  { server: loaded.server, uri: loaded.uri, name: loaded.name },
                  `\n${loaded.content}\n`,
                );
                const content: TextContent[] = [
                  {
                    type: "text",
                    text: JSON.stringify(
                      {
                        server: loaded.server,
                        uri: loaded.uri,
                        name: loaded.name,
                        description: loaded.description,
                        supportingUris: loaded.supportingUris,
                        ...(loaded.cacheDir ? { cacheDir: loaded.cacheDir } : {}),
                      },
                      null,
                      2,
                    ),
                  },
                  { type: "text", text: framed },
                ];
                if (logs.length > 0) {
                  content.push({ type: "text", text: logs.join("\n") });
                }
                return { content, details: loaded };
              };
            }
            case "read_file": {
              if (!params.uri) {
                throw new Error('mcp_skills action "read_file" requires parameter "uri" (skill SKILL.md URI).');
              }
              if (!params.path) {
                throw new Error('mcp_skills action "read_file" requires parameter "path".');
              }
              const file = await session.skills.readFile(server, params.uri, params.path, logOpts);
              return (logs) => jsonResult(file, logs);
            }
            case "directory": {
              if (!params.uri) {
                throw new Error('mcp_skills action "directory" requires parameter "uri".');
              }
              const uri = params.uri;
              const dir = await session.skills.directory(server, uri, params.cursor, logOpts);
              return (logs) => jsonResult({ server, uri, ...dir }, logs);
            }
          }
        },
      );
      return build(logs);
    },
  });

  pi.on("resources_discover", async () => {
    const skillPaths = currentSession?.skills.verifiedSkillPaths() ?? [];
    return skillPaths.length > 0 ? { skillPaths } : {};
  });

  pi.on("session_start", async (_event, ctx) => {
    if (currentSession) {
      await currentSession.shutdown(ctx);
    }

    const session = createMcpSession(pi, ctx);
    currentSession = session;

    // Released when the session shuts down (the prompts engine drops its listeners).
    session.prompts.onPromptsChanged((serverName, prompts) => {
      for (const prompt of prompts) {
        ensurePerPromptCommand(serverName, prompt);
      }
    });
    session.skills.onSkillsListed((serverName, skills) => {
      for (const skill of skills) {
        ensureSkillCommand(serverName, skill);
      }
    });

    session.restoreBranch(ctx.sessionManager.getBranch(), ctx.sessionManager.getEntries(), ctx);

    await session.reconcile({
      cwd: ctx.cwd,
      isProjectTrusted: ctx.isProjectTrusted(),
      sessionServers: toSessionServers(pi.getMcpServers()),
    }, ctx);
  });

  pi.on("mcp_servers_change", async (event, ctx) => {
    const session = activeSession();
    if (!session) return;

    await session.reconcile({
      cwd: ctx.cwd,
      isProjectTrusted: ctx.isProjectTrusted(),
      sessionServers: toSessionServers(event.servers ?? pi.getMcpServers()),
    }, ctx);
  });

  pi.on("before_agent_start", async (event, ctx) => {
    const session = activeSession();
    if (!session) return;
    await session.ready(ctx.signal);
    await session.skills.refreshStale(SKILL_REFRESH_WAIT_MS);
    const section = formatSkillsPromptSection(session.skills.listed());
    if (section) event.systemPromptOptions.sections.mcp_skills = section;
    else delete event.systemPromptOptions.sections.mcp_skills;
  });

  pi.on("session_tree", (_event, ctx) => {
    const session = activeSession();
    if (!session) return;
    session.restoreBranch(ctx.sessionManager.getBranch(), ctx.sessionManager.getEntries(), ctx);
  });

  pi.on("tool_result", async (event: ToolResultEvent, ctx): Promise<ToolResultEventResult | undefined> => {
    const session = activeSession();
    if (!session) return undefined;

    if (!event.isError || !event.toolName.startsWith("mcp__")) {
      return undefined;
    }

    const errorText = event.content
      .filter((block): block is TextContent => block.type === "text")
      .map((block: TextContent) => block.text)
      .join("\n");
    if (!errorText.includes("-32021") || !errorText.includes(EXT_TASKS)) {
      return undefined;
    }

    const states = await session.servers(ctx.signal, ctx);

    let serverName: string | undefined;
    let toolName: string | undefined;

    if (
      "details" in event &&
      isPlainObject(event.details) &&
      typeof event.details.server === "string" &&
      typeof event.details.tool === "string"
    ) {
      serverName = event.details.server;
      toolName = event.details.tool;
    } else {
      const candidates = states
        .map((state) => ({ name: state.name, namespace: mcpNamespace(state.name) }))
        .filter(
          (cfg) =>
            event.toolName.startsWith(`${cfg.namespace}__`) &&
            event.toolName.length > cfg.namespace.length + 2,
        )
        .sort((a, b) => b.namespace.length - a.namespace.length);
      const matched = candidates[0];
      if (matched) {
        serverName = matched.name;
        toolName = event.toolName.slice(matched.namespace.length + 2);
      }
    }

    if (!serverName || !toolName) return undefined;

    const state = states.find((candidate) => candidate.name === serverName);
    if (!state || state.era !== "modern" || !state.tasks) {
      return undefined;
    }

    const callSpec = JSON.stringify({
      action: "call",
      server: serverName,
      tool: toolName,
      arguments: event.input,
    });
    const hint = `Hint: Tool "${toolName}" on MCP server "${serverName}" requires ${EXT_TASKS}; use mcp_tasks ${callSpec}.`;

    const nextContent = [...event.content];
    const lastIdx = nextContent.length - 1;
    const lastBlock = lastIdx >= 0 ? nextContent[lastIdx] : undefined;
    if (lastBlock && lastBlock.type === "text") {
      nextContent[lastIdx] = { ...lastBlock, text: `${lastBlock.text}\n${hint}` };
    } else {
      nextContent.push({ type: "text", text: hint });
    }

    return {
      content: nextContent,
      ...(event.structuredContent !== undefined
        ? { structuredContent: event.structuredContent }
        : {}),
    };
  });

  pi.on(
    "agent_before_settle",
    async (
      event: AgentBeforeSettleEvent,
      ctx: ExtensionContext,
    ): Promise<AgentBeforeSettleEventResult | undefined> => {
      if (ctx.mode !== "print" && ctx.mode !== "json") {
        return undefined;
      }
      if (
        event.outcome === "aborted" ||
        event.outcome === "error" ||
        ctx.signal?.aborted
      ) {
        return undefined;
      }

      const session = activeSession();
      if (!session) return undefined;
      return (await session.settle(ctx)) ? { continue: true } : undefined;
    },
  );

  pi.on("session_shutdown", async (_event, ctx) => {
    const session = currentSession;
    currentSession = undefined;
    if (session) {
      await session.shutdown(ctx);
    } else {
      clearMcpStatus(ctx);
    }
  });
}
