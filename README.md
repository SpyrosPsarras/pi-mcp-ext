# @jangmanj/pi-mcp-ext

Stateless MCP `2026-07-28` capabilities for Pi, running alongside `builtin:mcp`.

## What It Adds Next to `builtin:mcp`

Pi's `builtin:mcp` extension speaks MCP `2025-11-25` and owns `/mcp`, synchronous `mcp__<server>__<tool>` tools on `2025-11-25` servers, `list_mcp_resources` / `read_mcp_resource`, and interactive `mcp-auth.json` sign-in. `@jangmanj/pi-mcp-ext` loads in the same Pi session without replacing `builtin:mcp` and adds the full `2026-07-28` surface on configured `stdio` and Streamable HTTP servers:

- **Stateless discovery and unified `subscriptions/listen` multiplexer**: probes enabled servers with `server/discover` (closing dormant probes cleanly on legacy `2025-11-25` servers) and shares at most one `subscriptions/listen` stream per server across events, tasks, tools, prompts, and resource watches.
- **Pure `2026-07-28` tools fallback**: when a strict `2026-07-28` server drops `initialize` so `builtin:mcp` cannot register its `mcp__<server>__*` tools, automatically registers them with full `exposure` / `toolExposure` parity and live `toolsListChanged` updates—standing down completely on dual-stack servers where `builtin:mcp` succeeded.
- **Prompts & Argument Completion (`mcp_prompts`, `/mcp-prompt`, `/mcp-prompt:<server>:<prompt>`)**: discovers server prompts via `prompts/list`, refreshes on `promptsListChanged`, autocompletes prompt and resource-template arguments via `completion/complete`, and sends resolved prompt messages.
- **Resources & Live Resource Subscriptions (`mcp_resources`)**: lists resources/templates, reads text/image/binary resources (`resources/read`), browses directories (`resources/directory/read`), and watches `resourceSubscriptions` / `resourcesListChanged` on `subscriptions/listen` with `mcp-resource` turn wakes.
- **Events (`io.modelcontextprotocol/events`, `mcp_events`)**: discovers event types via `events/list`, catches up with `events/poll`, streams live occurrences via `events/stream`, persists replay cursors in the session branch, deduplicates deliveries, and wakes Pi turns with `mcp-event` messages (`poll` and `push` delivery; `webhook`-only event types are skipped since a local CLI session has no inbound webhook endpoint).
- **Tasks (`io.modelcontextprotocol/tasks`, `mcp_tasks`) + Interactive Elicitation (`form` & `url`)**: invokes task-augmented tools, tracks `working` and `input_required` tasks across `subscriptions/listen` and fallback `tasks/get` polling, fulfills interactive `elicitation/create` requests directly via `ctx.ui` (flat primitive forms with review/modify + safe domain-verified external URL consent, showing the URL to open by hand when the opener command cannot start) before calling `tasks/update`, cancels via `tasks/cancel`, and wakes Pi turns with `mcp-task` messages.
- **Skills over MCP (`io.modelcontextprotocol/skills`, `mcp_skills`, `/mcp-skill:<server>:<skill>`)**: lists each server's skills in the system prompt before every run, discovers skill manifests without eager file fetches, enforces fail-closed manifest-bound user approval, verifies exact byte sizes + `sha256:` digests + YAML 1.2 frontmatter + parent directory names, confines supporting-file reads to the skill root, and excludes cached files from filesystem skill discovery to preserve MCP origin.
- **OAuth 2.0 Client Credentials (`io.modelcontextprotocol/oauth-client-credentials`)**: unattended machine-to-machine `client_secret` and RFC 7523 / RFC 10070 `private_key_jwt` (`RS*`, `ES*`, `EdDSA`) authentication with RFC 9728 / RFC 8414 discovery, strict issuer pinning, and in-memory token refresh.
- **OpenTelemetry Trace Context (`_meta`)**: propagates valid W3C `traceparent`, `tracestate`, and `baggage` fields into outbound `_meta`.
- **Task-capability hint, headless settle hold, and read-only config**: hints equivalent `mcp_tasks` calls on `-32021`, holds `-p` / `--mode json` open while tasks or `holdSettle` subscriptions/watches are active, and never writes or locks `mcp.json` or `mcp-auth.json`.

## Install

```sh
pi install npm:@jangmanj/pi-mcp-ext
```

## Tools

All five tools register directly (and are callable from `codemode` scripts as `tools.mcp_events(...)`, `tools.mcp_tasks(...)`, `tools.mcp_resources(...)`, `tools.mcp_prompts(...)`, and `tools.mcp_skills(...)`).

### `mcp_events`

Manage MCP `2026-07-28` event discovery, subscriptions, and polling.

- `action`: `"servers" | "list" | "subscribe" | "unsubscribe" | "subscriptions" | "poll"`
- `server?: string` — MCP server name (required for `list`, `subscribe`, `unsubscribe`, `poll`).
- `name?: string` — event type name (required for `subscribe`, `unsubscribe`, `poll`).
- `arguments?: Record<string, unknown>` — event filter or subscription arguments validated against the event's `inputSchema`.
- `delivery?: "auto" | "push" | "poll"` — delivery preference (default `"auto"`, preferring push with poll catch-up).
- `cursor?: string | null` — explicit starting cursor (`null` starts from now; omit to resume from the persisted session cursor).
- `maxAgeMs?: number` — optional replay age limit in integer milliseconds.
- `maxEvents?: number` — optional batch size limit for `action: "poll"`.
- `holdSettle?: boolean` — keep headless (`-p` / `--mode json`) runs open until an event arrives or `unsubscribe` is called.
- `logLevel?: "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency"` — per-request `SEP-2575` `io.modelcontextprotocol/logLevel` for `list` and `poll`; request-scoped `notifications/message` frames are appended to the tool result.

### `mcp_tasks`

Invoke and manage MCP `2026-07-28` task-augmented tool calls.

- `action`: `"call" | "get" | "update" | "cancel" | "active"`
- `server?: string` — MCP server name (required for `call`, `get`, `update`, `cancel`; optional filter for `active`).
- `tool?: string` — tool name on `server` for `action: "call"`. Returns the completed tool result immediately if the server finishes synchronously, or tracks the created task if the server returns `resultType: "task"`.
- `arguments?: Record<string, unknown>` — tool arguments for `action: "call"`.
- `taskId?: string` — task identifier for `get`, `update`, and `cancel`.
- `inputResponses?: Record<string, unknown>` — responses keyed by `inputRequests` id for `action: "update"`.
- `logLevel?: "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency"` — per-request `SEP-2575` `io.modelcontextprotocol/logLevel` for `call`, `get`, `update`, and `cancel`; request-scoped `notifications/message` frames are appended to the tool result.

`action: "active"` reads the client's session task ledger directly without issuing a server RPC.

### `mcp_resources`

Read, browse, and subscribe to live updates on `2026-07-28` server resources.

- `action`: `"list" | "templates" | "read" | "directory" | "subscribe" | "unsubscribe" | "subscriptions"`
- `server?: string` — MCP server name (required except for `subscriptions`).
- `uri?: string` — resource or directory URI (required for `read`, `directory`, `subscribe`, `unsubscribe`).
- `cursor?: string` — pagination cursor for `list`, `templates`, or `directory`.
- `holdSettle?: boolean` — keep headless (`-p` / `--mode json`) runs open while watching `uri`.
- `logLevel?` — per-request `SEP-2575` log level.

### `mcp_prompts` & `/mcp-prompt`

Discover prompts, render prompt messages, or autocomplete prompt/resource arguments (`completion/complete`).

- `action`: `"list" | "get" | "complete"`
- `server: string` — MCP server name.
- `name?: string` — prompt name (for `get` or `complete` with `refType: "prompt"`).
- `uri?: string` — resource URI or template (for `complete` with `refType: "resource"`).
- `arguments?: Record<string, string>` — prompt arguments for `get`, or resolved `context.arguments` for `complete`.
- `argumentName?: string`, `argumentValue?: string` — active argument for `complete`.
- Interactive slash commands: `/mcp-prompt` (interactive picker or `/mcp-prompt <server>/<prompt> key=value`) and dynamic per-prompt `/mcp-prompt:<server>:<prompt>` with live `completion/complete` argument suggestions.

### `mcp_skills`

Discover, verify, approve, and load Agent Skills over MCP (`io.modelcontextprotocol/skills`).

- `action`: `"list" | "get" | "load" | "read_file" | "directory"`
- `server: string` — MCP server name.
- `uri?: string` — skill `SKILL.md` URI (for `get`, `load`, `read_file`) or directory URI (for `directory`).
- `path?: string` — relative path or URI within the retained skill manifest (for `read_file`).
- `cursor?: string` — pagination cursor for `directory`.

`load` asks for approval the first time a skill version loads in a session, and on every load of a dynamic skill. When approval is needed and Pi has no UI, the load fails. To trust a server's skills, list its name in `PI_MCP_EXT_SKILL_AUTO_APPROVE` (comma-separated). Its skills, dynamic ones included, then load without the prompt, also headless. The 16 MiB limit and the frontmatter check still apply to every load, and skills with a file manifest still get their size and SHA-256 checks. A server that answers with a different skill URI than the one requested is refused. These loads are not recorded as session approvals, so removing a name brings the prompt back.

The extension lists each connected server's skills when it connects and again before a run once the listing is older than its `ttlMs`, waiting at most 2 seconds and keeping the last listing on failure. Before every run it adds an `mcp_skills` section to the system prompt with each skill's server, name, URI and description (up to 100 skills per server, descriptions cut at 1024 characters), so the model can load a matching skill on its own. Skills with `disable-model-invocation: true` stay out of that section. Typing `/mcp-skill:<server>:<skill> [request]` loads the skill without the approval prompt, with the same size, digest and frontmatter checks, and sends it with your request.

## OAuth 2.0 Client Credentials (`clientCredentials`)

Global `mcp.json` or session-registered HTTP servers (over `https:` or loopback) may configure unattended `io.modelcontextprotocol/oauth-client-credentials` using either `clientSecret` or RFC 7523 / RFC 10070 `privateKey` (`RS256`/`384`/`512`, `ES256`/`384`/`512`, `EdDSA`) with a required pinned `issuer`:

```json
{
  "mcpServers": {
    "ci-remote": {
      "url": "https://mcp.example.com/mcp",
      "clientCredentials": {
        "clientId": "ci-worker",
        "privateKey": "${CI_MCP_PRIVATE_KEY_PEM}",
        "algorithm": "ES256",
        "issuer": "https://auth.example.com"
      }
    }
  }
}
```

## Declarative Subscriptions (`subscribe`)

Any server entry in global `mcp.json`, a trusted project `.pi/mcp.json` (full server definition), or `pi.registerMcpServer()` may include an optional `subscribe` array. `builtin:mcp` ignores unknown fields, while `@jangmanj/pi-mcp-ext` activates the declared subscriptions automatically on `session_start` once `server/discover` confirms `io.modelcontextprotocol/events`:

```json
{
  "mcpServers": {
    "alerts": {
      "url": "https://alerts.example.com/mcp",
      "subscribe": ["*"]
    },
    "ci": {
      "command": "ci-mcp",
      "subscribe": [
        "build.failed",
        {
          "name": "deploy.finished",
          "arguments": { "env": "prod" },
          "delivery": "push",
          "maxAgeMs": 600000,
          "holdSettle": false
        }
      ]
    }
  }
}
```

- Each item is `"*"` (all push- or poll-capable events in `events/list`), an event name string, or `{ name, arguments?, delivery?, maxAgeMs?, holdSettle? }`.
- Defaults are `delivery: "auto"` and `holdSettle: false`, so declarative subscriptions do not hold headless runs open unless `holdSettle: true` is set.
- Subscriptions resume from the latest persisted session cursor when present, or start from `cursor: null` so restarts do not replay previously delivered events.
- Invalid `subscribe` values log a warning without blocking the server entry; legacy servers or servers without `io.modelcontextprotocol/events` ignore `subscribe`.
- Removing an entry from `subscribe` does not cancel an already-persisted subscription; call `mcp_events` with `action: "unsubscribe"` to stop it.

## Development

```sh
npm run typecheck   # Type-check src/ and tests/ with tsc --noEmit
npm test            # Run the node:test suite
npm run check       # Run typecheck and tests
npm run smoke:pack  # Pack tarball, install in a scratch directory, and load in Pi
```
