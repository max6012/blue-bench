# blue_bench_frontend

Browser-side stack for Blue-Bench: an MCP client and a model-tool-call loop,
both vanilla ES modules. No gateway, no bundler, no framework, no build step.
This is the frontend → tool-tier bridge in Blue-Bench's three-tier architecture.

## What's here

| File | Purpose |
|------|---------|
| `mcp_client.js`                         | MCP JSON-RPC 2.0 over SSE. Public API: `createMcpClient`, `McpClient`, `McpError`. |
| `loop.js`                               | Model ↔ tool-call loop. Public API: `runConversation`, plus re-exports from `tool_adapter.js`. |
| `tool_adapter.js`                       | Schema + stream adapters — `toOllamaTools`, `toAnthropicTools`, `parseTextEmbeddedToolCalls`, NDJSON/SSE readers. |
| `json_rpc.js`                           | Shared primitives — `Emitter`, `McpError`, `deferred`, JSON-RPC framing. |
| `package.json`                          | `"type": "module"`, test scripts. No runtime deps. |
| `tests/mcp_client.test.mjs`             | MCP client unit tests — mock EventSource + fetch, run offline. |
| `tests/loop.test.mjs`                   | Loop unit tests — mock fetch + MCP client, run offline. |
| `tests/mcp_client.integration.test.mjs` | Opt-in: spawns the real MCP server over SSE. |
| `tests/loop.integration.test.mjs`       | Opt-in: drives a short live conversation through Ollama + MCP. |

## Usage

```html
<script type="module">
  import { createMcpClient } from "./mcp_client.js";

  const client = await createMcpClient("http://127.0.0.1:8765");
  const tools  = await client.listTools();
  console.log(tools.map(t => t.name));   // ["search_alerts", "list_endpoints", ...]

  client.on("progress", (p) => console.log("progress:", p));
  const result = await client.callTool("list_endpoints", {});
  console.log(result.content);

  client.close();
</script>
```

### API

- `createMcpClient(baseUrl, options?) → Promise<McpClient>`
  - Opens the SSE stream at `<baseUrl>/sse`, waits for the `endpoint` frame,
    performs the MCP `initialize` handshake, and sends the
    `notifications/initialized` follow-up. Resolves to a ready client.
  - `options`:
    - `requestTimeoutMs` (default `30_000`)
    - `clientInfo` (default `{ name: "blue-bench-frontend", version: "0.1.0" }`)
    - `protocolVersion` (default `"2024-11-05"`)
    - `EventSource` / `fetch` — inject implementations (for Node tests).

- `client.listTools() → Promise<ToolDefinition[]>` — `tools/list`.
- `client.callTool(name, args) → Promise<ToolCallResult>` — `tools/call`.
- `client.on(event, handler)` / `client.off(event, handler)`
  - `"progress"`     — `notifications/progress` payloads from the server.
  - `"notification"` — any other server-initiated notification.
  - `"error"`        — SSE transport / malformed-frame errors.
  - `"close"`        — fired once after `close()`.
- `client.close()` — shuts the EventSource, rejects all pending requests.
- `client.serverInfo`, `client.serverCapabilities` — populated after handshake.

All errors reject with an `McpError` carrying `code` and `data` when the server
sent a JSON-RPC error.

## Running the server

From the repo root:

```bash
source .venv/bin/activate
scripts/mcp_server_sse.sh              # listens on 127.0.0.1:8765 by default
# or
python -m blue_bench_mcp.server --transport sse --host 127.0.0.1 --port 8765
```

CORS is enabled for `http(s)://localhost:*`, `http(s)://127.0.0.1:*`, and
`http(s)://[::1]:*` so a local browser frontend can connect directly.

## Tests

```bash
# Unit tests for both modules (no server, no network).
npm test
# individually:
npm run test:client    # mcp_client.js
npm run test:loop      # loop.js

# Integration tests — spawn the real SSE server; the loop integration test
# additionally requires local Ollama running a tiny model
# (set BLUE_BENCH_INTEGRATION_MODEL to override the default llama3.2:1b).
npm run test:integration
```

Tests require Node 20+ (Node 25+ for the `--experimental-eventsource` flag).
Browsers need no flags — `EventSource` is built in.

## Design notes

- **Transport.** The Blue-Bench MCP server emits one `event: endpoint` SSE
  frame carrying the POST URL (`/messages/?session_id=…`), then streams JSON-RPC
  responses and notifications as `event: message` frames. The client POSTs
  JSON-RPC requests to that endpoint and matches responses by `id`.
- **No retries.** Transport errors surface via the `error` event and unresolved
  requests stay pending until they time out or `close()` is called. Callers own
  the reconnect policy.
- **Single file.** No bundler tax. 400 lines including JSDoc.
- **Zero deps.** Uses only `EventSource`, `fetch`, `crypto.randomUUID()`.

## Tool-call loop (`loop.js`)

`loop.js` is the browser mirror of `blue_bench_client/runner.py`. Given a
profile, a composed system prompt, a user prompt, and an `McpClient`, it drives
a full model ↔ tool conversation and emits events a UI can plug straight into.

```js
import { createMcpClient } from "./mcp_client.js";
import { runConversation } from "./loop.js";

const mcp     = await createMcpClient("http://127.0.0.1:8765");
const profile = {
    model_id:       "gemma4:e4b",
    tool_protocol:  "native",              // | "text-embedded" | "anthropic-native"
    generation:     { temperature: 0.2, top_p: 1 },
    context_size:   8192,
    ollama:         { base_url: "http://127.0.0.1:11434" },
    // anthropic:   { proxy_url: "http://127.0.0.1:9000", anthropic_version: "2023-06-01" },
};

const { finalResponse, trace, events } = await runConversation({
    profile,
    systemPrompt: "...",                   // compose externally; loop takes raw string
    userPrompt:   "List endpoints and tell me how many there are.",
    mcpClient:    mcp,
    maxTurns:     10,                      // optional, default 10
});
```

### Events

Subscribe before awaiting, or pass your own emitter via `events: new Emitter()`.

| Event          | Payload |
|----------------|---------|
| `turn`         | `{ index, role, content }` — each model output |
| `tool_call`    | `{ id, name, args }` — as the model requests a tool |
| `tool_result`  | `{ id, name, result, elapsed_ms }` — after MCP returns |
| `response`     | `{ content }` — final textual answer |
| `progress`     | `{ note }` — diagnostic status (e.g. force-synthesis retry) |
| `error`        | `{ error }` — fatal issues (also thrown) |

### Protocol branches

- **`native`** — Ollama `/api/chat` with a `tools` schema, streaming NDJSON.
  The model returns structured `tool_calls`; the loop dispatches them to MCP
  and feeds the text result back as `{ role: "tool" }` messages.
- **`text-embedded`** — Ollama `/api/chat` without a tool schema. The model
  emits ```` ```tool_call {...} ``` ```` fenced JSON (fallbacks: legacy
  `<tool>/<args>` tags, bare JSON). Results are fed back as synthetic
  `<tool_result name="...">...</tool_result>` user messages.
- **`anthropic-native`** — POSTs to `${profile.anthropic.proxy_url}/v1/messages`
  (proxy injects the API key server-side). SSE stream parsed for
  `content_block_start` / `input_json_delta` / `content_block_stop`;
  `tool_use` blocks are dispatched and echoed back as `tool_result` blocks.

### Behavior parity with `runner.py`

- Same turn ordering, same max-turns salvage of the last non-empty assistant
  message.
- **Force-synthesis retry** on the native branch: if the final turn has no
  content and no more tool calls, the loop sends a terse synthesis nudge and
  retries once (identical to `_force_final_synthesis_native`). If the retry
  is also empty, the loop salvages the last non-empty assistant content.
- Text-embedded parsers: fenced → legacy tags → bare JSON, same precedence.

## Scope

The loop is a library; no UI. A UI that drives it lives in a sibling task
(`t-b9nx`).
