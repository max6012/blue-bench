# Blue-Bench Architecture

Blue-Bench is an MCP server for Blue Team tools plus a validation harness for
the models that drive it. This document describes how the pieces fit together
— three orthogonal design primitives (tools, models, prompts), many clients
talking to one server over two transports, and three deployment tiers that
scale independently.

Target audience: a new contributor who wants to add a tool, add a model, or
deploy the stack. Skim time ~10 minutes.

## 1. Overview

The architecture has one goal: keep every practical concern separately
editable. Adding a tool should not require touching a model adapter. Adding a
model should not require rewriting any prompt. Tuning a prompt for a weaker
local model should not change the tool surface or the server code. In
Blue-Bench, each of those is a different file in a different directory.

Four design decisions make this work:

- **Tools live behind MCP.** The server ([`blue_bench_mcp/`](../blue_bench_mcp))
  speaks the [Model Context Protocol](https://modelcontextprotocol.io/) over
  two transports (stdio and SSE). Any compliant MCP client sees the same tool
  surface. The server does not know or care which model is on the other end.
- **Models are YAML profiles.** A profile
  ([`blue_bench_mcp/profiles/*.yaml`](../blue_bench_mcp/profiles)) declares
  tool-call protocol, context window, generation params, and which prompt
  parts to compose. Swapping models is a file swap, not a code change.
- **Prompts compose from markdown parts.** Role, site, guidelines, and
  coaching live as separate markdown files under
  [`blue_bench_mcp/prompts/`](../blue_bench_mcp/prompts) and are assembled
  per-request by [`prompts_compose.py`](../blue_bench_mcp/prompts_compose.py).
  Nothing is hardcoded; nothing is model-specific except the coaching file.
- **The browser is a real MCP client.** The frontend
  ([`blue_bench_frontend/`](../blue_bench_frontend)) speaks MCP JSON-RPC 2.0
  over SSE directly, runs the same tool-call loop a Python client would, and
  reaches the Anthropic API through a minimal key-holding proxy. No gateway.
  No framework. No server-side rendering.

Everything else is a consequence.

## 2. Three design primitives

### 2.1 Tools

**What.** Blue Team capabilities — Elasticsearch search, Wazuh alerts,
OpenEDR endpoint detection, Sigma rule validation, nmap scans, forensic
evidence listing/hashing/metadata.

**Where.**

- [`blue_bench_mcp/tool_classes/`](../blue_bench_mcp/tool_classes) — one
  class per backend. Config is injected via the typed `ServerConfig`
  ([`config.py`](../blue_bench_mcp/config.py)). Each method is an `async`
  function that returns a `str`. Errors are first-class `str` outputs
  starting with `"Error: "`, not exceptions.
- [`blue_bench_mcp/tools/`](../blue_bench_mcp/tools) — thin registration
  shims. Each module exposes a `register(server, cfg)` function that wires
  its class's methods with `@server.tool()`. The server auto-imports every
  module in this package at startup (see `register_all` in
  [`server.py`](../blue_bench_mcp/server.py)).
- [`blue_bench_mcp/guardrails.py`](../blue_bench_mcp/guardrails.py) — shared
  safety primitives: `truncate_results`, `validate_path_under`,
  `validate_target_in_range`. Every tool applies these consistently.

**How to add one.** Write a class under `tool_classes/`, write a thin
`register()` under `tools/`, restart the server. That is the whole contract;
see §7.1.

**What is intentionally NOT here.** No retry logic, no request caching, no
long-running jobs, no authentication layer. Tools are stateless RPCs with
deterministic timeouts; anything stateful lives in the backend data store
(Elasticsearch, Wazuh) or in the caller.

### 2.2 Models

**What.** Each supported model is a YAML profile. The profile is the adapter
between a specific model (and its tool-call protocol) and the rest of the
system.

**Where.**

- [`blue_bench_mcp/profiles/*.yaml`](../blue_bench_mcp/profiles) — one file
  per model (`gemma4-e4b.yaml`, `gemma3-tools-12b.yaml`,
  `claude-opus-4-7.yaml`, `claude-sonnet-4-6.yaml`, …).
- [`blue_bench_mcp/profiles/schema.py`](../blue_bench_mcp/profiles/schema.py)
  — Pydantic schema. Fields:
  - `model_id` — passed verbatim to the runtime (Ollama model tag, Anthropic
    model name).
  - `tool_protocol` — one of `native`, `text-embedded`, `anthropic-native`.
  - `prompt_style` — advisory hint for the composer.
  - `context_size` — maps to `num_ctx` for Ollama, informational for
    Anthropic.
  - `generation` — `temperature`, `top_p`, optional `top_k`.
  - `coaching_hints` — free-form bullets that may be interpolated into the
    coaching prompt part (currently reference material; the coaching file
    itself is authoritative).
  - `recommended_workflows` — optional BLUF-only metadata.
  - `prompt_parts` — `{section: filename}` mapping that tells the composer
    which markdown files to use for `role`, `site`, `guidelines`, `coaching`.

**How to add one.** Write a profile YAML; optionally write a matching
`prompts/coaching/<model>.md`. That's it. See §7.2.

**What is intentionally NOT here.** No Python per model. No subclasses. No
model registry. The only place code branches on model is in the tool-call
loop, where `tool_protocol` selects one of three protocol branches (§5).
Adding a fourth protocol is the only case where code changes are required.

### 2.3 Prompts

**What.** System prompts are composed, not written. Four sections, in order:
`role` (who the model is), `site` (the specific deployment's indices,
hostnames, conventions), `guidelines` (how to investigate, what to produce),
`coaching` (per-model behavioral hints).

**Where.**

- [`blue_bench_mcp/prompts/role/`](../blue_bench_mcp/prompts/role) — e.g.
  `blue_team_analyst.md`. Typically site- and model-agnostic.
- [`blue_bench_mcp/prompts/site/`](../blue_bench_mcp/prompts/site) — e.g.
  `default.md`. Per-deployment overlay: index names, host ranges, SOC IRP
  conventions. The one file every operator customizes.
- [`blue_bench_mcp/prompts/guidelines/`](../blue_bench_mcp/prompts/guidelines)
  — e.g. `investigation_protocol.md`, `terse.md`, `tool_first.md`. Pick the
  one that matches the workflow style you want.
- [`blue_bench_mcp/prompts/coaching/`](../blue_bench_mcp/prompts/coaching)
  — e.g. `gemma4.md`, `gemma3-tools.md`, `claude.md`. Compensates for
  known weaknesses of a specific model (or a class of models).
- [`blue_bench_mcp/prompts_compose.py`](../blue_bench_mcp/prompts_compose.py)
  — `compose(profile, context)` reads the four parts in order, strips HTML
  comments, substitutes `{placeholder}` values from the context dict,
  concatenates with blank lines, and returns the final system prompt.
  Missing placeholders raise `ValueError` rather than silently leaving
  braces in the output.

**How to add one.** Write a markdown file under the relevant section; point
a profile at it via `prompt_parts`. See §7.4.

**What is intentionally NOT here.** No Jinja, no YAML frontmatter, no
templating DSL. Just `{placeholder}` substitution and markdown. HTML
comments (`<!-- … -->`) are stripped before substitution so you can leave
source-only notes in the file without them leaking to the model.

## 3. Clients — many clients, one server

The MCP server serves every client type through the same tool surface. The
only differences are transport and where the tool-call loop runs.

| Client                                | Path                                                       | Transport | Loop location           |
|---------------------------------------|------------------------------------------------------------|-----------|-------------------------|
| Reference MCP client + Ollama runner  | [`blue_bench_client/`](../blue_bench_client)               | stdio     | `runner.py` (Python)    |
| Operator CLI (`blue-bench …`)         | [`blue_bench_cli/`](../blue_bench_cli)                     | stdio     | Delegates to `runner.py` |
| Evaluation harness (`qualify`)        | [`blue_bench_eval/`](../blue_bench_eval)                   | stdio     | Delegates to `runner.py` |
| Browser UI / custom web app           | [`blue_bench_frontend/`](../blue_bench_frontend)           | SSE       | `loop.js` (JavaScript)  |
| Third-party MCP clients               | Claude Code, Claude Desktop, Cline, Continue, IDE plugins  | stdio     | Client's own            |

**Reference client + runner** ([`blue_bench_client/runner.py`](../blue_bench_client/runner.py))
launches the MCP server as a subprocess, loads a profile, composes the
system prompt, calls Ollama or Anthropic, parses whichever tool-call
protocol the profile declared, dispatches each call back through the MCP
client, and captures a structured `Trace` ([`trace.py`](../blue_bench_client/trace.py))
that downstream aggregation can consume.

**Operator CLI** ([`blue_bench_cli/main.py`](../blue_bench_cli/main.py)) is a
thin `typer` wrapper: `blue-bench qualify --profile X` runs the eval corpus
via the runner; `blue-bench aggregate` and `blue-bench diff` work on the
resulting run directory; `blue-bench server` is a shortcut for
`python -m blue_bench_mcp.server`.

**Eval harness** ([`blue_bench_eval/qualify.py`](../blue_bench_eval/qualify.py))
iterates a corpus of YAML prompt specs, runs each through the same runner,
and writes one `Trace` JSON per prompt to `results/<run>/prompts/`. Judging
is a separate step (human or LLM-assisted).

**Browser UI** ([`blue_bench_frontend/`](../blue_bench_frontend)) is the big
new thing. `mcp_client.js` speaks MCP JSON-RPC 2.0 over SSE directly to the
server; `loop.js` is a line-for-line port of the Python runner's tool-call
loop, with the same three protocol branches and the same turn ordering.
`tool_adapter.js` handles schema translation and Ollama/Anthropic stream
parsing. Zero npm dependencies; one file per concern; served as static
assets.

**Third-party MCP clients** use stdio and their own loops. Launch
`python -m blue_bench_mcp.server` (or point them at `scripts/mcp_server.sh`)
and they see the full tool surface. Nothing in the server is
client-specific.

## 4. Three-tier deployment (production architecture)

Blue-Bench deploys as three independent tiers. Each tier is a self-contained
compose file in [`docker/`](../docker). Tiers are stateless at the service
level (state lives in named Docker volumes for ES and Wazuh) and share no
compose network, so each scales horizontally without coordination.

### 4.1 Tier 1 — Tool tier

**File:** [`docker/compose.tools.yml`](../docker/compose.tools.yml)
**Host profile:** CPU, 8+ GB RAM (Elasticsearch dominates).
**Services:**

- `mcp` — the Blue-Bench MCP server running in SSE mode on `:8765`, built
  from [`docker/Dockerfile.mcp`](../docker/Dockerfile.mcp). Non-root user,
  nmap and curl installed, no secrets baked in.
- `elasticsearch` `:9200`, `wazuh` `:55000`, `openedr` `:9443` — backend
  data stores. The MCP container reaches them via service DNS on
  `blue-bench-net`.
- `target` — a minimal Linux container aliased as `10.10.5.22` on
  `blue-bench-net`, the default nmap scan target.
- `scanner` — a long-lived `instrumentisto/nmap` sidecar. Used only when
  `NmapTool.scanner_container` is set (host-mode deployments); the MCP
  container has its own nmap binary and skips the sidecar dispatch path.
- `seed` — one-shot Elasticsearch seeder (profile: `seed`).

### 4.2 Tier 2 — LLM tier

**File:** [`docker/compose.llm.yml`](../docker/compose.llm.yml)
**Host profile:** GPU for Ollama (NVIDIA container toolkit required for
passthrough). For dev / MVP, Ollama runs on the host and only the proxy
container is started here.
**Services:**

- `anthropic-proxy` `:8766` — thin FastAPI forwarder to
  `api.anthropic.com/v1/messages`, built from
  [`docker/Dockerfile.proxy`](../docker/Dockerfile.proxy). Holds
  `ANTHROPIC_API_KEY` server-side so the browser never sees it. Fails fast
  at startup if the key is unset. Strips client-supplied `x-api-key` and
  `Authorization` headers before forwarding. Preserves SSE streaming.
- `ollama` `:11434` — Ollama runtime. Model cache persisted at
  `./data/ollama`. GPU passthrough is a commented `deploy.resources`
  template; uncomment for range / production on an NVIDIA host.

### 4.3 Tier 3 — Frontend tier

**File:** [`docker/compose.frontend.yml`](../docker/compose.frontend.yml)
**Host profile:** any static host or CDN.
**Services:**

- `frontend` `:5173 → 80` — plain `nginx:alpine` serving
  [`blue_bench_frontend/`](../blue_bench_frontend) as static files.
  Read-only bind mount. No build step, no bundler, no framework.

### 4.4 Dev convenience — `compose.all.yml`

**File:** [`docker/compose.all.yml`](../docker/compose.all.yml). Uses
Docker Compose's `include:` directive (requires v2.20+) to bring all three
tiers up on a single host for development. Each tier keeps its own
networks and volumes — `include:` does not merge them. Production
deployments should use the three tier files directly.

### 4.5 Topology

```
+--------------------------------------------------------------+
|  Browser (http://<frontend>:5173)                            |
|  +--------------------------------------------------------+  |
|  |  blue_bench_frontend/                                  |  |
|  |    mcp_client.js  --(SSE + JSON-RPC, CORS)-----+       |  |
|  |    loop.js        --(HTTP, Ollama/Anthropic)---|---+   |  |
|  |    tool_adapter.js, json_rpc.js                |   |   |  |
|  +------------------------------------------------|---|---+  |
+-------------------------------------------------- | - | ----+
                                                    |   |
                  +---------------------------------+   +----------+
                  |                                                 |
                  v                                                 v
+-------------------------------------+     +---------------------------------+
|   Tier 1 - Tool tier  (CPU host)    |     |   Tier 2 - LLM tier  (GPU host) |
|                                     |     |                                 |
|   mcp            :8765  [SSE]       |     |   ollama          :11434        |
|     |                               |     |   anthropic-proxy :8766         |
|     +-- elasticsearch :9200         |     |     |                           |
|     +-- wazuh         :55000        |     |     +--> api.anthropic.com      |
|     +-- openedr       :9443         |     |          (holds API key)        |
|     +-- target        10.10.5.22    |     |                                 |
|     +-- scanner (nmap sidecar)      |     +---------------------------------+
|                                     |
|   compose.tools.yml                 |     compose.llm.yml
+-------------------------------------+

         +------------------------------------+
         |   Tier 3 - Frontend tier (static)  |
         |   nginx :5173 -> blue_bench_frontend/
         |   compose.frontend.yml             |
         +------------------------------------+

  Third-party MCP clients (Claude Code, Cline, Continue, IDE extensions)
  connect to Tier 1 via stdio, bypassing the browser tier entirely:

      $ python -m blue_bench_mcp.server               # stdio, same tool surface
```

Key properties the diagram encodes:

- **Stateless per tier.** The MCP server holds no conversation state; each
  SSE session is independent. The proxy holds no state. The frontend is
  static. Durable state lives in Elasticsearch + Wazuh named volumes and
  in `data/evidence/`.
- **Independent scaling.** Tier 1 scales horizontally behind a load
  balancer (any number of `mcp` containers all point at the same ES).
  Tier 2 scales by adding GPU nodes. Tier 3 is a CDN problem.
- **Independent swap-out.** Replace Ollama with another inference runtime
  — nothing in Tier 1 or Tier 3 changes. Replace the browser UI with a
  custom app — nothing in Tier 1 or Tier 2 changes. Replace the tool
  backends — nothing in Tier 2 or Tier 3 changes.
- **No shared compose network between tiers.** Cross-tier traffic goes
  over exposed ports on the host network. This is deliberate: it forces
  the same reachability contract in production as in dev.

## 5. Client transports

The MCP server speaks two transports from the same process and registers
the same tools on both. Choose by `--transport`:

### 5.1 stdio (default)

For server-side clients: Claude Code, Claude Desktop, Cline, Continue, the
reference runner, the CLI, the eval harness. The client spawns the server
as a child process and speaks MCP over stdin/stdout. Lowest latency, no
network stack, one-client-per-process.

```bash
python -m blue_bench_mcp.server
# or: scripts/mcp_server.sh
```

### 5.2 SSE (HTTP + Server-Sent Events)

For browser and network clients.

```bash
python -m blue_bench_mcp.server --transport sse --host 127.0.0.1 --port 8765
# or: scripts/mcp_server_sse.sh
```

- **Endpoint pattern.** `GET /sse` opens an EventSource. The server emits
  one `event: endpoint` frame carrying a session-specific URL
  (`/messages/?session_id=…`). The client `POST`s JSON-RPC requests to
  that URL and correlates responses by `id` on the same SSE stream.
- **Multi-client.** Every SSE connection gets its own session. The browser
  and a custom Node client can connect concurrently; the server fans out
  notifications per session.
- **CORS.** Allowlist resolves in priority order: explicit `origins=`
  argument → `BLUE_BENCH_CORS_ORIGINS` env var → `config.yaml`
  `transport.sse.origins` → default `["http://localhost:*",
  "http://127.0.0.1:*"]`. See
  [`transport_sse.py`](../blue_bench_mcp/transport_sse.py). A single `"*"`
  entry disables origin checking (dev only).
- **Health.** `GET /health` returns `{"ok": true, "service":
  "blue-bench-mcp"}`. Used by the compose healthcheck.

### 5.3 Browser → model path

The browser talks to two model endpoints directly, by design:

- **Ollama (direct).** `fetch('http://<ollama>:11434/api/chat', …)`. The
  browser enforces CORS, so operators must set `OLLAMA_ORIGINS` to include
  the frontend origin (Ollama reads this at startup only). See the
  `README.md` section "Browser frontend setup — enabling Ollama CORS" and
  `scripts/ollama_cors_enable.sh` for per-OS commands.
- **Anthropic (via proxy).** `fetch('http://<proxy>:8766/v1/messages', …)`.
  The proxy injects `x-api-key` server-side; the browser never handles the
  secret. This is the only reason the proxy exists — no model selection,
  no caching, no retries.

The browser never talks to Tier 1 by any path other than MCP over SSE, and
never talks to Tier 2 by any path other than these two HTTP endpoints.

## 6. Validation methodology

Brief version — full detail in [`blue_bench_eval/`](../blue_bench_eval)
and `README.md`.

- **Frontier reference runs** (Claude Sonnet / Opus via the Anthropic API,
  through the proxy when browser-driven or directly via SDK from Python)
  establish the configuration ceiling. If a frontier model does not score
  100% on the fixed corpus, the wiring is broken — not the model. This
  catches infrastructure bugs, fixture gaps, hallucinated schemas, and
  missing coaching before they get attributed to local-model capability.
- **Local runs** (Ollama-hosted open-weight models) are measured as a
  percentage of that ceiling. Coaching and prompts get tuned against a
  stable reference instead of a moving target.
- Every tool-surface change should re-trigger the frontier run to
  re-establish the ceiling before local tuning resumes.

Runs produce traces in `results/<timestamp>-<profile>/prompts/*.json`.
Judging produces `scored/*.json`. `blue-bench aggregate` renders a BLUF.

## 7. Adding things

### 7.1 Adding a tool

1. Write the implementation under
   [`blue_bench_mcp/tool_classes/<tool>.py`](../blue_bench_mcp/tool_classes):
   one class, N async methods, config from `ServerConfig`, guardrails from
   [`guardrails.py`](../blue_bench_mcp/guardrails.py). Return `str`.
   Errors are `str` starting with `"Error: "`.
2. Write the registration shim under
   [`blue_bench_mcp/tools/<tool>.py`](../blue_bench_mcp/tools): a
   `register(server, cfg)` function that instantiates your class and wires
   each method with `@server.tool()`. Docstrings on the registered
   functions become the tool descriptions visible to the model.
3. Restart the server. Auto-discovery picks up the new module.

**Minimal example.**

```python
# blue_bench_mcp/tool_classes/evidence.py
class EvidenceTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.evidence_dir = Path(cfg.evidence.evidence_dir).resolve()
        self.max_chars = cfg.limits.max_result_chars

    async def list_evidence(self) -> str: ...
    async def file_hash(self, filename: str, algorithm: str = "sha256") -> str: ...
```

```python
# blue_bench_mcp/tools/evidence.py
def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = EvidenceTool(cfg)

    @server.tool()
    async def list_evidence() -> str:
        """List available evidence files."""
        return await tool.list_evidence()

    @server.tool()
    async def file_hash(filename: str, algorithm: str = "sha256") -> str:
        """Compute a hash of an evidence file."""
        return await tool.file_hash(filename=filename, algorithm=algorithm)
```

### 7.2 Adding a model (profile)

1. Write
   [`blue_bench_mcp/profiles/<name>.yaml`](../blue_bench_mcp/profiles)
   declaring `model_id`, `tool_protocol`, `context_size`, `generation`,
   `prompt_parts`. Example:

   ```yaml
   name: my-model
   model_id: my-model:latest
   tool_protocol: native          # or text-embedded / anthropic-native
   prompt_style: terse
   context_size: 32768
   generation:
     temperature: 0.2
     top_p: 0.9
   prompt_parts:
     role: blue_team_analyst.md
     site: default.md
     guidelines: investigation_protocol.md
     coaching: my-model.md        # optional
   ```

2. If the model needs bespoke coaching, write
   `prompts/coaching/<my-model>.md`.
3. Run `blue-bench qualify --profile <name>`. No code changes.

**Adding a new `tool_protocol`** (as opposed to a new model on an existing
protocol) does require a code change: add a branch to `runner.py` and the
mirror branch in `loop.js`. There are currently three.

### 7.3 Adding a client

Two cases:

- **Third-party MCP client.** Point it at `python -m
  blue_bench_mcp.server` (stdio) or `http://<host>:8765/sse` (SSE).
  Nothing to add on the Blue-Bench side.
- **Custom application.** If browser-side, import `mcp_client.js` and
  `loop.js` from
  [`blue_bench_frontend/`](../blue_bench_frontend) — they are ES modules
  with zero dependencies. If server-side, use
  [`blue_bench_client/mcp_client.py`](../blue_bench_client/mcp_client.py)
  (stdio) or any MCP SDK that speaks SSE. Either way, reuse the existing
  runner / loop — do not rewrite the tool-call dispatch.

### 7.4 Adding coaching or a site overlay

- **Coaching.** Create
  `prompts/coaching/<your-model>.md`. Point a profile at it via
  `prompt_parts.coaching`. Coaching is per-model behavioral hints — "when
  the user asks for X, prefer Y," "avoid listing raw IDs," "always call
  `count_by_field` before `search_alerts`." Keep it short.
- **Site overlay.** Edit or add
  `prompts/site/<site>.md` with your indices, hostnames, subnet ranges,
  IRP conventions. Point all profiles for that deployment at it via
  `prompt_parts.site`. The site file is the one place deployment-specific
  language lives.

## 8. Repo layout

```
blue_bench_mcp/           MCP server: tools, profiles, composable prompts, SSE transport
  tool_classes/             One class per backend (elastic, wazuh, openedr, sigma, nmap, evidence)
  tools/                    Thin @server.tool() registration shims
  profiles/                 Per-model YAML + schema.py (Pydantic)
  prompts/{role,site,guidelines,coaching}/   Markdown parts
  config.py                 Typed ServerConfig; ${VAR:-default} env substitution
  guardrails.py             truncate_results, validate_path_under, validate_target_in_range
  prompts_compose.py        Pure-function composer (placeholder substitution)
  server.py                 FastMCP entry: stdio | sse
  transport_sse.py          Starlette wrapper: CORS + /health
  anthropic_proxy.py        FastAPI forwarder to api.anthropic.com (Tier 2)

blue_bench_client/        Reference Python MCP client + Ollama runner + Trace
  mcp_client.py             Stdio MCP client (JSON-RPC framing)
  runner.py                 Three-protocol tool-call loop, emits Trace
  trace.py                  Trace / Turn / ToolCall dataclasses

blue_bench_cli/           Operator CLI (typer): qualify | aggregate | diff | server

blue_bench_eval/          Validation harness
  prompts/                  YAML prompt corpus
  rubrics/                  Scoring rubric(s)
  qualify.py                Runs the corpus under a profile -> traces
  aggregate.py              Scored traces -> BLUF.md

blue_bench_frontend/      Browser-side stack (Tier 3 content; zero npm deps)
  mcp_client.js             MCP over SSE + JSON-RPC 2.0
  loop.js                   Browser mirror of runner.py (three protocols)
  tool_adapter.js           Ollama/Anthropic schema + stream parsing
  json_rpc.js               Emitter, McpError, request framing
  tests/                    Unit + integration tests (Node 20+)

docker/                   Three-tier compose + Dockerfiles + mock backends
  compose.tools.yml         Tier 1 (CPU): mcp + ES + Wazuh + OpenEDR + target + scanner
  compose.llm.yml           Tier 2 (GPU): ollama + anthropic-proxy
  compose.frontend.yml      Tier 3 (static): nginx -> blue_bench_frontend/
  compose.all.yml           Dev aggregator (uses `include:` directive)
  Dockerfile.mcp            MCP server image (non-root, nmap, SSE)
  Dockerfile.proxy          Anthropic proxy image (minimal, non-root)
  Dockerfile.openedr        OpenEDR FastAPI mock
  Dockerfile.seed           One-shot ES seeder
  Dockerfile.target         nmap scan target (10.10.5.22)
  mock_backends.py          OpenEDR mock app
  seed_elasticsearch.py     Sample telemetry seeder

scripts/                  Operator helpers (mcp_server.sh, seed, ollama_cors_enable, ...)
tests/                    Python unit + integration tests (pytest)
docs/                     Public architecture + guides (this file, TOOL_CLASS_PATTERN, ...)
```

## 9. Run lifecycle

End-to-end, a single eval prompt flows like this:

1. **Load profile.**
   [`load_profile()`](../blue_bench_mcp/profiles/__init__.py) parses
   `blue_bench_mcp/profiles/<name>.yaml` into a `ModelProfile`.
2. **Compose system prompt.**
   [`compose(profile, context)`](../blue_bench_mcp/prompts_compose.py)
   reads the four markdown parts referenced by `prompt_parts`, strips
   HTML comments, substitutes `{tool_list}`, `{tool_count}`,
   `{workflows}`, etc. from the context dict, and concatenates.
3. **Launch server + connect client.** The runner spawns
   `python -m blue_bench_mcp.server` as a child process and opens a
   stdio MCP client (browser clients open an SSE session instead).
4. **Fetch tool list.** `client.list_tools()` → fed into the composer
   context as `{tool_list}` / `{tool_count}`.
5. **Model ↔ tool loop.**
   [`runner.run()`](../blue_bench_client/runner.py) (or
   [`runConversation()`](../blue_bench_frontend/loop.js) in the browser)
   branches on `profile.tool_protocol`:
   - `native` — Ollama `/api/chat` with a `tools` schema; the response
     carries structured `tool_calls`.
   - `text-embedded` — Ollama `/api/chat` without a schema; the model
     emits ```` ```tool_call {"name": …, "parameters": …} ``` ```` fenced
     JSON which the runner parses with regex (fallbacks: legacy
     `<tool>/<args>` tags, bare JSON).
   - `anthropic-native` — Anthropic Messages API via SDK (Python) or
     proxy (browser) with native `tool_use` / `tool_result` blocks.

   Each tool call is dispatched through the MCP client; the result is
   fed back into the conversation. Loop repeats until the model stops
   calling tools or `max_turns` is reached.
6. **Trace.** The runner captures a
   [`Trace`](../blue_bench_client/trace.py): profile, model, ordered
   turns (assistant + tool), composed prompt, final answer, wall-clock
   timing. Traces are the eval harness's input and are
   protocol-agnostic.
7. **Qualify path only.**
   [`blue_bench_eval.qualify.run_corpus()`](../blue_bench_eval/qualify.py)
   runs steps 1–6 per prompt in the corpus and writes one JSON per
   prompt plus a `run_meta.json` under
   `results/<timestamp>-<profile>/`. `blue-bench aggregate` consumes the
   scored outputs.

## Non-goals

- **Replacing MCP.** Blue-Bench is an MCP server. It does not reinvent
  the protocol.
- **Hosting the model.** Blue-Bench does not ship model weights or a
  training pipeline. Tier 2 is Ollama or the Anthropic API.
- **Being a SIEM.** Blue-Bench integrates with existing SIEMs
  (Elasticsearch, Wazuh) as data sources; it does not try to be one.
- **Running a bundler.** The frontend is vanilla ESM. If you need a
  bundler, fork — but you will not get support for build-tool issues in
  this repo.
- **Auth.** The proxy strips client-supplied credentials and injects the
  server-side key. Any further authentication (SSO, IP allow-list,
  reverse-proxy policy) lives outside Blue-Bench.
