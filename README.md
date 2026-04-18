# Blue-Bench

**AI-augmented Blue Team validation framework and MCP tool server**, designed for self-hosted open-weight LLMs in network-isolated environments.

Blue-Bench lets you plug a local LLM (via Ollama) or a frontier cloud model (via the Anthropic API) into a curated set of Blue Team security tools — Elasticsearch queries, Wazuh alerts, Sigma/YARA validation, forensic triage, nmap — through the [Model Context Protocol](https://modelcontextprotocol.io/). The same MCP server serves any compliant client (Claude Code, Cline, Continue, Open WebUI, a custom CLI, or the reference client shipped here). Swapping models is a YAML profile change, not a code change.

> **Status:** Stable. Configuration is end-to-end validated by frontier-model reference runs; open-weight Gemma 4 E4B reaches 95.8% of that ceiling on 24 GB commodity hardware. See `docs/ARCHITECTURE.md` for the design overview.

## Why this exists

Practical SOC workflows mix LLM reasoning with specialized tools: "triage these alerts," "write a Sigma rule that matches this pattern," "extract IOCs from this binary." Doing that with a local LLM (not a cloud API) is non-trivial — tool wiring, system-prompt coaching, and per-model protocol differences all matter. Blue-Bench makes each of those a **separately editable concern** so teams can adapt without forking the runtime.

## Architecture (three layers)

- **Tools live in the MCP server.** `blue_bench_mcp/tool_classes/` holds implementations; `blue_bench_mcp/tools/` registers them with the server. Any MCP client sees the same surface.
- **Models are YAML profiles.** `blue_bench_mcp/profiles/<name>.yaml` declares tool-call protocol (`native` for Ollama-native tool schemas, `text-embedded` for text-fence tool calls, or `anthropic-native` for Anthropic's structured tool_use blocks), context size, coaching hints, and which prompt parts to compose. Adding a model is adding a profile.
- **System prompts compose from markdown parts at request time.** `blue_bench_mcp/prompts/{role,site,guidelines,coaching}/*.md` holds the pieces: `role` and `guidelines` are model- and site-agnostic; `site/` is a per-deployment overlay describing indices, hostnames, and IRP conventions; `coaching/` is per-model behavior hints. `prompts_compose.py` assembles them with per-request placeholder substitution. System prompts are never hardcoded.

A thin reference MCP client (`blue_bench_client/`) and a validation harness (`blue_bench_eval/`) are included but optional — third-party MCP clients work equivalently.

## Validation methodology

Runs fall into two classes:

- **Frontier reference runs** (Claude Sonnet / Opus via the Anthropic API) establish the configuration ceiling. If a frontier model doesn't score 100% on the fixed corpus, the wiring is broken — not the model. This catches infrastructure bugs, data-fixture gaps, hallucinated tool schemas, and missing coaching before they get attributed to local-model capability.
- **Local runs** (Ollama-hosted open-weight models) are measured as a percentage of the frontier ceiling. Tune coaching and prompts against a stable reference instead of a moving target.

Every tool-surface change should re-trigger the frontier run to re-establish the ceiling. See `docs/ARCHITECTURE.md` for the run lifecycle and `blue_bench_eval/` for the rubric.

## Quickstart

Requires Python 3.10+, Docker, and a local [Ollama](https://ollama.com/) install with the model you want to test pulled.

```bash
# 1. Install
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# 2. Bring up the tool tier (MCP server + Elasticsearch + Wazuh + OpenEDR mock + scanner sidecar)
docker compose -f docker/compose.tools.yml up -d --build
# Or, for one-command dev bring-up of all three tiers (tools + LLM + frontend):
#   docker compose -f docker/compose.all.yml up -d --build

# 3. Seed Elasticsearch with sample telemetry (you supply data/raw/*.json + conn.log)
python scripts/seed_es.py

# 4. Pull a model you want to test
ollama pull gemma4:e4b    # or llama3.1:8b, qwen3:8b, ...
# For frontier runs, set ANTHROPIC_API_KEY in .env instead.

# 5. Run the evaluation corpus
blue-bench qualify --profile gemma4-e4b --limit 1
```

Results land in `results/<timestamp>-<profile>/`. To aggregate into a BLUF after judging, use `blue-bench aggregate <run-dir>`.

## Transport: stdio vs SSE

The MCP server speaks two transports from the same process — tool registration is identical:

- **stdio (default)** — what Claude Code, the reference runner, and most desktop MCP clients expect. Launch with `scripts/mcp_server.sh` or `python -m blue_bench_mcp.server`.
- **SSE (HTTP/Server-Sent Events)** — for browser-based MCP clients that connect directly to the server. Launch with `scripts/mcp_server_sse.sh` or:
  ```bash
  python -m blue_bench_mcp.server --transport sse --host 127.0.0.1 --port 8765
  ```
  Clients connect to `http://<host>:<port>/sse`. Multiple clients can connect concurrently. Host, port, and CORS origins are configurable in `config.yaml` under `transport.sse`; CLI flags (`--host`, `--port`) override. The env var `BLUE_BENCH_CORS_ORIGINS` (comma-separated, or `*` for dev) overrides the origin allowlist at runtime. Default allowlist is `http://localhost:*` and `http://127.0.0.1:*`. A small `/health` endpoint on the same port returns `{"ok": true}` (used by the container healthcheck).

## Tiered deployment — three compose files

Blue-Bench is designed for a three-tier deployment. Each tier is independently deployable and has its own compose file under `docker/`:

| Tier | Compose file | Services | Typical host |
| --- | --- | --- | --- |
| 1. Tools | `docker/compose.tools.yml` | `mcp` (SSE :8765) + elasticsearch + wazuh + openedr + target + scanner | CPU |
| 2. LLM | `docker/compose.llm.yml` | `anthropic-proxy` (:8766) + `ollama` (:11434) | GPU (for Ollama) |
| 3. Frontend | `docker/compose.frontend.yml` | `frontend` (nginx, :5173 → 80) serving `blue_bench_frontend/` | Any static host / CDN |

For dev / MVP on a single host, a fourth compose file — `docker/compose.all.yml` — uses Docker Compose's `include:` directive to bring up all three tiers at once. Requires Docker Compose v2.20+ (ships with Docker Desktop 4.24+).

```bash
# Dev / MVP — everything on one host:
docker compose -f docker/compose.all.yml up -d --build

# Production — each tier on its appropriate host:
docker compose -f docker/compose.tools.yml up -d --build       # CPU host
docker compose -f docker/compose.llm.yml up -d --build         # GPU host
docker compose -f docker/compose.frontend.yml up -d            # Static host
```

Exposed endpoints after `compose.all.yml` is up:

```
MCP SSE / health:       http://localhost:8765/sse  |  /health
Anthropic proxy:        http://localhost:8766/v1/messages  |  /health
Ollama:                 http://localhost:11434/api/tags
Frontend (browser UI):  http://localhost:5173
Elastic / OpenEDR / Wazuh: :9200 / :9443 / :55000 (as before)
```

### Tier 1 — tool tier

The `mcp` service shares `blue-bench-net` with the backends and reaches them via service DNS (`elasticsearch:9200`, `wazuh:55000`, `openedr:9443`). `config.yaml` uses `${VAR:-default}` interpolation so the same file works host-mode (localhost) and in-container. The container runs as a non-root user, installs its own `nmap` binary (so scans reach `10.10.5.22` directly on `blue-bench-net`), and does not bake in any secrets — pass credentials via `docker compose --env-file ...` or a `.env` in the repo root.

The stdio transport path is unchanged: `python -m blue_bench_mcp.server` still works on the host for Claude Code / Cline / the reference runner, talking to the same Dockerized backends.

### Tier 2 — LLM tier

The Anthropic proxy is built from `docker/Dockerfile.proxy` (minimal image: `python:3.12-slim` + fastapi + uvicorn + httpx + python-dotenv, non-root user). It fails fast at startup if `ANTHROPIC_API_KEY` is unset — put the key in the repo-root `.env` before `docker compose up`.

Ollama is containerized here for range / production deployment onto a GPU host. **For dev / MVP, most people run Ollama directly on the host** so it can use Metal / CUDA locally — in that case, start only the proxy from this compose file (`docker compose -f docker/compose.llm.yml up -d anthropic-proxy`). For GPU passthrough to the `ollama` container, uncomment the `deploy.resources.reservations.devices` block in `compose.llm.yml` (requires the NVIDIA container toolkit on the host). Model cache is persisted on the host at `./data/ollama`.

## Browser frontend setup — enabling Ollama CORS

If you're running a browser-based MCP client (served by default at `http://localhost:5173`) and it calls Ollama directly via `fetch`, the browser enforces CORS. Ollama's default configuration rejects cross-origin requests, so you need to whitelist the frontend origin via the `OLLAMA_ORIGINS` environment variable. **Ollama reads this variable at startup only — restart the server after changing it.**

The helper script prints the right command(s) for your OS (it does not execute them):

```bash
scripts/ollama_cors_enable.sh http://localhost:5173
```

Quick reference per platform:

- **macOS (Ollama.app, menu-bar install):**
  ```bash
  launchctl setenv OLLAMA_ORIGINS "http://localhost:5173"
  # then quit Ollama from the menu bar and relaunch
  ```
- **macOS (Homebrew service):**
  ```bash
  brew services stop ollama
  OLLAMA_ORIGINS="http://localhost:5173" brew services start ollama
  ```
- **Linux (systemd):**
  ```bash
  sudo systemctl edit ollama.service
  # add under [Service]:
  #   Environment="OLLAMA_ORIGINS=http://localhost:5173"
  sudo systemctl daemon-reload && sudo systemctl restart ollama
  ```
- **Windows:** set `OLLAMA_ORIGINS=http://localhost:5173` via System Properties → Environment Variables (user scope), then quit Ollama from the system tray and relaunch.

**Dev-only shortcut:** `OLLAMA_ORIGINS="*"` allows any origin. Only use on a host whose Ollama port is not reachable from other machines — never in a shared or production-like deployment.

### Smoke test

```bash
curl -H "Origin: http://localhost:5173" -I http://localhost:11434/api/tags
```

Expected response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://localhost:5173
```

If the `Access-Control-Allow-Origin` header is missing, Ollama did not pick up the new value — confirm the variable was set in the same environment that launched Ollama, and that you restarted the server afterwards.

## Layout

```
blue_bench_mcp/           MCP server — tools, profiles, composable prompts
blue_bench_client/        Reference MCP client + Ollama runner
blue_bench_cli/           Operator CLI: blue-bench qualify | aggregate | diff | server
blue_bench_eval/          Validation harness: prompt YAML + rubric + aggregator
docker/                   compose.{tools,llm,frontend,all}.yml + Dockerfile.* + mock backends
scripts/                  Data seeding + utilities
tests/                    Unit + integration tests (pytest)
docs/                     Public architecture + guides
```

Private / gitignored (contributor-local):

```
docs/internal/            Internal planning + narrative
results/                  Run traces + scored JSONs + BLUFs
data/raw/                 Source telemetry (AIT-ADS, Brim, etc.)
data/evidence/            Forensic samples
.plandb.db                Agent task graph state
.claude/                  Assistant session state
```

## Adding a model

1. Write `blue_bench_mcp/profiles/<your-model>.yaml` declaring `model_id`, `tool_protocol`, `context_size`, `generation`, `prompt_parts`.
2. If the model needs bespoke coaching, write `blue_bench_mcp/prompts/coaching/<your-model>.md` (markdown with optional `{placeholder}` substitution).
3. `blue-bench qualify --profile <your-model>` — run the evaluation.

## Adding a tool

1. Write `blue_bench_mcp/tool_classes/<tool>.py` — one class, N async methods, config from `ServerConfig`, guardrails from `blue_bench_mcp/guardrails.py`.
2. Write `blue_bench_mcp/tools/<tool>.py` — a thin `register(server, cfg)` that wires each method with `@server.tool()`.
3. Restart the server. The tool is discoverable by every MCP client.

See `docs/ARCHITECTURE.md` for the full contract.

## Browser-side Anthropic proxy

`blue_bench_mcp/anthropic_proxy.py` is a minimal FastAPI app for browser MCP
clients that need to talk to Claude. Browsers cannot safely hold
`ANTHROPIC_API_KEY`, so this proxy holds it server-side and forwards
`POST /v1/messages` verbatim to `https://api.anthropic.com/v1/messages`,
preserving SSE streaming when the request body has `"stream": true`.

Put `ANTHROPIC_API_KEY` in your repo-root `.env` (same file the qualify
runner uses — see `.env.example`). The proxy fails fast at startup if the
key is missing.

```bash
# Start (default host 127.0.0.1, port 8766):
scripts/anthropic_proxy.sh --port 8766
# or, equivalently:
python -m blue_bench_mcp.anthropic_proxy --port 8766

# Health check:
curl -s http://localhost:8766/health
# {"ok": true, "upstream": "api.anthropic.com"}
```

CORS defaults to any `http://localhost:*` or `http://127.0.0.1:*` origin.
Override with `FRONTEND_ORIGIN` in `.env` — a comma-separated allow-list
(`https://app.example.com,https://staging.example.com`) or `*`.

Security notes:

- The proxy strips any client-supplied `x-api-key` and `Authorization`
  header before forwarding, so browser code can never override the key.
- Request and response bodies are never logged. Uvicorn's access log
  records method, path, and status only.
- The proxy does nothing else: no model selection, no caching, no retries,
  no auth of its own. Put it behind whatever policy your deployment needs
  (SSO, IP allow-list, reverse proxy) — it is just the thin HTTPS leg.

## License

MIT — see [`LICENSE`](LICENSE).

## Contributing

Issues and PRs welcome. Architecture conversations happen in issues; before proposing a large change please open an issue first to avoid duplicate work.
