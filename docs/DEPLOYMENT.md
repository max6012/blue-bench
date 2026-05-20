# Blue-Bench Deployment Guide

Operational reference for standing up the stack across the three deployment tiers.
For architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).
For evaluation methodology, see [EVAL.md](EVAL.md).

## Three-tier deployment

Blue-Bench separates tools, LLM runtime, and the browser frontend into independent tiers. Each has its own compose file under `docker/`.

| Tier | Compose file | Services | Typical host |
| --- | --- | --- | --- |
| 1. Tools | `docker/compose.tools.yml` | `mcp` (SSE :8765) + elasticsearch + wazuh + openedr + target + scanner | CPU |
| 2. LLM | `docker/compose.llm.yml` | `anthropic-proxy` (:8766) + `ollama` (:11434) | GPU (for Ollama) |
| 3. Frontend | `docker/compose.frontend.yml` | `frontend` (nginx, :5173 → 80) serving `blue_bench_frontend/` | Any static host / CDN |

For dev / MVP on a single host, `docker/compose.all.yml` uses Docker Compose's `include:` directive to bring up all three tiers at once. Requires Docker Compose v2.20+ (ships with Docker Desktop 4.24+).

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
Elastic / OpenEDR / Wazuh: :9200 / :9443 / :55000
```

### Tier 1 — tool tier

The `mcp` service shares `blue-bench-net` with the backends and reaches them via service DNS (`elasticsearch:9200`, `wazuh:55000`, `openedr:9443`). `config.yaml` uses `${VAR:-default}` interpolation so the same file works host-mode (localhost) and in-container. The container runs as a non-root user, installs its own `nmap` binary, and does not bake in any secrets — pass credentials via `docker compose --env-file ...` or a `.env` in the repo root.

The stdio transport path is unchanged: `python -m blue_bench_mcp.server` still works on the host for Claude Code / Cline / the reference CLI, talking to the same Dockerized backends.

### Tier 2 — LLM tier

The Anthropic proxy is built from `docker/Dockerfile.proxy` (minimal image: `python:3.12-slim` + fastapi + uvicorn + httpx + python-dotenv, non-root user). It fails fast at startup if `ANTHROPIC_API_KEY` is unset — put the key in the repo-root `.env` before `docker compose up`.

Ollama is containerized here for range / production deployment onto a GPU host. **For dev / MVP, most people run Ollama directly on the host** so it can use Metal / CUDA locally — in that case, start only the proxy from this compose file (`docker compose -f docker/compose.llm.yml up -d anthropic-proxy`). For GPU passthrough to the `ollama` container, uncomment the `deploy.resources.reservations.devices` block in `compose.llm.yml` (requires the NVIDIA container toolkit). Model cache is persisted on the host at `./data/ollama`.

## Transport: stdio vs SSE

The MCP server speaks two transports from the same process:

- **stdio (default)** — what Claude Code, the reference CLI, and most desktop MCP clients expect. Launch with `scripts/mcp_server.sh` or `python -m blue_bench_mcp.server`.
- **SSE (HTTP/Server-Sent Events)** — for browser-based MCP clients. Launch with `scripts/mcp_server_sse.sh` or:
  ```bash
  python -m blue_bench_mcp.server --transport sse --host 127.0.0.1 --port 8765
  ```
  Clients connect to `http://<host>:<port>/sse`. Multiple clients can connect concurrently. Host, port, and CORS origins are configurable in `config.yaml` under `transport.sse`; CLI flags override. The env var `BLUE_BENCH_CORS_ORIGINS` (comma-separated, or `*` for dev) overrides the origin allowlist at runtime. Default allowlist is `http://localhost:*` and `http://127.0.0.1:*`. A small `/health` endpoint on the same port returns `{"ok": true}`.

## Browser frontend — enabling Ollama CORS

If the browser frontend calls Ollama directly via `fetch`, the browser enforces CORS. Ollama's default configuration rejects cross-origin requests. Whitelist the frontend origin via the `OLLAMA_ORIGINS` environment variable. **Ollama reads this variable at startup only — restart after changing it.**

```bash
scripts/ollama_cors_enable.sh http://localhost:5173   # prints the right command for your OS
```

Quick reference:

- **macOS (Ollama.app):**
  ```bash
  launchctl setenv OLLAMA_ORIGINS "http://localhost:5173"
  # quit Ollama from the menu bar and relaunch
  ```
- **macOS (Homebrew):**
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
- **Windows:** set `OLLAMA_ORIGINS=http://localhost:5173` via System Properties → Environment Variables, then restart Ollama from the system tray.

**Dev-only shortcut:** `OLLAMA_ORIGINS="*"` allows any origin. Only use on a host whose Ollama port is not reachable from other machines.

Smoke test:
```bash
curl -H "Origin: http://localhost:5173" -I http://localhost:11434/api/tags
# Expected: Access-Control-Allow-Origin: http://localhost:5173
```

## Anthropic proxy

`blue_bench_mcp/anthropic_proxy.py` is a minimal FastAPI app for browser MCP clients that need to talk to Claude. Browsers cannot safely hold `ANTHROPIC_API_KEY`, so this proxy holds it server-side and forwards `POST /v1/messages` verbatim to `https://api.anthropic.com/v1/messages`, preserving SSE streaming when the request body has `"stream": true`.

```bash
# Start (default host 127.0.0.1, port 8766):
scripts/anthropic_proxy.sh --port 8766

# Health check:
curl -s http://localhost:8766/health
# {"ok": true, "upstream": "api.anthropic.com"}
```

CORS defaults to any `http://localhost:*` or `http://127.0.0.1:*` origin. Override with `FRONTEND_ORIGIN` in `.env` — comma-separated or `*`.

Security notes:
- Strips any client-supplied `x-api-key` and `Authorization` header before forwarding.
- Request and response bodies are never logged.
- No model selection, caching, retries, or auth of its own — put it behind whatever policy your deployment needs.
