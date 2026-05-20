#!/bin/sh
# Launch the Blue-Bench MCP server over SSE (HTTP).
#
# Usage:
#   scripts/mcp_server_sse.sh [--host 127.0.0.1] [--port 8765] [--config path/to/config.yaml]
#
# The SSE server exposes:
#   GET  http://<host>:<port>/sse        — event stream
#   POST http://<host>:<port>/messages/  — client -> server messages
#
# CORS origins come from config.yaml (transport.sse.origins) and can be
# overridden at runtime via BLUE_BENCH_CORS_ORIGINS (comma-separated; use
# "*" to allow any origin in dev).
#
# Like scripts/mcp_server.sh, this cd's to the repo root so relative paths
# in config.yaml resolve correctly.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

VENV_PY="$REPO_ROOT/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
    echo "Error: $VENV_PY not found. Run 'python3 -m venv .venv && pip install -e .[dev]' first." >&2
    exit 1
fi

exec "$VENV_PY" -m blue_bench_mcp.server --transport sse "$@"
