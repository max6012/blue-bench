#!/bin/sh
# Launch the Blue-Bench MCP server over stdio.
#
# Usage:
#   scripts/mcp_server.sh [--config path/to/config.yaml]
#
# This wrapper cd's to the repo root so relative paths in config.yaml
# (e.g., data/evidence/) resolve correctly regardless of where the
# caller invokes it from. Intended for registration with MCP clients
# that expect a single executable (e.g. `claude mcp add`).
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

VENV_PY="$REPO_ROOT/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
    echo "Error: $VENV_PY not found. Run 'python3 -m venv .venv && pip install -e .[dev]' first." >&2
    exit 1
fi

exec "$VENV_PY" -m blue_bench_mcp.server "$@"
