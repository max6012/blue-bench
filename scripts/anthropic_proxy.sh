#!/bin/sh
# Launch the Blue-Bench Anthropic proxy.
#
# Usage:
#   scripts/anthropic_proxy.sh [--host 127.0.0.1] [--port 8766]
#
# Reads ANTHROPIC_API_KEY from .env (python-dotenv). Fails fast if unset.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

VENV_PY="$REPO_ROOT/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
    echo "Error: $VENV_PY not found. Run 'python3 -m venv .venv && pip install -e .[dev]' first." >&2
    exit 1
fi

exec "$VENV_PY" -m blue_bench_mcp.anthropic_proxy "$@"
