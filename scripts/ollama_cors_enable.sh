#!/usr/bin/env bash
# ollama_cors_enable.sh
#
# Print the OS-appropriate command(s) to allow a browser-based MCP client
# (served from http://localhost:5173 by default) to call Ollama's HTTP API
# at http://localhost:11434 directly via fetch.
#
# This script DOES NOT execute launchctl / systemctl / registry changes on
# your behalf. It prints commands for you to review and run yourself.
#
# Usage:
#   scripts/ollama_cors_enable.sh [ORIGIN]
#
# Example:
#   scripts/ollama_cors_enable.sh http://localhost:5173
#
# Environment:
#   Ollama reads OLLAMA_ORIGINS at startup. Any change requires restarting
#   Ollama (quit + relaunch, or service restart).

set -euo pipefail

ORIGIN="${1:-http://localhost:5173}"
UNAME="$(uname -s 2>/dev/null || echo unknown)"

hr() { printf '%s\n' "--------------------------------------------------------"; }

cat <<EOF
Blue-Bench — Ollama CORS enable helper
Target origin: ${ORIGIN}
Detected OS:   ${UNAME}

This script prints the commands you should run. It does not execute them.
EOF
hr

case "${UNAME}" in
    Darwin)
        cat <<EOF
macOS detected.

Option A — Ollama.app (menu-bar install, most common):

    launchctl setenv OLLAMA_ORIGINS "${ORIGIN}"

  Then fully quit Ollama from the menu bar and relaunch it. launchctl setenv
  does not persist across reboots; to make it permanent, add the command to
  a LaunchAgent plist or your shell profile and ensure the Ollama app is
  started by a process that inherits it.

Option B — Homebrew service (ollama serve as a brew service):

    brew services stop ollama
    OLLAMA_ORIGINS="${ORIGIN}" brew services start ollama

  Or, for a foreground run (useful for debugging):

    OLLAMA_ORIGINS="${ORIGIN}" ollama serve

EOF
        ;;
    Linux)
        cat <<EOF
Linux detected.

Systemd (typical install via curl | sh):

    sudo systemctl edit ollama.service

  Add the following override, then save and exit:

    [Service]
    Environment="OLLAMA_ORIGINS=${ORIGIN}"

  Reload and restart:

    sudo systemctl daemon-reload
    sudo systemctl restart ollama

Foreground (no systemd):

    OLLAMA_ORIGINS="${ORIGIN}" ollama serve

EOF
        ;;
    MINGW*|MSYS*|CYGWIN*)
        cat <<EOF
Windows (POSIX shell detected).

PowerShell, persistent user env var:

    [Environment]::SetEnvironmentVariable("OLLAMA_ORIGINS", "${ORIGIN}", "User")

  Then quit Ollama from the system tray and relaunch it. Alternatively set
  the variable via System Properties -> Environment Variables.

EOF
        ;;
    *)
        cat <<EOF
Unrecognized OS (${UNAME}). General guidance:

  Set the environment variable OLLAMA_ORIGINS="${ORIGIN}" in whatever
  mechanism starts the Ollama server on your platform, then restart Ollama.
  Ollama reads this variable at startup only.

EOF
        ;;
esac

hr
cat <<EOF
Dev-only shortcut (NOT SAFE outside localhost-only deployments):

    OLLAMA_ORIGINS="*"

  This allows any origin to call your Ollama server. Only use on a machine
  whose Ollama port is not reachable from other hosts.

EOF
hr
cat <<EOF
Verify with a CORS preflight-style curl:

    curl -H "Origin: ${ORIGIN}" -I http://localhost:11434/api/tags

  You should see:
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: ${ORIGIN}

  If Access-Control-Allow-Origin is missing, Ollama did not pick up the
  new OLLAMA_ORIGINS value — confirm it was set in the same environment
  that launched Ollama and that you restarted the server.

EOF

exit 0
