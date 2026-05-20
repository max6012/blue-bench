#!/usr/bin/env bash
# Blue-Bench demo pre-flight — narrated.
#
# Run from the project root in your terminal monitor while the frontend monitor
# shows http://127.0.0.1:5173/. The script narrates each step; pace it so the
# audience can read along. Set PAUSE=0 to silence the pacing for practice runs.

set -euo pipefail

# ── styling ────────────────────────────────────────────────────────────────
BOLD=$(tput bold 2>/dev/null || true)
DIM=$(tput dim 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
BLUE=$(tput setaf 4 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

PAUSE=${PAUSE:-1.2}

# Prefer the project venv if present; the seed script needs its deps.
if [[ -x "$(pwd)/.venv/bin/python" ]]; then
  PY="$(pwd)/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  PY="python"
fi

step() { echo; echo "${BOLD}${BLUE}▶ $*${RESET}"; sleep "$PAUSE"; }
say()  { echo "${DIM}  $*${RESET}"; sleep "$PAUSE"; }
ok()   { echo "${GREEN}  ✓ $*${RESET}"; }
warn() { echo "${YELLOW}  ⚠ $*${RESET}"; }
fail() { echo "${RED}  ✗ $*${RESET}"; exit 1; }
hdr()  { echo; echo "${BOLD}$*${RESET}"; }

# ── config ─────────────────────────────────────────────────────────────────
MCP_URL=${MCP_URL:-http://127.0.0.1:8765}
PROXY_URL=${PROXY_URL:-http://127.0.0.1:8766}
OLLAMA_URL=${OLLAMA_URL:-http://127.0.0.1:11434}
SONNET_MODEL=${SONNET_MODEL:-claude-sonnet-4-6}
GEMMA_TAG=${GEMMA_TAG:-gemma4:e4b}
QWEN_TAG=${QWEN_TAG:-qwen3.5:9b}
CONTINGENCY_TAGS=${CONTINGENCY_TAGS:-"gpt-oss:20b mistral-small:latest"}

clear
hdr "Blue-Bench demo pre-flight"
say "Run from project root. Frontend is on the other monitor."
say "PAUSE=${PAUSE}s between narration lines. Set PAUSE=0 to skip pacing."

# ── 1. service health ──────────────────────────────────────────────────────
step "1 — Service health checks"
say "Three local services must be up: MCP server, Anthropic proxy, Ollama."

say "MCP server (SSE on :8765)"
if curl -fsS -m 3 "${MCP_URL}/health" >/dev/null 2>&1; then
  ok "MCP responding"
else
  fail "MCP not reachable at ${MCP_URL} — start it before running the demo"
fi

say "Anthropic proxy (:8766) — holds ANTHROPIC_API_KEY server-side; fails fast if missing"
if curl -fsS -m 3 "${PROXY_URL}/health" >/dev/null 2>&1; then
  ok "Proxy responding"
else
  fail "Proxy not reachable at ${PROXY_URL} — bring it up via scripts/anthropic_proxy.sh"
fi

say "Ollama (:11434) — local model runtime"
if MODELS=$(curl -fsS -m 3 "${OLLAMA_URL}/api/tags" 2>/dev/null); then
  COUNT=$(printf '%s' "$MODELS" | "$PY" -c "import json,sys; print(len(json.load(sys.stdin).get('models', [])))" 2>/dev/null || echo 0)
  if [[ "${COUNT:-0}" -gt 0 ]]; then
    ok "Ollama up — ${COUNT} models loaded"
  else
    fail "Ollama up but no models pulled — pull gemma4:e4b and qwen3.5:9b first"
  fi
else
  fail "Ollama not reachable at ${OLLAMA_URL}"
fi

# ── 2. re-seed ES ──────────────────────────────────────────────────────────
step "2 — Re-seed Elasticsearch with fresh timestamps"
say "Sample telemetry must have @timestamp within the last 60 min."
say "Without this, every 'last-hour' query returns empty mid-demo."
echo "${YELLOW}  $ ${PY} scripts/seed_es.py${RESET}"
if "$PY" scripts/seed_es.py; then
  ok "ES re-seeded"
else
  fail "Re-seed failed — check Elasticsearch is reachable and data/raw/ has fixtures"
fi

# ── 3. Sonnet wiring ───────────────────────────────────────────────────────
step "3 — Sonnet wiring check (Anthropic proxy → api.anthropic.com)"
say "Same path the in-browser Sonnet tool test uses."
say "Confirms API key, network egress, and model routing."
say "If this fails, the in-browser Sonnet step will also fail."

REQ='{"model":"'"${SONNET_MODEL}"'","max_tokens":16,"messages":[{"role":"user","content":"reply with the single word OK"}]}'
if RESP=$(curl -fsS -m 20 -X POST "${PROXY_URL}/v1/messages" \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d "$REQ" 2>&1); then
  REPLY_TEXT=$(printf '%s' "$RESP" | "$PY" -c "import json,sys; d=json.load(sys.stdin); print(d['content'][0]['text'].strip()[:32])" 2>/dev/null || echo "(unparsed)")
  ok "Sonnet round-trip succeeded — model replied: \"${REPLY_TEXT}\""
else
  echo "${RED}  ${RESP}${RESET}"
  fail "Sonnet round-trip failed — check ANTHROPIC_API_KEY in .env and proxy logs"
fi

# ── 4. warm local models ───────────────────────────────────────────────────
step "4 — Warm local models"
say "First request loads weights into RAM; pre-warming avoids 10–30s cold-start mid-demo."

warm_one() {
  local tag="$1"; local label="$2"; local timeout="${3:-90}"
  say "Warming ${label} (${tag})…"
  local start=$(date +%s)
  if curl -fsS -m "${timeout}" -X POST "${OLLAMA_URL}/api/chat" \
    -H "content-type: application/json" \
    -d "{\"model\":\"${tag}\",\"messages\":[{\"role\":\"user\",\"content\":\"reply with OK\"}],\"stream\":false}" \
    >/dev/null 2>&1; then
    local elapsed=$(( $(date +%s) - start ))
    ok "${label} warm (${elapsed}s)"
  else
    return 1
  fi
}

warm_one "${GEMMA_TAG}" "Gemma 4 E4B" 60       || fail "Gemma 4 warm failed — pull it: ollama pull ${GEMMA_TAG}"
warm_one "${QWEN_TAG}" "Qwen 3.5 9B" 90        || fail "Qwen 3.5 9B warm failed — pull it: ollama pull ${QWEN_TAG}"

say "Contingency models (audience-question coverage) — warn-only if missing"
for tag in $CONTINGENCY_TAGS; do
  warm_one "$tag" "Contingency (${tag})" 90 || warn "Contingency ${tag} not warmed — won't be available for off-script questions"
done

# ── 5. manual checks ───────────────────────────────────────────────────────
step "5 — Manual checks (do these on the frontend monitor now)"
say "These I can't verify from terminal — switch your eyes to the other screen."
echo
echo "  ${BOLD}a)${RESET} Refresh the frontend tab — confirm '${BOLD}MCP: 14 tools${RESET}' in the top bar"
echo "  ${BOLD}b)${RESET} Profile = ${BOLD}gemma4-e4b${RESET} · click chip ${BOLD}p2-01 Initial alert triage${RESET} · result < 10s"
echo "  ${BOLD}c)${RESET} Profile dropdown → ${BOLD}claude-sonnet-4-6${RESET} · run ${BOLD}\"List all active Elastic alerts\"${RESET} · confirm result"
echo "  ${BOLD}d)${RESET} Profile dropdown → ${BOLD}gemma4-e4b${RESET} · ready for the demo"
echo "  ${BOLD}e)${RESET} Backup recording opens and plays (docs/internal/IPC/frontend_demo_backup.mp4)"
echo "  ${BOLD}f)${RESET} Monitor 1 fonts readable from the back of the room"
echo

hdr "${GREEN}Pre-flight automated checks complete.${RESET}"
echo "${DIM}Run this script again any time the stack restarts or models cool off.${RESET}"
echo
