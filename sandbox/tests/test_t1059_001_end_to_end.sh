#!/usr/bin/env bash
# Acceptance test for t-sandbox (GHA variant).
#
# Validates that the sandbox runs T1059.001 end-to-end and produces
# captured EVTX + Sysmon output via the GitHub Actions workflow.
#
# Pre-conditions:
#   - gh CLI authenticated against the repo (gh auth login)
#   - jq + python3 on PATH
#   - The sandbox-atomic.yml workflow exists on the branch you target
#     (it does, via this PR)
#
# What it does:
#   1. Trigger the GHA workflow with technique=T1059.001 test_numbers=1
#   2. Wait for the workflow run to complete
#   3. Download the sandbox-capture artifact
#   4. Assert on the harvested files
#
# Exits 0 on success.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ORCH="$(cd "$HERE/../orchestrator" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

echo "=== Step 1/3: trigger workflow ==="
"$ORCH/trigger-capture.sh" T1059.001 -TestNumbers 1

# shellcheck disable=SC1091
source /tmp/sandbox-current-run.id

echo ""
echo "=== Step 2/3: harvest ==="
"$ORCH/harvest-from-run.sh" "$GHA_RUN_ID"

CAP_DIR="$REPO_ROOT/data/raw/sandbox/$WORKFLOW_RUN_ID"

echo ""
echo "=== Step 3/3: assert ==="

fail() { echo "FAIL: $1" >&2; exit 1; }

# 3a. EVTX files exist and are non-empty.
for evtx in Security.evtx System.evtx Sysmon.evtx PowerShell.evtx; do
    p="$CAP_DIR/windows/$evtx"
    [[ -s $p ]] || fail "$evtx missing or empty at $p"
done
echo "  OK: all expected EVTX files present and non-empty"

# 3b. manifest present + non-zero total bytes.
[[ -s "$CAP_DIR/manifest.json" ]] || fail "manifest.json missing"
total=$(python3 -c "import json; print(json.load(open('$CAP_DIR/manifest.json'))['total_bytes'])")
if [[ "$total" -lt 10000 ]]; then
    fail "manifest reports total_bytes=$total which is implausibly small"
fi
echo "  OK: manifest.json present, total_bytes=$total"

# 3c. EVTX content checks (best-effort via python-evtx).
#
# Note on EventID regex: python-evtx serialises records as
#   <EventID Qualifiers="">N</EventID>
# (always with the Qualifiers attribute, even when empty). A plain
# `<EventID>N</EventID>` substring match returns zero hits even on
# records that DO carry the EventID. Use the attribute-tolerant
# pattern `<EventID[^>]*>N</EventID>`. (Caught during run-5 acceptance:
# the script returned green with 0 matches against an EVTX that
# actually contained 82 matching records.)
if python3 -c "import Evtx.Evtx" 2>/dev/null; then
    found_4688_powershell=$(python3 - <<PY
import re
from Evtx.Evtx import Evtx
eid_re = re.compile(r"<EventID[^>]*>4688</EventID>")
hits = 0
with Evtx("$CAP_DIR/windows/Security.evtx") as evtx:
    for record in evtx.records():
        xml = record.xml()
        if eid_re.search(xml) and re.search(r"powershell\.exe", xml, re.I):
            hits += 1
print(hits)
PY
)
    if [[ "$found_4688_powershell" -eq 0 ]]; then
        fail "no Security 4688 referencing powershell.exe in Security.evtx"
    fi
    echo "  OK: $found_4688_powershell Security 4688 events reference powershell.exe"

    found_sysmon_proccreate=$(python3 - <<PY
import re
from Evtx.Evtx import Evtx
eid_re = re.compile(r"<EventID[^>]*>1</EventID>")
hits = 0
with Evtx("$CAP_DIR/windows/Sysmon.evtx") as evtx:
    for record in evtx.records():
        xml = record.xml()
        if eid_re.search(xml) and re.search(r"powershell\.exe", xml, re.I):
            hits += 1
print(hits)
PY
)
    if [[ "$found_sysmon_proccreate" -eq 0 ]]; then
        fail "no Sysmon EventID 1 (ProcessCreate) referencing powershell.exe"
    fi
    echo "  OK: $found_sysmon_proccreate Sysmon EventID 1 events reference powershell.exe"
else
    echo "  WARN: python-evtx not installed -- relying on non-empty size only."
    echo "        pip install python-evtx to enable content assertions."
fi

echo ""
echo "ACCEPTANCE OK: workflow_run_id=$WORKFLOW_RUN_ID gha_run_id=$GHA_RUN_ID"
