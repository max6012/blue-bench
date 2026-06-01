#!/usr/bin/env bash
# Acceptance test for t-sandbox.
#
# Validates that the sandbox runs T1059.001 end-to-end and produces
# captured EVTX + Sysmon + (optionally) Zeek output.
#
# Pre-conditions:
#   - both VMs are bootstrapped and at the 'baseline' snapshot
#   - orchestrator SSH key (default $HOME/.ssh/blue-bench-sandbox.key) is
#     installed on both VMs
#   - utmctl on PATH
#
# What it does:
#   1. Restore both VMs to baseline
#   2. Run T1059.001 #1 on the Windows VM
#   3. Harvest the resulting captures
#   4. Assert on the harvested files
#
# Exits 0 on success.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ORCH="$(cd "$HERE/../orchestrator" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

echo "=== Step 1/4: restore both VMs to baseline ==="
"$ORCH/restore.sh" both baseline

# Wait for SSH to come back up on both VMs.
echo "  Waiting for SSH on both VMs (up to 90s)..."
for i in $(seq 1 18); do
    if ssh -i "${SANDBOX_SSH_KEY:-$HOME/.ssh/blue-bench-sandbox.key}" \
           -o BatchMode=yes -o ConnectTimeout=3 \
           -o StrictHostKeyChecking=accept-new \
           "analyst@${SANDBOX_WIN_IP:-192.168.66.10}" 'exit 0' 2>/dev/null && \
       ssh -i "${SANDBOX_SSH_KEY:-$HOME/.ssh/blue-bench-sandbox.key}" \
           -o BatchMode=yes -o ConnectTimeout=3 \
           -o StrictHostKeyChecking=accept-new \
           "analyst@${SANDBOX_LNX_IP:-192.168.66.20}" 'exit 0' 2>/dev/null; then
        echo "  SSH up on both VMs (attempt $i)."
        break
    fi
    sleep 5
done

echo ""
echo "=== Step 2/4: run T1059.001 #1 ==="
"$ORCH/run-atomic.sh" T1059.001 -TestNumbers 1 --target windows

run_id=$(cat /tmp/sandbox-current-run.id)
echo "  run_id=$run_id"

echo ""
echo "=== Step 3/4: harvest ==="
"$ORCH/harvest.sh" "$run_id"

CAP_DIR="$REPO_ROOT/data/raw/sandbox/$run_id"

echo ""
echo "=== Step 4/4: assert ==="

fail() { echo "FAIL: $1" >&2; exit 1; }

# 4a. EVTX files exist and are non-empty.
for evtx in Security.evtx System.evtx Sysmon.evtx PowerShell.evtx; do
    p="$CAP_DIR/windows/$evtx"
    [[ -s $p ]] || fail "$evtx missing or empty at $p"
done
echo "  OK: all expected EVTX files present and non-empty"

# 4b. EVTX content check via wevtutil from inside the Windows VM.
#     (We have the EVTX files locally but parsing them on the Mac
#     requires python-evtx or similar. Easier to ask the Windows VM
#     to read its own EVTX one more time pre-snapshot-restore.)
#
#     We do the check OFFLINE from the .evtx file using python-evtx
#     if available; otherwise we skip with a warning and rely on
#     non-empty size as the weak gate.
if python3 -c "import Evtx.Evtx" 2>/dev/null; then
    found_4688_powershell=$(python3 - <<PY
import re
from Evtx.Evtx import Evtx
hits = 0
with Evtx("$CAP_DIR/windows/Security.evtx") as evtx:
    for record in evtx.records():
        xml = record.xml()
        if "<EventID>4688</EventID>" in xml and re.search(r"powershell\.exe", xml, re.I):
            hits += 1
print(hits)
PY
)
    if [[ "$found_4688_powershell" -eq 0 ]]; then
        fail "no Security 4688 event referencing powershell.exe in $CAP_DIR/windows/Security.evtx"
    fi
    echo "  OK: $found_4688_powershell Security 4688 events reference powershell.exe"

    found_sysmon_proccreate=$(python3 - <<PY
import re
from Evtx.Evtx import Evtx
hits = 0
with Evtx("$CAP_DIR/windows/Sysmon.evtx") as evtx:
    for record in evtx.records():
        xml = record.xml()
        if "<EventID>1</EventID>" in xml and re.search(r"powershell\.exe", xml, re.I):
            hits += 1
print(hits)
PY
)
    if [[ "$found_sysmon_proccreate" -eq 0 ]]; then
        fail "no Sysmon EventID 1 (ProcessCreate) referencing powershell.exe in Sysmon.evtx"
    fi
    echo "  OK: $found_sysmon_proccreate Sysmon EventID 1 events reference powershell.exe"
else
    echo "  WARN: python-evtx not installed -- relying on non-empty size only."
    echo "        pip install python-evtx to enable content assertions."
fi

# 4c. Zeek conn.log on the Linux side exists (atomic-internal traffic).
#     Not strictly required for T1059.001 #1 (mimikatz cradle is local),
#     but the conn.log file itself should exist as evidence Zeek was
#     running.
zlog="$CAP_DIR/linux/logs/current/conn.log"
if [[ ! -f $zlog && ! -f "$CAP_DIR/linux/opt/zeek/logs/current/conn.log" ]]; then
    echo "  WARN: Zeek conn.log not found at expected paths -- check linux/ layout"
else
    echo "  OK: Zeek conn.log present"
fi

# 4d. Manifest written.
[[ -s "$CAP_DIR/manifest.json" ]] || fail "manifest.json missing"
echo "  OK: manifest.json present"

echo ""
echo "ACCEPTANCE OK: run_id=$run_id"
