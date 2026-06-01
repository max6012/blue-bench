#!/usr/bin/env bash
# Harvest captured telemetry from the sandbox VMs into data/raw/sandbox/<run_id>/.
#
# Streams collected:
#   Windows VM:
#     - Security.evtx                (4624 / 4625 / 4634 / 4672 / 4688 etc.)
#     - System.evtx
#     - Microsoft-Windows-Sysmon%4Operational.evtx
#     - Microsoft-Windows-PowerShell%4Operational.evtx
#     - C:\sandbox\transcripts\*.txt  (PowerShell transcripts)
#   Linux VM:
#     - /var/log/audit/audit.log     (auditd)
#     - /opt/zeek/logs/current/*.log (Zeek)
#     - /var/log/suricata/eve.json   (Suricata)
#     - /var/log/syslog
#     - /var/log/auth.log
#
# Run AFTER run-atomic.sh. Uses /tmp/sandbox-current-run.id by default.

set -euo pipefail

WIN_IP=${SANDBOX_WIN_IP:-192.168.66.10}
LNX_IP=${SANDBOX_LNX_IP:-192.168.66.20}
SSH_KEY=${SANDBOX_SSH_KEY:-$HOME/.ssh/blue-bench-sandbox.key}
REPO_ROOT=${BLUE_BENCH_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}

RUN_ID=${1:-}
if [[ -z $RUN_ID ]]; then
    if [[ -f /tmp/sandbox-current-run.id ]]; then
        RUN_ID=$(cat /tmp/sandbox-current-run.id)
    else
        echo "ABORT: no run_id argument and /tmp/sandbox-current-run.id missing." >&2
        exit 2
    fi
fi

OUT_DIR="$REPO_ROOT/data/raw/sandbox/$RUN_ID"
mkdir -p "$OUT_DIR"/{windows,linux}

echo "Harvest -> $OUT_DIR (run_id=$RUN_ID)"

# --- Windows EVTX ---------------------------------------------------

echo "  Windows: exporting EVTX channels..."
ssh -i "$SSH_KEY" -o BatchMode=yes "analyst@$WIN_IP" \
    "Remove-Item -Recurse -Force C:\\sandbox\\harvest -ErrorAction SilentlyContinue; \\
     New-Item -ItemType Directory -Path C:\\sandbox\\harvest | Out-Null; \\
     wevtutil epl Security C:\\sandbox\\harvest\\Security.evtx; \\
     wevtutil epl System   C:\\sandbox\\harvest\\System.evtx; \\
     wevtutil epl Microsoft-Windows-Sysmon/Operational      C:\\sandbox\\harvest\\Sysmon.evtx; \\
     wevtutil epl Microsoft-Windows-PowerShell/Operational  C:\\sandbox\\harvest\\PowerShell.evtx; \\
     wevtutil epl Microsoft-Windows-WMI-Activity/Operational C:\\sandbox\\harvest\\WMI.evtx; \\
     Compress-Archive -Path C:\\sandbox\\harvest\\* -DestinationPath C:\\sandbox\\harvest.zip -Force"

scp -i "$SSH_KEY" -o BatchMode=yes "analyst@$WIN_IP:C:\\sandbox\\harvest.zip" "$OUT_DIR/windows/harvest.zip"
(cd "$OUT_DIR/windows" && unzip -q harvest.zip && rm harvest.zip)

# Pull PowerShell transcripts separately (text files, not in EVTX).
ssh -i "$SSH_KEY" -o BatchMode=yes "analyst@$WIN_IP" \
    "if (Test-Path C:\\sandbox\\transcripts) { Compress-Archive -Path C:\\sandbox\\transcripts\\* -DestinationPath C:\\sandbox\\transcripts.zip -Force } else { New-Item -ItemType File -Path C:\\sandbox\\transcripts.zip -Force | Out-Null }"
scp -i "$SSH_KEY" -o BatchMode=yes "analyst@$WIN_IP:C:\\sandbox\\transcripts.zip" "$OUT_DIR/windows/transcripts.zip" || true

# --- Linux: auditd, Zeek, Suricata, syslog -------------------------

echo "  Linux: bundling audit + zeek + suricata + syslog..."
ssh -i "$SSH_KEY" -o BatchMode=yes "analyst@$LNX_IP" \
    "sudo tar -czf /tmp/sandbox-harvest.tgz \
        /var/log/audit/audit.log* \
        /opt/zeek/logs/current \
        /var/log/suricata/eve.json \
        /var/log/syslog \
        /var/log/auth.log 2>/dev/null || true"
scp -i "$SSH_KEY" -o BatchMode=yes "analyst@$LNX_IP:/tmp/sandbox-harvest.tgz" "$OUT_DIR/linux/harvest.tgz"
(cd "$OUT_DIR/linux" && tar -xzf harvest.tgz && rm harvest.tgz)

# --- manifest -------------------------------------------------------

echo "  Writing manifest..."

# Per-file sha256 for provenance.
manifest_path="$OUT_DIR/manifest.json"
python3 - <<PY > "$manifest_path"
import hashlib, json, os, sys, time

out_dir = "$OUT_DIR"
run_id = "$RUN_ID"

def sha256(path, chunk=1<<20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

files = []
for root, _, fnames in os.walk(out_dir):
    for fn in fnames:
        if fn in ("manifest.json",): continue
        p = os.path.join(root, fn)
        rel = os.path.relpath(p, out_dir)
        files.append({
            "path": rel,
            "bytes": os.path.getsize(p),
            "sha256": sha256(p),
        })

manifest = {
    "schema_version": 1,
    "run_id": run_id,
    "harvested_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "files": sorted(files, key=lambda f: f["path"]),
    "total_bytes": sum(f["bytes"] for f in files),
}
print(json.dumps(manifest, indent=2))
PY

# Append the row to data/raw/sandbox/manifest.csv (overall index).
INDEX="$REPO_ROOT/data/raw/sandbox/manifest.csv"
if [[ ! -f $INDEX ]]; then
    echo "run_id,harvested_at_utc,total_bytes,file_count" > "$INDEX"
fi
total_bytes=$(python3 -c "import json; m=json.load(open('$manifest_path')); print(m['total_bytes'])")
file_count=$(python3 -c "import json; m=json.load(open('$manifest_path')); print(len(m['files']))")
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$RUN_ID,$ts,$total_bytes,$file_count" >> "$INDEX"

echo ""
echo "OK: harvested -> $OUT_DIR"
echo "    $file_count files, $total_bytes bytes total."
echo "    manifest: $manifest_path"
