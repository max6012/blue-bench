#!/usr/bin/env bash
# Fire one Atomic Red Team technique on the AWS Windows capture host
# while Zeek records the mirrored traffic, then harvest both tiers
# into data/raw/sandbox/<run_id>/:
#   windows/  EVTX (Sysmon, PowerShell, Security, System) + manifest
#   zeek/     conn/dns/http/ssl/... logs from the mirror window
#
# Usage:
#   ./fire-and-harvest.sh T1059.001 1
#   ./fire-and-harvest.sh T1071.001 1 "@{ domain = 'http://example.com' }"
#
# Env: ZEEK_WINDOW (capture seconds, default 75).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
ENVFILE="$HERE/aws-resources.env"
# shellcheck disable=SC1090
source "$ENVFILE"
SSH_KEY="$HOME/.ssh/bb-sandbox-ed25519"
SSHO=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes)
ZEEK_WINDOW="${ZEEK_WINDOW:-75}"

TECH="${1:?usage: fire-and-harvest.sh TECHNIQUE TESTNUMBERS [input_args]}"
TNS="${2:?need test numbers}"
IARGS="${3:-}"

# Pipe-free suffix: `tr </dev/urandom | head -c6` trips SIGPIPE
# under `set -o pipefail` (head closes the pipe, tr dies 141),
# which killed the script before it produced any output.
RID_SUF="$(printf '%04x%02x' $RANDOM $((RANDOM % 256)))"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${TECH}-${RID_SUF}"
OUT="$REPO_ROOT/data/raw/sandbox/$RUN_ID"
mkdir -p "$OUT/windows" "$OUT/zeek"
echo "run_id: $RUN_ID"
echo "window: ${ZEEK_WINDOW}s   tech: $TECH tests=$TNS ${IARGS:+iargs=$IARGS}"

# ---- 1. start Zeek on the mirror (backgrounded local ssh) --------
ZDIR="/tmp/zk-$RUN_ID"
( ssh "${SSHO[@]}" "ubuntu@$ZEEK_PUBLIC_IP" \
    "mkdir -p $ZDIR && cd $ZDIR && sudo timeout $ZEEK_WINDOW /opt/zeek/bin/zeek -i vxlan0 -C 2>/dev/null; sudo chown -R ubuntu $ZDIR" ) &
ZEEK_BG=$!
sleep 6   # let Zeek bind vxlan0

# ---- 2. fire the atomic on Windows (blocking) --------------------
echo "firing atomic..."
EXTRA=""
[[ -n $IARGS ]] && EXTRA=" -InputArgs $IARGS"
BB_SANDBOX_ALLOW_REMOTE=1 BB_SANDBOX_SSH_HOST="$WIN_PUBLIC_IP" BB_SANDBOX_SSH_PORT=22 BB_SANDBOX_SSH_USER="$WIN_SSH_USER" \
  "$HERE/ssh-exec.sh" -c "Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force; \$env:PSAtomicsFolder='C:\AtomicRedTeam\atomics'; Invoke-AtomicTest $TECH -TestNumbers $TNS -PathToAtomicsFolder 'C:\AtomicRedTeam\atomics'$EXTRA" 2>&1 | tail -5

echo "atomic done; waiting for Zeek window to close + flush..."
wait "$ZEEK_BG" || true

# ---- 3. harvest Zeek logs ---------------------------------------
scp "${SSHO[@]}" "ubuntu@$ZEEK_PUBLIC_IP:$ZDIR/*.log" "$OUT/zeek/" 2>/dev/null || echo "  (no zeek logs this run)"
ssh "${SSHO[@]}" "ubuntu@$ZEEK_PUBLIC_IP" "sudo rm -rf $ZDIR" 2>/dev/null || true
echo "  zeek logs: $(ls "$OUT/zeek" 2>/dev/null | wc -l | tr -d ' ')"

# ---- 4. harvest Windows EVTX ------------------------------------
WIN_HARVEST="C:\\harvest\\$RUN_ID"
BB_SANDBOX_ALLOW_REMOTE=1 BB_SANDBOX_SSH_HOST="$WIN_PUBLIC_IP" BB_SANDBOX_SSH_PORT=22 BB_SANDBOX_SSH_USER="$WIN_SSH_USER" \
  "$HERE/ssh-exec.sh" -c "
\$d='$WIN_HARVEST'; New-Item -ItemType Directory -Path \$d -Force | Out-Null
wevtutil epl 'Microsoft-Windows-Sysmon/Operational' \"\$d\Sysmon.evtx\" /ow:true
wevtutil epl 'Windows PowerShell' \"\$d\PowerShell.evtx\" /ow:true
wevtutil epl Security \"\$d\Security.evtx\" /ow:true
wevtutil epl System \"\$d\System.evtx\" /ow:true
Compress-Archive -Path \$d\* -DestinationPath \"\$d.zip\" -Force
Write-Host ('zip: ' + (Get-Item \"\$d.zip\").Length + ' bytes')
" 2>&1 | tail -3

scp "${SSHO[@]}" "$WIN_SSH_USER@$WIN_PUBLIC_IP:C:/harvest/$RUN_ID.zip" "$OUT/windows/evtx.zip" 2>&1 | tail -1
( cd "$OUT/windows" && unzip -o evtx.zip >/dev/null && rm -f evtx.zip )
echo "  windows evtx: $(ls "$OUT/windows" 2>/dev/null | tr '\n' ' ')"

# ---- 5. manifest ------------------------------------------------
cat > "$OUT/manifest.json" <<EOF
{
  "run_id": "$RUN_ID",
  "technique": "$TECH",
  "test_numbers": "$TNS",
  "input_args": "$IARGS",
  "source": "aws-substrate",
  "win_instance": "$WIN_INSTANCE_ID",
  "zeek_instance": "$ZEEK_INSTANCE_ID",
  "zeek_window_seconds": $ZEEK_WINDOW,
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "OK: harvested -> $OUT"
ls -la "$OUT/windows" "$OUT/zeek" 2>&1 | head -30
