#!/usr/bin/env bash
# Run an Atomic Red Team technique inside the sandbox.
#
# Usage:
#   ./run-atomic.sh T1059.001 [-TestNumbers 1] [--target windows|linux]
#
# Defaults:
#   --target windows
#   -TestNumbers 1
#
# What it does:
#   1. Verifies safe-fire isolation (delegates to safe-fire-check.sh)
#   2. Generates a run_id = <utc-timestamp>-<technique>-<random-suffix>
#   3. SSHes into the target VM and invokes Invoke-AtomicTest
#   4. Waits a flush window so Sysmon / Zeek / Suricata catch up
#   5. Does NOT harvest -- run harvest.sh after.
#
# The run_id is printed to stdout AND written to
# /tmp/sandbox-current-run.id for harvest.sh to pick up.

set -euo pipefail

WIN_IP=${SANDBOX_WIN_IP:-192.168.66.10}
LNX_IP=${SANDBOX_LNX_IP:-192.168.66.20}
SSH_KEY=${SANDBOX_SSH_KEY:-$HOME/.ssh/blue-bench-sandbox.key}
HERE="$(cd "$(dirname "$0")" && pwd)"

TECHNIQUE=${1:-}
shift || true

TARGET=windows
TEST_NUMBERS="1"
EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"; shift 2 ;;
        -TestNumbers)
            TEST_NUMBERS="$2"; shift 2 ;;
        *)
            EXTRA+=("$1"); shift ;;
    esac
done

if [[ -z $TECHNIQUE ]]; then
    cat >&2 <<EOF
usage: $0 <T-number> [-TestNumbers N] [--target windows|linux] [extra Invoke-AtomicTest args]

examples:
    $0 T1059.001
    $0 T1059.001 -TestNumbers 1,2 --target windows
    $0 T1003.001 -TestNumbers 1 --target linux
EOF
    exit 2
fi

# --- 1. safe-fire gate ---------------------------------------------

"$HERE/safe-fire-check.sh"

# --- 2. run_id -------------------------------------------------------

now=$(date -u +%Y%m%dT%H%M%SZ)
suffix=$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c6)
run_id="${now}-${TECHNIQUE}-${suffix}"
echo "$run_id" > /tmp/sandbox-current-run.id

echo ""
echo "RUN_ID: $run_id"
echo "TARGET: $TARGET"
echo "TECH:   $TECHNIQUE TestNumbers=$TEST_NUMBERS ${EXTRA[*]:-}"
echo ""

# --- 3. dispatch -----------------------------------------------------

case "$TARGET" in
    windows)
        # Windows OpenSSH defaults to PowerShell as the configured shell.
        ssh -i "$SSH_KEY" -o BatchMode=yes "analyst@$WIN_IP" \
            "Import-Module C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1 -Force; \\
             \$env:PSAtomicsFolder='C:\\AtomicRedTeam\\atomics'; \\
             Invoke-AtomicTest $TECHNIQUE -TestNumbers $TEST_NUMBERS -GetPrereqs -PathToAtomicsFolder C:\\AtomicRedTeam\\atomics; \\
             Invoke-AtomicTest $TECHNIQUE -TestNumbers $TEST_NUMBERS -PathToAtomicsFolder C:\\AtomicRedTeam\\atomics ${EXTRA[*]:-}"
        ;;
    linux)
        ssh -i "$SSH_KEY" -o BatchMode=yes "analyst@$LNX_IP" \
            "pwsh -NoProfile -Command \"Import-Module /opt/atomic-red-team/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force; \\
             \\\$env:PSAtomicsFolder='/opt/atomic-red-team/atomics'; \\
             Invoke-AtomicTest $TECHNIQUE -TestNumbers $TEST_NUMBERS -GetPrereqs -PathToAtomicsFolder /opt/atomic-red-team/atomics; \\
             Invoke-AtomicTest $TECHNIQUE -TestNumbers $TEST_NUMBERS -PathToAtomicsFolder /opt/atomic-red-team/atomics ${EXTRA[*]:-}\""
        ;;
    *)
        echo "unknown --target: $TARGET" >&2
        exit 2 ;;
esac

# --- 4. flush wait --------------------------------------------------

FLUSH_S=${SANDBOX_FLUSH_SECONDS:-60}
echo ""
echo "Waiting ${FLUSH_S}s for telemetry to flush (Sysmon, Zeek, Suricata)..."
sleep "$FLUSH_S"

echo ""
echo "DONE. Run ./harvest.sh next to collect the captured telemetry."
echo "RUN_ID: $run_id"
