#!/usr/bin/env bash
# Restore one or both sandbox VMs to a named snapshot.
#
# Usage:
#   ./restore.sh windows baseline
#   ./restore.sh linux   baseline
#   ./restore.sh both    baseline

set -euo pipefail

if ! command -v utmctl >/dev/null 2>&1; then
    echo "ABORT: utmctl not on PATH. See snapshot.sh for fix." >&2
    exit 1
fi

TARGET=${1:-}
NAME=${2:-baseline}

WIN_VM=${SANDBOX_WIN_VM:-sandbox-win}
LNX_VM=${SANDBOX_LNX_VM:-sandbox-lnx}

if [[ -z $TARGET ]]; then
    echo "usage: $0 {windows|linux|both} [snapshot-name=baseline]" >&2
    exit 2
fi

restore_one() {
    local vm=$1 nm=$2
    echo "Restoring $vm -> '$nm' (this stops the VM, reverts, then leaves it stopped)"
    utmctl stop "$vm" --force 2>/dev/null || true
    utmctl snapshot restore "$vm" "$nm"
    utmctl start "$vm"
    echo "  $vm started; wait ~20s for SSH to come back."
}

case "$TARGET" in
    windows) restore_one "$WIN_VM" "$NAME" ;;
    linux)   restore_one "$LNX_VM" "$NAME" ;;
    both)
        restore_one "$WIN_VM" "$NAME" &
        restore_one "$LNX_VM" "$NAME" &
        wait
        ;;
    *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac

echo "OK: restored to '$NAME'."
