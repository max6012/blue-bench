#!/usr/bin/env bash
# Take a UTM snapshot of one or both sandbox VMs.
#
# UTM CLI: `utmctl` from the UTM 4.5+ command-line interface.
#   utmctl snapshot create <vm-name> <snapshot-name>
#
# Usage:
#   ./snapshot.sh windows baseline
#   ./snapshot.sh linux   baseline
#   ./snapshot.sh both    baseline
#   ./snapshot.sh both    post-T1059.001

set -euo pipefail

if ! command -v utmctl >/dev/null 2>&1; then
    cat >&2 <<EOF
ABORT: utmctl not on PATH.

UTM 4.5+ ships utmctl. Add it to PATH:
    export PATH="/Applications/UTM.app/Contents/MacOS:\$PATH"
or invoke via the full path:
    /Applications/UTM.app/Contents/MacOS/utmctl snapshot create ...
EOF
    exit 1
fi

TARGET=${1:-}
NAME=${2:-}

WIN_VM=${SANDBOX_WIN_VM:-sandbox-win}
LNX_VM=${SANDBOX_LNX_VM:-sandbox-lnx}

if [[ -z $TARGET || -z $NAME ]]; then
    echo "usage: $0 {windows|linux|both} <snapshot-name>" >&2
    exit 2
fi

snap_one() {
    local vm=$1 nm=$2
    echo "Snapshotting $vm -> '$nm'"
    utmctl snapshot create "$vm" "$nm"
}

case "$TARGET" in
    windows) snap_one "$WIN_VM" "$NAME" ;;
    linux)   snap_one "$LNX_VM" "$NAME" ;;
    both)
        snap_one "$WIN_VM" "$NAME"
        snap_one "$LNX_VM" "$NAME"
        ;;
    *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac

echo "OK: snapshot '$NAME' created."
