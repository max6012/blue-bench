#!/usr/bin/env bash
# Top-level Linux VM bootstrap. Runs numbered scripts in order.
#
# Prerequisites (out-of-band before this script):
#   - VM static IP 192.168.66.20, no default gateway
#   - /tmp/sandbox-deps/ staged with .debs + ART zips (see utm-vm-spec.md)
#   - /home/analyst/.ssh/authorized_keys staged (orchestrator key)
#
# Sequence:
#   01 install packages       (auditd, zeek, suricata, ART deps)
#   02 configure auditd
#   03 configure zeek
#   04 configure suricata
#   05 install Atomic Red Team

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: bootstrap.sh must run as root (use sudo)." >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

steps=(
    "01-install-packages.sh"
    "02-configure-auditd.sh"
    "03-configure-zeek.sh"
    "04-configure-suricata.sh"
    "05-install-atomic-red-team.sh"
)

for step in "${steps[@]}"; do
    if [[ ! -x "$HERE/$step" ]]; then
        chmod +x "$HERE/$step"
    fi
    echo ""
    echo "=== $step ==="
    "$HERE/$step"
done

echo ""
echo "OK: Linux bootstrap complete. Snapshot the VM as 'baseline' before running atomics."
