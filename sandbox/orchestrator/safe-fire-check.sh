#!/usr/bin/env bash
# Verify safe-fire isolation before running an atomic.
#
# Checks (all must pass):
#   1. Both VMs reachable on sandbox-net IPs from the Mac host
#   2. Each VM has NO default route (no path off sandbox-net)
#   3. Each VM cannot resolve a public DNS name
#   4. Each VM cannot reach 8.8.8.8
#   5. (warning only) pfctl rules state -- atomics need pfctl disabled
#      for SSH to work; the warning reminds you to re-enable on done.

set -euo pipefail

WIN_IP=${SANDBOX_WIN_IP:-192.168.66.10}
LNX_IP=${SANDBOX_LNX_IP:-192.168.66.20}
SSH_KEY=${SANDBOX_SSH_KEY:-$HOME/.ssh/blue-bench-sandbox.key}

fail() {
    echo "FAIL: $1" >&2
    return 1
}
ok() {
    echo "OK:   $1"
}

# --- 1. reachability -------------------------------------------------

if ! ping -W 2 -c 1 "$WIN_IP" >/dev/null 2>&1; then
    fail "Windows VM $WIN_IP not reachable from Mac host" || exit 1
fi
ok "Windows VM $WIN_IP reachable"

if ! ping -W 2 -c 1 "$LNX_IP" >/dev/null 2>&1; then
    fail "Linux VM $LNX_IP not reachable from Mac host" || exit 1
fi
ok "Linux VM $LNX_IP reachable"

# --- 2. Linux-side default route + egress probes --------------------

lnx_ssh() { ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=4 \
                -o StrictHostKeyChecking=accept-new \
                "analyst@$LNX_IP" "$@"; }

if lnx_ssh "ip route show default" | grep -qE "default via "; then
    fail "Linux VM has a default route -- isolation broken" || exit 1
fi
ok "Linux VM has NO default route"

if lnx_ssh "timeout 3 ping -W 2 -c 1 8.8.8.8" >/dev/null 2>&1; then
    fail "Linux VM can reach 8.8.8.8 -- isolation broken" || exit 1
fi
ok "Linux VM CANNOT reach 8.8.8.8"

if lnx_ssh "timeout 3 nslookup google.com 1.1.1.1" >/dev/null 2>&1; then
    fail "Linux VM can resolve via public DNS -- isolation broken" || exit 1
fi
ok "Linux VM CANNOT resolve via public DNS"

# --- 3. Windows-side default route + egress probes ------------------

win_ssh() { ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=4 \
                -o StrictHostKeyChecking=accept-new \
                "analyst@$WIN_IP" "$@"; }

# Windows OpenSSH defaults to PowerShell as the shell.
default_route=$(win_ssh 'Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count' || true)
if [[ "${default_route:-0}" != "0" ]]; then
    fail "Windows VM has a default route -- isolation broken" || exit 1
fi
ok "Windows VM has NO default route"

# Windows TCP probe to 8.8.8.8:53 should timeout/fail.
win_egress=$(win_ssh 'Test-NetConnection 8.8.8.8 -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue' 2>/dev/null || echo False)
if [[ "$win_egress" == *True* ]]; then
    fail "Windows VM can reach 8.8.8.8:53 -- isolation broken" || exit 1
fi
ok "Windows VM CANNOT reach 8.8.8.8:53"

# --- 4. cross-VM connectivity ---------------------------------------

if ! lnx_ssh "ping -W 2 -c 1 $WIN_IP" >/dev/null 2>&1; then
    fail "Linux VM cannot reach Windows VM -- tap won't see Windows traffic" || exit 1
fi
ok "Linux VM ↔ Windows VM (tap will see traffic)"

# --- 5. pfctl reminder (Mac side) -----------------------------------

if sudo -n pfctl -s rules 2>/dev/null | grep -q '192.168.66.0/24'; then
    if sudo -n pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
        echo "WARN: pfctl rules for sandbox-net are loaded AND enabled."
        echo "      SSH into VMs will fail until you run: sudo pfctl -d"
        echo "      Re-enable after harvest: sudo pfctl -e"
    else
        echo "INFO: pfctl rules loaded but disabled (this is what you want during a run)"
    fi
else
    echo "INFO: no pfctl sandbox-net rules detected. UTM isolation is the primary"
    echo "      control; pfctl is belt-and-suspenders."
fi

echo ""
echo "SAFE-FIRE OK -- ready to run atomics."
