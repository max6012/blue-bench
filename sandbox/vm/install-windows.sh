#!/usr/bin/env bash
# Drive an unattended Windows 11 install under QEMU on macOS arm64.
# Reads autounattend.iso (built by build-unattended-iso.sh) +
# the user-supplied Win11 ISO; produces bb-sandbox-win11-baseline.qcow2
# in the VM image dir; polls WinRM until reachable; emits per-phase
# wall-clock to perf-timings.json.
#
# Usage:
#   ./install-windows.sh /path/to/Win11_23H2_English_x64.iso
#
# Idempotency: if the baseline qcow2 already exists, refuses to
# overwrite. Delete it explicitly to re-install.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# VM image dir lives OUTSIDE the repo. qcow2 baselines are
# env-specific + multi-GB and never belong in git.
VM_DIR="${BB_SANDBOX_VM_DIR:-$HOME/Library/Application Support/bb-sandbox-vm}"
BASELINE_QCOW="$VM_DIR/bb-sandbox-win11-baseline.qcow2"
UNATTEND_ISO="$HERE/autounattend.iso"
TIMINGS="$HERE/perf-timings.json"

# QEMU resources -- match runbook config (4 CPU, 8 GB, 80 GB disk).
CPU=4
RAM=8192
DISK_SIZE=80G
WINRM_PORT=5985

# VNC is the display channel. -display cocoa fails when QEMU is
# launched from a non-UI-context shell -- the window exists but
# never surfaces in the Dock. VNC decouples the viewer process from
# the QEMU process so launch context doesn't matter; we open
# vnc://127.0.0.1:5900 from the script after QEMU comes up.
VNC_PORT=5900
VNC_DISPLAY=0   # VNC :0 -> TCP/5900

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <path-to-Win11-iso>" >&2
    exit 1
fi
WIN_ISO="$1"

# ---- preflight ----------------------------------------------------
if [[ ! -f $WIN_ISO ]]; then
    echo "ABORT: Windows ISO not found at $WIN_ISO" >&2
    exit 1
fi
if [[ ! -f $UNATTEND_ISO ]]; then
    echo "ABORT: autounattend.iso missing. Run build-unattended-iso.sh first." >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ABORT: qemu-system-x86_64 not on PATH. brew install qemu." >&2
    exit 1
fi
if [[ -f $BASELINE_QCOW ]]; then
    echo "ABORT: $BASELINE_QCOW already exists." >&2
    echo "       Delete it explicitly to re-run the install:" >&2
    echo "         rm '$BASELINE_QCOW'" >&2
    exit 1
fi

mkdir -p "$VM_DIR"

# OVMF firmware for UEFI boot (Windows 11 requires UEFI).
OVMF="$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-x86_64-code.fd"
OVMF_VARS_TEMPLATE="$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-i386-vars.fd"
OVMF_VARS="$VM_DIR/edk2-vars.fd"
if [[ ! -f $OVMF ]]; then
    echo "ABORT: OVMF firmware not found at $OVMF" >&2
    exit 1
fi
cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"

# ---- create the qcow2 baseline ------------------------------------
echo "Creating qcow2 baseline at $BASELINE_QCOW ($DISK_SIZE)..."
qemu-img create -f qcow2 "$BASELINE_QCOW" "$DISK_SIZE"

# ---- launch QEMU --------------------------------------------------
echo "Launching QEMU with Windows ISO + autounattend.iso..."
echo "(install runs unattended; WinRM polls until reachable)"
start_ts=$(date +%s)

# Run QEMU in the background; capture pid so we can shut it down
# politely on success. -nographic keeps the install headless --
# autounattend.xml drives all UI; no operator should need to look.
qemu-system-x86_64 \
    -accel tcg \
    -machine q35 \
    -cpu max \
    -smp "$CPU" \
    -m "$RAM" \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF" \
    -drive "if=pflash,format=raw,file=$OVMF_VARS" \
    -drive "file=$BASELINE_QCOW,if=virtio,format=qcow2" \
    -drive "file=$WIN_ISO,media=cdrom,readonly=on,file.locking=off" \
    -drive "file=$UNATTEND_ISO,media=cdrom,readonly=on,file.locking=off" \
    -netdev "user,id=net0,hostfwd=tcp::${WINRM_PORT}-:5985" \
    -device "virtio-net,netdev=net0" \
    -boot order=d \
    -display none \
    -vnc "127.0.0.1:${VNC_DISPLAY}" \
    -monitor "unix:$VM_DIR/qemu-monitor.sock,server,nowait" \
    -pidfile "$VM_DIR/qemu.pid" \
    &
qemu_pid=$!

# Wait a beat for VNC + monitor socket to bind, then open the
# system's default VNC viewer. macOS Screen Sharing handles no-auth
# VNC fine; the loopback URL means no auth prompt either way.
for _ in $(seq 1 20); do
    if nc -z 127.0.0.1 "$VNC_PORT" 2>/dev/null; then break; fi
    sleep 0.5
done
echo "Opening RealVNC Connect at vnc://127.0.0.1:${VNC_PORT}..."
# Prefer RealVNC Connect (handles anonymous VNC cleanly); fall back
# to the default vnc:// handler if it isn't installed.
if [[ -d "/Applications/RealVNC Connect.app" ]]; then
    open -a "RealVNC Connect" "vnc://127.0.0.1:${VNC_PORT}" || true
else
    open "vnc://127.0.0.1:${VNC_PORT}" || \
        echo "  (could not open vnc:// URL; connect manually)"
fi

# Inject Enter to clear the UEFI "Press any key to boot from CD or
# DVD..." prompt that cdboot.efi displays for ~5s at first power-on.
# Without this keypress, BdsDxe falls through to the next boot entry
# (typically PXE) and the install never starts. Run for ~15s only:
# Windows Setup reboots 1-2x mid-install, and on those reboots the
# CD prompt MUST time out so BdsDxe falls through to the now-bootable
# Windows Boot Manager on the HDD. Spamming Enter beyond the first
# boot would re-enter Setup in a loop.
(
    # Wait a beat for the monitor socket to appear.
    for _ in $(seq 1 20); do
        [[ -S $VM_DIR/qemu-monitor.sock ]] && break
        sleep 0.5
    done
    for _ in $(seq 1 15); do
        printf 'sendkey ret\n' | nc -U "$VM_DIR/qemu-monitor.sock" 2>/dev/null || true
        sleep 1
    done
) &

# ---- poll for WinRM -----------------------------------------------
# Windows OOBE + FirstLogonCommands settles in ~20-40 min under TCG
# on arm64; cap at 90 min before giving up.
echo "Polling WinRM on localhost:$WINRM_PORT (up to 90 minutes)..."
deadline=$(( $(date +%s) + 5400 ))
winrm_ready=0
while (( $(date +%s) < deadline )); do
    # Abort early if QEMU died -- otherwise we spin uselessly until
    # the 90-min deadline. Earlier run did exactly this after a
    # macOS file-lock failure at startup.
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        echo "ABORT: QEMU process $qemu_pid exited unexpectedly." >&2
        echo "       (see prior stderr above for the cause)" >&2
        exit 1
    fi
    if nc -z -G 2 localhost "$WINRM_PORT" 2>/dev/null; then
        # Port is open. Verify it's actually WinRM (not garbage).
        if curl -s --max-time 5 -X POST "http://localhost:$WINRM_PORT/wsman" \
              -H "Content-Type: application/soap+xml" >/dev/null 2>&1; then
            winrm_ready=1
            break
        fi
    fi
    sleep 15
done

end_ts=$(date +%s)
elapsed=$(( end_ts - start_ts ))

if [[ $winrm_ready -eq 0 ]]; then
    echo "ABORT: WinRM never came up in $((elapsed/60)) minutes" >&2
    echo "       qcow2 left at $BASELINE_QCOW for forensics" >&2
    if kill -0 "$qemu_pid" 2>/dev/null; then
        echo "       QEMU pid $qemu_pid still running -- kill manually:" >&2
        echo "         kill $qemu_pid" >&2
    fi
    exit 1
fi

echo "OK: WinRM reachable after ${elapsed}s ($(printf '%.1f' $(bc <<<"scale=1; $elapsed/60"))min)"

# ---- record timing ------------------------------------------------
cat > "$TIMINGS" <<EOF
{
  "phase": "win-install",
  "boot_to_winrm_seconds": $elapsed,
  "boot_to_winrm_minutes": $(printf '%.1f' $(bc <<<"scale=1; $elapsed/60")),
  "qcow2_path": "$BASELINE_QCOW",
  "qcow2_size_bytes": $(stat -f%z "$BASELINE_QCOW"),
  "qemu_version": "$(qemu-system-x86_64 --version | head -1 | awk '{print $4}')",
  "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "Timings -> $TIMINGS"

# ---- shut the guest down politely so the qcow2 is consistent -----
echo "Requesting guest shutdown via QEMU monitor..."
echo "system_powerdown" | nc -U "$VM_DIR/qemu-monitor.sock" &>/dev/null || true

# Wait up to 5 min for clean shutdown; SIGKILL otherwise (qcow2
# corruption risk but caller can rebuild).
for i in $(seq 1 60); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then break; fi
    sleep 5
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    echo "WARN: clean shutdown timed out -- SIGKILL'ing QEMU" >&2
    kill -9 "$qemu_pid" || true
fi

echo
echo "Baseline qcow2 ready: $BASELINE_QCOW"
echo "Next: ./deploy-tooling.sh (t-guest-tooling)"
