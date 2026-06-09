#!/usr/bin/env bash
# Boot the baseline qcow2 produced by install-windows.sh. No
# install ISOs attached -- this is the "Windows is already
# installed, just power it on" path used by t-guest-tooling for
# the Sysmon/ART deploy phase, and (later) by fire-and-harvest.sh
# for per-capture runs (against a CLONED baseline).
#
# Usage:
#   ./boot-vm.sh                      # boot the baseline qcow2 in place
#   ./boot-vm.sh /path/to/clone.qcow2 # boot a specific qcow2
#
# Polls WinRM until reachable; emits the QEMU pid + timing to
# perf-timings-boot.json. Caller is responsible for shutting the
# VM down when finished (via the monitor socket or shutdown over
# WinRM).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VM_DIR="${BB_SANDBOX_VM_DIR:-$HOME/Library/Application Support/bb-sandbox-vm}"
DEFAULT_QCOW="$VM_DIR/bb-sandbox-win11-baseline.qcow2"
QCOW="${1:-$DEFAULT_QCOW}"

CPU=4
RAM=8192
WINRM_PORT=5985
VNC_DISPLAY=0
VNC_PORT=5900

if [[ ! -f $QCOW ]]; then
    echo "ABORT: qcow2 not found at $QCOW" >&2
    echo "       Run install-windows.sh first." >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ABORT: qemu-system-x86_64 not on PATH." >&2; exit 1
fi
if pgrep -f "qemu-system-x86_64.*$QCOW" >/dev/null; then
    echo "ABORT: QEMU is already running on $QCOW" >&2; exit 1
fi

OVMF="$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-x86_64-code.fd"
OVMF_VARS="$VM_DIR/edk2-vars.fd"
if [[ ! -f $OVMF_VARS ]]; then
    echo "ABORT: OVMF vars not found at $OVMF_VARS (install-windows.sh should have created it)" >&2
    exit 1
fi

echo "Booting $QCOW (no install ISOs)..."
start_ts=$(date +%s)

qemu-system-x86_64 \
    -accel tcg \
    -machine q35 \
    -cpu max \
    -smp "$CPU" \
    -m "$RAM" \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF" \
    -drive "if=pflash,format=raw,file=$OVMF_VARS" \
    -drive "file=$QCOW,if=none,id=hd0,format=qcow2" \
    -device "ide-hd,drive=hd0,bus=ide.0,bootindex=1" \
    -netdev "user,id=net0,hostfwd=tcp::${WINRM_PORT}-:5985" \
    -device "e1000e,netdev=net0" \
    -display none \
    -vnc "127.0.0.1:${VNC_DISPLAY}" \
    -monitor "unix:$VM_DIR/qemu-monitor.sock,server,nowait" \
    -pidfile "$VM_DIR/qemu.pid" \
    &
qemu_pid=$!

if [[ -x "/Applications/TigerVNC.app/Contents/MacOS/vncviewer" ]]; then
    # Wait for VNC bind, then open the viewer.
    for _ in $(seq 1 20); do
        nc -z 127.0.0.1 "$VNC_PORT" 2>/dev/null && break
        sleep 0.5
    done
    /Applications/TigerVNC.app/Contents/MacOS/vncviewer "127.0.0.1:${VNC_PORT}" &
fi

echo "Polling WinRM on localhost:$WINRM_PORT (up to 10 minutes)..."
deadline=$(( $(date +%s) + 600 ))
winrm_ready=0
while (( $(date +%s) < deadline )); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        echo "ABORT: QEMU pid $qemu_pid exited unexpectedly." >&2; exit 1
    fi
    if nc -z -G 2 localhost "$WINRM_PORT" 2>/dev/null; then
        if curl -s --max-time 5 -X POST "http://localhost:$WINRM_PORT/wsman" \
              -H "Content-Type: application/soap+xml" >/dev/null 2>&1; then
            winrm_ready=1; break
        fi
    fi
    sleep 10
done

end_ts=$(date +%s)
elapsed=$(( end_ts - start_ts ))

if [[ $winrm_ready -eq 0 ]]; then
    echo "ABORT: WinRM never came up in $((elapsed/60)) minutes" >&2
    echo "       QEMU pid $qemu_pid still running -- shut down via:" >&2
    echo "         echo system_powerdown | nc -U '$VM_DIR/qemu-monitor.sock'" >&2
    exit 1
fi

cat > "$HERE/perf-timings-boot.json" <<EOF
{
  "phase": "boot-baseline",
  "qcow2_path": "$QCOW",
  "boot_to_winrm_seconds": $elapsed,
  "boot_to_winrm_minutes": $(printf '%.1f' $(bc <<<"scale=1; $elapsed/60")),
  "qemu_pid": $qemu_pid,
  "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "OK: WinRM reachable after ${elapsed}s ($(printf '%.1f' $(bc <<<"scale=1; $elapsed/60"))min)"
echo "Timings -> $HERE/perf-timings-boot.json"
echo "QEMU pid: $qemu_pid"
echo "Shut down via: echo system_powerdown | nc -U '$VM_DIR/qemu-monitor.sock'"
