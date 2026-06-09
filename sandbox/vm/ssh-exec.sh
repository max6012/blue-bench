#!/usr/bin/env bash
# Run a PowerShell snippet inside the loopback-forwarded Windows
# guest over SSH. Replaces the earlier winrm-exec.sh, which failed
# because pwsh on macOS has no WSMan client library.
#
# Reads the script body from stdin OR a file (-f <path>) OR a
# literal (-c <cmd>); streams stdout + stderr to the Mac terminal.
#
# Usage:
#   echo 'Get-Process | Select-Object -First 5' | ./ssh-exec.sh
#   ./ssh-exec.sh -f deploy-sysmon.ps1
#   ./ssh-exec.sh -c 'Write-Host hello'

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

SSH_HOST="${BB_SANDBOX_SSH_HOST:-127.0.0.1}"
SSH_PORT="${BB_SANDBOX_SSH_PORT:-2222}"
SSH_USER="${BB_SANDBOX_SSH_USER:-sandbox}"
SSH_KEY="${BB_SANDBOX_SSH_KEY:-$HOME/.ssh/bb-sandbox-ed25519}"

# Loopback (QEMU-local) and the AWS substrate are both fine:
# auth is ed25519 key-only, and the AWS host is reachable only
# from the operator IP via the bb-sandbox security group. The
# earlier hard loopback-only guard dated from the WinRM
# basic-auth+cleartext era, which no longer applies. To allow an
# explicit non-loopback host, set BB_SANDBOX_ALLOW_REMOTE=1.
case "$SSH_HOST" in
    127.0.0.1|localhost|::1) ;;
    *)
        if [[ "${BB_SANDBOX_ALLOW_REMOTE:-0}" != "1" ]]; then
            echo "ABORT: ssh-exec.sh refuses non-loopback host '$SSH_HOST'." >&2
            echo "       Set BB_SANDBOX_ALLOW_REMOTE=1 to allow (AWS substrate)." >&2
            exit 1
        fi
        ;;
esac

if [[ ! -f $SSH_KEY ]]; then
    echo "ABORT: SSH key $SSH_KEY missing." >&2
    exit 1
fi

# Parse args.
script_body=""
mode="stdin"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)    script_body="$(cat "$2")"; mode="file=$2"; shift 2 ;;
        -c|--command) script_body="$2";          mode="inline";  shift 2 ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
if [[ -z $script_body && $mode == "stdin" ]]; then
    script_body="$(cat)"
fi
if [[ -z $script_body ]]; then
    echo "ABORT: no script body (stdin empty, no -f/-c)." >&2
    exit 1
fi

# Pipe the PowerShell body to powershell.exe -Command -. Default
# shell in the guest is powershell.exe (set by autounattend's
# HKLM:\SOFTWARE\OpenSSH\DefaultShell). Reading from stdin is the
# friendliest path for multi-line scripts -- avoids escape
# explosions in the ssh argv.
ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -p "$SSH_PORT" \
    "${SSH_USER}@${SSH_HOST}" \
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command -' <<< "$script_body"
