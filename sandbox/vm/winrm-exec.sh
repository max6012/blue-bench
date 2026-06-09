#!/usr/bin/env bash
# Run a PowerShell command inside the loopback-forwarded Windows
# guest over WinRM. Reads the script body from stdin OR a file
# (-f <path>); streams stdout + stderr to the Mac terminal.
#
# Idiomatic-but-thin: this is the only place that knows about the
# WinRM endpoint + credentials, so callers (deploy-tooling.sh,
# fire-and-harvest.sh) stay focused on what to run, not how to
# reach the guest.
#
# Usage:
#   echo 'Get-Process | Select-Object -First 5' | ./winrm-exec.sh
#   ./winrm-exec.sh -f deploy-sysmon.ps1
#   ./winrm-exec.sh -c 'Write-Host hello'

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Endpoint pinned to QEMU's hostfwd. Reaching anywhere else over
# basic-auth + cleartext is a security mistake; the script will
# refuse a non-loopback host below.
WINRM_HOST="${BB_SANDBOX_WINRM_HOST:-127.0.0.1}"
WINRM_PORT="${BB_SANDBOX_WINRM_PORT:-5985}"
WINRM_USER="${BB_SANDBOX_WINRM_USER:-sandbox}"
WINRM_PASS="${BB_SANDBOX_WINRM_PASS:-Sb!4-bench-2026}"

# Hard refuse non-loopback hosts -- basic+cleartext over a real
# network would leak the password. If a future use needs remote
# WinRM, switch to HTTPS+Kerberos first.
case "$WINRM_HOST" in
    127.0.0.1|localhost|::1) ;;
    *)
        echo "ABORT: winrm-exec.sh refuses non-loopback host '$WINRM_HOST'." >&2
        echo "       basic-auth + AllowUnencrypted is loopback-only." >&2
        exit 1
        ;;
esac

PWSH="${BB_SANDBOX_PWSH:-/usr/local/bin/pwsh-preview}"
if [[ ! -x $PWSH ]]; then
    # Fallback search -- a future stable PowerShell install would
    # land at /usr/local/bin/pwsh.
    for cand in /usr/local/bin/pwsh /opt/homebrew/bin/pwsh /opt/homebrew/bin/pwsh-preview; do
        [[ -x $cand ]] && PWSH=$cand && break
    done
fi
if [[ ! -x $PWSH ]]; then
    echo "ABORT: pwsh / pwsh-preview not found. Install via:" >&2
    echo "         brew install --cask powershell@preview" >&2
    exit 1
fi

# Parse args.
script_body=""
mode="stdin"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)   script_body="$(cat "$2")"; mode="file=$2";  shift 2 ;;
        -c|--command) script_body="$2";         mode="inline";   shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0"
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

# Drive Invoke-Command from pwsh-on-Mac. Trust this loopback URL
# explicitly so PSRemoting doesn't bounce on Kerberos lookup.
# -AllowRedirection and -SkipCNCheck NOT used; loopback URL has no
# CN to check.
"$PWSH" -NoProfile -NonInteractive -Command "
\$user = '$WINRM_USER'
\$pass = ConvertTo-SecureString '$WINRM_PASS' -AsPlainText -Force
\$cred = [pscredential]::new(\$user, \$pass)
\$so   = New-PSSessionOption -OpenTimeout 60000 -OperationTimeout 7200000 -IdleTimeout 600000

# Trust the loopback host for basic auth + HTTP.
\$null = winrm set winrm/config/client/auth '@{Basic=\"true\"}' 2>&1
\$null = winrm set winrm/config/client '@{TrustedHosts=\"$WINRM_HOST\"}' 2>&1 || true

\$session = New-PSSession -ComputerName '$WINRM_HOST' -Port $WINRM_PORT \`
                         -Credential \$cred -Authentication Basic \`
                         -SessionOption \$so -ErrorAction Stop
try {
    \$body = @'
$script_body
'@
    Invoke-Command -Session \$session -ScriptBlock {
        param(\$body)
        \$ErrorActionPreference = 'Stop'
        Invoke-Expression \$body
    } -ArgumentList \$body
} finally {
    Remove-PSSession \$session
}
"
