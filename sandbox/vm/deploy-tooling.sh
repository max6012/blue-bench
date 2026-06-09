#!/usr/bin/env bash
# Deploy Sysmon + Atomic Red Team into the running baseline VM via
# WinRM. The VM must already be booted (boot-vm.sh) and WinRM
# reachable on 127.0.0.1:5985.
#
# Sequence:
#   1. Push sandbox/workflow/sysmon-config.xml into the guest.
#   2. Download Sysmon64 from sysinternals; install with the config.
#   3. Install Invoke-AtomicRedTeam + the atomics repo.
#   4. Verify Sysmon EID 1 fires on a Get-Process probe.
#   5. Caller (or a follow-up step) issues system_powerdown and
#      takes a qcow2 snapshot named 'tooled'.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WINRM_EXEC="$HERE/winrm-exec.sh"
SYSMON_CONFIG="$REPO_ROOT/sandbox/workflow/sysmon-config.xml"

if [[ ! -x $WINRM_EXEC ]]; then
    echo "ABORT: $WINRM_EXEC not executable" >&2; exit 1
fi
if [[ ! -f $SYSMON_CONFIG ]]; then
    echo "ABORT: $SYSMON_CONFIG not found" >&2; exit 1
fi

echo "=== Phase 1: push sysmon-config.xml into guest ==="
# Encode the XML to base64 to avoid quoting nightmares over WinRM.
SYSMON_B64=$(base64 < "$SYSMON_CONFIG" | tr -d '\n')

"$WINRM_EXEC" -c "
\$ErrorActionPreference = 'Stop'
\$b64 = '$SYSMON_B64'
\$xml = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\$b64))
\$out = 'C:\sandbox\sysmon-config.xml'
New-Item -ItemType Directory -Path 'C:\sandbox' -Force | Out-Null
Set-Content -Path \$out -Value \$xml -Encoding UTF8
Write-Host \"sysmon-config.xml landed at \$out (\$((Get-Item \$out).Length) bytes)\"
"

echo
echo "=== Phase 2: install Sysmon ==="
"$WINRM_EXEC" -c "
\$ErrorActionPreference = 'Stop'
\$dst = 'C:\sandbox\Sysmon64.exe'
if (-not (Test-Path \$dst)) {
    Write-Host 'Downloading Sysmon64 from sysinternals...'
    Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' `
                      -OutFile \$dst -UseBasicParsing
}
& \$dst -accepteula -i 'C:\sandbox\sysmon-config.xml'
Start-Sleep -Seconds 5
Get-Service Sysmon64 | Format-List Status, StartType
"

echo
echo "=== Phase 3: install Atomic Red Team ==="
"$WINRM_EXEC" -c "
\$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy Bypass -Scope Process -Force
\$installer = Invoke-WebRequest `
    'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' `
    -UseBasicParsing
Invoke-Expression \$installer.Content
Install-AtomicRedTeam -getAtomics -Force
Get-Module -ListAvailable Invoke-AtomicRedTeam | Format-List Name, Version, Path
"

echo
echo "=== Phase 4: verify Sysmon EID 1 fires ==="
"$WINRM_EXEC" -c "
\$ErrorActionPreference = 'Stop'
# Generate a process-create event by spawning a short-lived child.
Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','Start-Sleep 1' -NoNewWindow -Wait
Start-Sleep -Seconds 3
# Count Sysmon EID 1 events in the last minute. Should be >=1
# (the powershell.exe we just spawned).
\$since = (Get-Date).AddMinutes(-1)
\$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = \$since
} -ErrorAction SilentlyContinue
if (\$events.Count -ge 1) {
    Write-Host \"OK: Sysmon EID 1 fired \$(\$events.Count) times in last minute\"
} else {
    Write-Error \"Sysmon EID 1 did NOT fire in last minute -- Sysmon may not be running correctly\"
    exit 1
}
"

echo
echo "=== Phase 5: ready for snapshot ==="
echo "Sysmon + ART installed. To snapshot the tooled state:"
echo "  echo system_powerdown | nc -U '\$HOME/Library/Application Support/bb-sandbox-vm/qemu-monitor.sock'"
echo "  # (wait for QEMU to exit)"
echo "  qemu-img snapshot -c tooled '\$HOME/Library/Application Support/bb-sandbox-vm/bb-sandbox-win11-baseline.qcow2'"
