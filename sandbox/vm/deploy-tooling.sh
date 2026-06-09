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
SSH_EXEC="$HERE/ssh-exec.sh"
SYSMON_CONFIG="$REPO_ROOT/sandbox/workflow/sysmon-config.xml"

if [[ ! -x $SSH_EXEC ]]; then
    echo "ABORT: $SSH_EXEC not executable" >&2; exit 1
fi
if [[ ! -f $SYSMON_CONFIG ]]; then
    echo "ABORT: $SYSMON_CONFIG not found" >&2; exit 1
fi

echo "=== Phase 1: push sysmon-config.xml into guest ==="
SYSMON_B64=$(base64 < "$SYSMON_CONFIG" | tr -d '\n')

"$SSH_EXEC" <<PS1
\$ErrorActionPreference = 'Stop'
\$b64 = '${SYSMON_B64}'
\$xml = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\$b64))
\$out = 'C:\sandbox\sysmon-config.xml'
New-Item -ItemType Directory -Path 'C:\sandbox' -Force | Out-Null
Set-Content -Path \$out -Value \$xml -Encoding UTF8
Write-Host ("sysmon-config.xml landed at " + \$out + " (" + (Get-Item \$out).Length + " bytes)")
PS1

echo
echo "=== Phase 2: install Sysmon ==="
# TLS 1.2 forced -- Win PowerShell 5.1 defaults to SystemDefault,
# which can negotiate TLS 1.0/1.1 that sysinternals/GitHub reject.
# Start-Process -Wait (not the & call operator): over an SSH-driven
# powershell session, & launched the installer without blocking, so
# the service-status check raced an install that hadn't happened.
"$SSH_EXEC" <<'PS2'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dst = 'C:\sandbox\Sysmon64.exe'
if (-not (Test-Path $dst)) {
    Write-Host 'Downloading Sysmon64 from sysinternals...'
    Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' -OutFile $dst -UseBasicParsing
}
$p = Start-Process -FilePath $dst -ArgumentList '-accepteula','-i','C:\sandbox\sysmon-config.xml' -Wait -PassThru -NoNewWindow
Write-Host ("Sysmon installer exit: " + $p.ExitCode)
Start-Sleep -Seconds 4
Get-Service Sysmon64 | Format-List Status, StartType
PS2

echo
echo "=== Phase 3: install Atomic Red Team ==="
# Pre-install the NuGet provider + powershell-yaml NON-interactively
# first. Install-AtomicRedTeam's own 'Installing powershell-yaml'
# step calls Install-Module, which over a non-interactive SSH
# session hits a ShouldContinue prompt and dies with "Object
# reference not set to an instance of an object" -- masked by the
# installer's generic "Installation of AtomicRedTeam Failed."
"$SSH_EXEC" <<'PS3'
$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name powershell-yaml -Force -Scope AllUsers
$installer = Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing
Invoke-Expression $installer.Content
Install-AtomicRedTeam -getAtomics -Force
Write-Host ("atomics present (T1059.001): " + (Test-Path C:\AtomicRedTeam\atomics\T1059.001\T1059.001.yaml))
PS3

echo
echo "=== Phase 4: verify Sysmon EID 1 fires ==="
"$SSH_EXEC" <<'PS4'
$ErrorActionPreference = 'Stop'
# Trigger a process-create event.
Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','Start-Sleep 1' -NoNewWindow -Wait
Start-Sleep -Seconds 3
$since = (Get-Date).AddMinutes(-1)
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = $since
} -ErrorAction SilentlyContinue
if ($events.Count -ge 1) {
    Write-Host ("OK: Sysmon EID 1 fired " + $events.Count + " times in last minute")
} else {
    Write-Error 'Sysmon EID 1 did NOT fire in last minute -- Sysmon may not be running correctly'
    exit 1
}
PS4

echo
echo "=== Phase 5: ready to snapshot (AWS) ==="
cat <<'HINT'
Sysmon + ART installed + verified. To bake a tooled AMI (so future
captures launch pre-tooled instead of re-running this deploy):

  source sandbox/vm/aws-resources.env
  aws ec2 create-image --region "$AWS_REGION" --instance-id "$WIN_INSTANCE_ID" \
    --name "bb-sandbox-win-tooled-$(date +%Y%m%d)" --no-reboot

Stop the instance when idle to halt billing:
  aws ec2 stop-instances --region "$AWS_REGION" --instance-ids "$WIN_INSTANCE_ID"
HINT
