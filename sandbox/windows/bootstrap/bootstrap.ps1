<#
.SYNOPSIS
    Top-level Windows VM bootstrap. Runs the numbered scripts in order
    and stops on the first failure.

.DESCRIPTION
    Prerequisites (out-of-band, before this script):
      - VM static IP 192.168.66.10, no default gateway
      - C:\sandbox\tools\Sysmon64.exe staged
      - C:\sandbox\tools\atomic-red-team.zip staged
      - C:\sandbox\tools\invoke-atomicredteam.zip staged
      - C:\Users\analyst\.ssh\authorized_keys staged (orchestrator key)

    Sequence:
      01 disable defender             (BLOCKS network egress as safe-fire)
      02 install Sysmon
      03 enable EventLog channels
      04 install Atomic Red Team
      05 create test accounts
      06 enable + lock down SSH

.NOTES
    Must be run as Administrator from C:\sandbox\bootstrap\ (relative
    paths in the child scripts assume the bootstrap/ working directory).
#>

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Error 'ABORT: bootstrap.ps1 must be run as Administrator.'
    exit 1
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $here

$steps = @(
    '01-disable-defender.ps1',
    '02-install-sysmon.ps1',
    '03-enable-eventlog.ps1',
    '04-install-atomic-red-team.ps1',
    '05-create-test-accounts.ps1',
    '06-enable-ssh.ps1'
)

foreach ($step in $steps) {
    $path = Join-Path $here $step
    if (-not (Test-Path $path)) {
        Write-Error "ABORT: $step not found in $here"
        exit 1
    }
    Write-Host ""
    Write-Host "=== $step ==="
    & $path
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ABORT: $step exited $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "OK: bootstrap complete. Snapshot the VM as 'baseline' before running atomics."
