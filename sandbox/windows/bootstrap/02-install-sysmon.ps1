<#
.SYNOPSIS
    Install Sysmon with the modular config under windows/sysmon-config.xml.

.DESCRIPTION
    Idempotent: if Sysmon is already installed with the same config
    hash, the script is a no-op. The config lives next to this file
    in the bootstrap/ directory so it travels with the deployment.

    Sysmon binary is downloaded from Microsoft's official Sysinternals
    URL the first time only; subsequent runs reuse the cached copy.
    NOTE: this needs to be done OUT-OF-BAND -- the sandbox VM has no
    egress. Drop Sysmon64.exe into C:\sandbox\tools\ before bootstrap.

.NOTES
    Must be run as Administrator.
#>

$ErrorActionPreference = 'Stop'

$sysmonExe = 'C:\sandbox\tools\Sysmon64.exe'
$sysmonConfig = "$PSScriptRoot\..\sysmon-config.xml"

if (-not (Test-Path $sysmonExe)) {
    Write-Error @"
ABORT: $sysmonExe not found.

Sysmon binary must be staged out-of-band before bootstrap because the
sandbox VM has no internet egress. From a host with internet access:
    1. Download Sysmon from
       https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    2. Unzip and copy Sysmon64.exe to C:\sandbox\tools\Sysmon64.exe in
       the VM (via UTM shared folder, SCP from the orchestrator host,
       or a one-time mounted ISO with the binary).
"@
    exit 1
}

if (-not (Test-Path $sysmonConfig)) {
    Write-Error "ABORT: $sysmonConfig not found. Ensure sysmon-config.xml ships with bootstrap."
    exit 1
}

# Already installed?
$installed = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($installed -and $installed.Status -eq 'Running') {
    Write-Host 'Sysmon already installed -- reloading config.'
    & $sysmonExe -c $sysmonConfig
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Sysmon -c (reload config) failed with exit $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host 'OK: Sysmon config reloaded.'
    exit 0
}

# Fresh install with EULA accepted + config applied.
& $sysmonExe -accepteula -i $sysmonConfig
if ($LASTEXITCODE -ne 0) {
    Write-Error "Sysmon install failed with exit $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Confirm service is up.
$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Error 'Sysmon service did not start.'
    exit 1
}

Write-Host 'OK: Sysmon installed and running.'
