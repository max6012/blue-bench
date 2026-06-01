<#
.SYNOPSIS
    Install Sysmon on the GHA runner using the modular config under
    sandbox/workflow/sysmon-config.xml.

.DESCRIPTION
    GHA runners have internet egress, so we fetch Sysmon directly from
    Microsoft. The download is to C:\Sysmon\Sysmon.zip, then unzipped
    and Sysmon64.exe is invoked with -accepteula -i <config>.
#>

$ErrorActionPreference = 'Stop'

$sysmonRoot = 'C:\Sysmon'
$sysmonZip  = "$sysmonRoot\Sysmon.zip"
$sysmonExe  = "$sysmonRoot\Sysmon64.exe"
$configPath = "$PSScriptRoot\sysmon-config.xml"

if (-not (Test-Path $configPath)) {
    Write-Error "ABORT: $configPath not found"
    exit 1
}

New-Item -ItemType Directory -Path $sysmonRoot -Force | Out-Null

if (-not (Test-Path $sysmonExe)) {
    Write-Host 'Downloading Sysmon from Microsoft Sysinternals...'
    # Pinned to the live URL; the Sysinternals binary is stable across
    # minor releases and self-contained.
    Invoke-WebRequest `
        -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
        -OutFile $sysmonZip `
        -UseBasicParsing
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonRoot -Force
    if (-not (Test-Path $sysmonExe)) {
        Write-Error "ABORT: Sysmon64.exe not found at $sysmonExe after extract"
        exit 1
    }
}

# If a previous step already installed Sysmon (re-run), reload config.
$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host 'Sysmon already installed; reloading config.'
    & $sysmonExe -c $configPath
} else {
    Write-Host 'Installing Sysmon with config + accepting EULA...'
    & $sysmonExe -accepteula -i $configPath
}

# Confirm service running.
$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Error 'Sysmon service did not start.'
    exit 1
}

Write-Host 'OK: Sysmon installed and running.'
