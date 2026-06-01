<#
.SYNOPSIS
    Bundle captured telemetry from the GHA runner into ./harvest/
    so the workflow's upload-artifact step picks it up.

.DESCRIPTION
    Outputs under ./harvest/<run_id>/ relative to the workflow
    working directory:

        windows/Security.evtx
        windows/System.evtx
        windows/Sysmon.evtx
        windows/PowerShell.evtx
        windows/WMI.evtx
        windows/TaskScheduler.evtx
        windows/transcripts/*.txt
        windows/sysmon-archive/*           (raw files Sysmon archived)
        manifest.json                      (per-file sha256 + sizes)

    The orchestrator's harvest-from-run.sh downloads this artifact
    into data/raw/sandbox/<run_id>/ locally.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RunId
)

$ErrorActionPreference = 'Stop'

$outRoot = Join-Path $PWD "harvest\$RunId"
$winDir  = Join-Path $outRoot 'windows'
New-Item -ItemType Directory -Path $winDir -Force | Out-Null

# --- EVTX exports -------------------------------------------------

$channels = @{
    'Security'                                  = "$winDir\Security.evtx"
    'System'                                    = "$winDir\System.evtx"
    'Microsoft-Windows-Sysmon/Operational'      = "$winDir\Sysmon.evtx"
    'Microsoft-Windows-PowerShell/Operational'  = "$winDir\PowerShell.evtx"
    'Microsoft-Windows-WMI-Activity/Operational' = "$winDir\WMI.evtx"
    'Microsoft-Windows-TaskScheduler/Operational' = "$winDir\TaskScheduler.evtx"
}

foreach ($ch in $channels.Keys) {
    $dest = $channels[$ch]
    Write-Host "  EVTX: $ch -> $(Split-Path -Leaf $dest)"
    & wevtutil.exe epl $ch $dest /ow:true
}

# --- PowerShell transcripts --------------------------------------

if (Test-Path 'C:\sandbox-transcripts') {
    $tDest = Join-Path $winDir 'transcripts'
    New-Item -ItemType Directory -Path $tDest -Force | Out-Null
    Copy-Item -Path 'C:\sandbox-transcripts\*' -Destination $tDest -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Sysmon archive directory (FileCreate-tracked drops) ---------

$sysArchive = "$env:SystemRoot\Sysmon"
if (Test-Path $sysArchive) {
    $aDest = Join-Path $winDir 'sysmon-archive'
    New-Item -ItemType Directory -Path $aDest -Force | Out-Null
    Copy-Item -Path "$sysArchive\*" -Destination $aDest -Recurse -Force -ErrorAction SilentlyContinue
}

# --- manifest with per-file sha256 -------------------------------

$files = Get-ChildItem -Path $outRoot -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' }
$manifest = @{
    schema_version  = 1
    run_id          = $RunId
    harvested_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    gha_run_id       = $env:GITHUB_RUN_ID
    gha_run_url      = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
    files           = @()
    total_bytes     = 0
}

foreach ($f in $files | Sort-Object FullName) {
    $rel = $f.FullName.Substring($outRoot.Length + 1).Replace('\','/')
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
    $manifest.files += @{
        path   = $rel
        bytes  = $f.Length
        sha256 = $hash
    }
    $manifest.total_bytes += $f.Length
}

$manifestPath = Join-Path $outRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host ""
Write-Host "OK: harvest -> $outRoot"
Write-Host "    $($manifest.files.Count) files, $($manifest.total_bytes) bytes"
