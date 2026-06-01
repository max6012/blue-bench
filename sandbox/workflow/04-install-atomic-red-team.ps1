<#
.SYNOPSIS
    Install Atomic Red Team + Invoke-AtomicRedTeam on the GHA runner.

.DESCRIPTION
    Fetches both repos from GitHub via raw zipball URLs. The runner has
    internet egress; no out-of-band staging required.

    Pinned to redcanaryco's master branches at fetch time. For
    reproducibility across days, replace 'master' with a tag/SHA once
    you've picked a baseline (recommended after the first acceptance
    run).
#>

$ErrorActionPreference = 'Stop'

$artRoot = 'C:\AtomicRedTeam'
$artZip  = "$env:TEMP\atomic-red-team.zip"
$iarZip  = "$env:TEMP\invoke-atomicredteam.zip"

New-Item -ItemType Directory -Path $artRoot -Force | Out-Null

# --- atomic-red-team repo (technique catalogue) -----------------------

if (-not (Test-Path "$artRoot\atomics")) {
    Write-Host 'Downloading atomic-red-team repo...'
    Invoke-WebRequest `
        -Uri 'https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip' `
        -OutFile $artZip -UseBasicParsing
    Expand-Archive -Path $artZip -DestinationPath $artRoot -Force

    # The zip extracts to atomic-red-team-master\; normalise atomics\.
    $extracted = Get-ChildItem -Path $artRoot -Directory -Filter 'atomic-red-team-*' | Select-Object -First 1
    if ($extracted) {
        $atomicsSrc = Join-Path $extracted.FullName 'atomics'
        if (Test-Path $atomicsSrc) {
            Move-Item -Path $atomicsSrc -Destination "$artRoot\atomics" -Force
        }
    }
}

# --- invoke-atomicredteam module --------------------------------------

$iarRoot = "$artRoot\invoke-atomicredteam"
if (-not (Test-Path "$iarRoot\Invoke-AtomicRedTeam.psd1")) {
    Write-Host 'Downloading invoke-atomicredteam module...'
    Invoke-WebRequest `
        -Uri 'https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/heads/master.zip' `
        -OutFile $iarZip -UseBasicParsing
    Expand-Archive -Path $iarZip -DestinationPath $artRoot -Force

    $extracted = Get-ChildItem -Path $artRoot -Directory -Filter 'invoke-atomicredteam-*' | Select-Object -First 1
    if ($extracted -and $extracted.FullName -ne $iarRoot) {
        # Find the actual psd1 location -- the module sometimes lives one level deeper.
        $psd1 = Get-ChildItem -Path $extracted.FullName -Filter 'Invoke-AtomicRedTeam.psd1' -Recurse | Select-Object -First 1
        if ($psd1) {
            Move-Item -Path $psd1.Directory.FullName -Destination $iarRoot -Force
        } else {
            Move-Item -Path $extracted.FullName -Destination $iarRoot -Force
        }
    }
}

# --- import + smoke test ----------------------------------------------

$psd1 = Get-ChildItem -Path $iarRoot -Filter 'Invoke-AtomicRedTeam.psd1' -Recurse | Select-Object -First 1
if (-not $psd1) {
    Write-Error "ABORT: Invoke-AtomicRedTeam.psd1 not found under $iarRoot"
    exit 1
}

Import-Module $psd1.FullName -Force

[System.Environment]::SetEnvironmentVariable('PSAtomicsFolder', "$artRoot\atomics", 'Machine')
$env:PSAtomicsFolder = "$artRoot\atomics"

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Write-Error 'Invoke-AtomicTest command not available after module import.'
    exit 1
}

Write-Host 'OK: Atomic Red Team installed; Invoke-AtomicTest available.'
