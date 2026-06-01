<#
.SYNOPSIS
    Install the Atomic Red Team Invoke-AtomicTest PowerShell module +
    technique repository.

.DESCRIPTION
    The sandbox VM has no internet egress, so the ART payload must be
    staged out-of-band before bootstrap. Drop the ART release zip into
    C:\sandbox\tools\atomic-red-team.zip before running this script.

    Download instructions for an internet-connected host:
        1. Clone https://github.com/redcanaryco/atomic-red-team
           (or download the release zip from the same repo)
        2. Zip the repository contents -> atomic-red-team.zip
        3. Also download the Invoke-AtomicRedTeam module zip from
           https://github.com/redcanaryco/invoke-atomicredteam
           -> invoke-atomicredteam.zip
        4. Copy both zips into C:\sandbox\tools\ inside the VM

.NOTES
    Must be run as Administrator. Idempotent.
#>

$ErrorActionPreference = 'Stop'

$artZip = 'C:\sandbox\tools\atomic-red-team.zip'
$iarZip = 'C:\sandbox\tools\invoke-atomicredteam.zip'
$artRoot = 'C:\AtomicRedTeam'
$iarRoot = 'C:\AtomicRedTeam\invoke-atomicredteam'

foreach ($zip in @($artZip, $iarZip)) {
    if (-not (Test-Path $zip)) {
        Write-Error @"
ABORT: $zip not found.

Stage Atomic Red Team archives out-of-band (no sandbox egress):
  - atomic-red-team.zip          (the technique repo)
  - invoke-atomicredteam.zip     (the PowerShell module)
both under C:\sandbox\tools\.
"@
        exit 1
    }
}

# Idempotent: skip if already installed.
if (Test-Path "$artRoot\atomics") {
    Write-Host 'Atomic Red Team already extracted -- skipping unzip.'
} else {
    Write-Host "Extracting $artZip -> $artRoot ..."
    Expand-Archive -Path $artZip -DestinationPath $artRoot -Force
    # The zip likely contains a top-level "atomic-red-team-master/" or
    # similar; normalise that to $artRoot\atomics\.
    $extracted = Get-ChildItem -Path $artRoot -Directory | Select-Object -First 1
    if ($extracted -and -not (Test-Path "$artRoot\atomics")) {
        $atomicsSrc = Join-Path $extracted.FullName 'atomics'
        if (Test-Path $atomicsSrc) {
            Move-Item -Path $atomicsSrc -Destination "$artRoot\atomics" -Force
        }
    }
}

if (Test-Path "$iarRoot\Invoke-AtomicRedTeam.psd1") {
    Write-Host 'Invoke-AtomicRedTeam module already extracted -- skipping unzip.'
} else {
    Write-Host "Extracting $iarZip -> $iarRoot ..."
    Expand-Archive -Path $iarZip -DestinationPath "$artRoot" -Force
    $extracted = Get-ChildItem -Path $artRoot -Directory -Filter 'invoke*' | Select-Object -First 1
    if ($extracted -and $extracted.Name -ne 'invoke-atomicredteam') {
        Move-Item -Path $extracted.FullName -Destination $iarRoot -Force
    }
}

# Import + smoke test.
$psd1 = Get-ChildItem -Path $iarRoot -Filter 'Invoke-AtomicRedTeam.psd1' -Recurse | Select-Object -First 1
if (-not $psd1) {
    Write-Error "ABORT: Invoke-AtomicRedTeam.psd1 not found under $iarRoot"
    exit 1
}

Import-Module $psd1.FullName -Force

# Set the module's path-to-atomics so Invoke-AtomicTest finds the repo.
$env:PSAtomicsFolder = "$artRoot\atomics"
[System.Environment]::SetEnvironmentVariable('PSAtomicsFolder', "$artRoot\atomics", 'Machine')

$smoke = Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue
if (-not $smoke) {
    Write-Error 'Invoke-AtomicTest command not available after module import.'
    exit 1
}

Write-Host 'OK: Atomic Red Team installed; Invoke-AtomicTest available.'
