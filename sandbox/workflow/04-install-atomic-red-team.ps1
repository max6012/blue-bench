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

# --- install module dependencies --------------------------------------

# Invoke-AtomicRedTeam.psd1 declares powershell-yaml as a RequiredModule.
# Import-Module fails with "required module 'powershell-yaml' is not
# loaded" if we skip this. GHA runner has PSGallery access; install
# under CurrentUser scope (no admin elevation needed inside pwsh) and
# pin -Repository PSGallery on the install so the trust-policy change
# actually applies to the source we use. Original policy is restored
# in a finally block so this script doesn't leave the runner with a
# persistent config change.
Write-Host 'Installing powershell-yaml (Invoke-AtomicRedTeam dependency)...'
if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
    # Look up PSGallery safely -- it should always be registered on
    # windows-latest, but Get-PSRepository throws under EAP='Stop' if
    # for some reason it isn't, which would abort the step before any
    # useful diagnostic. Treat absence as a hard error with a clear
    # message instead.
    $psgallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $psgallery) {
        # Write-Error is terminating under EAP='Stop'; no explicit exit
        # needed and adding one would be dead code (same anti-pattern
        # Max flagged on PR #11).
        Write-Error 'PSGallery is not registered on this runner; cannot install powershell-yaml.'
    }
    $previousPolicy = $psgallery.InstallationPolicy

    try {
        if ($previousPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        Install-Module -Name 'powershell-yaml' -Repository PSGallery `
                       -Scope CurrentUser -Force -AllowClobber
    } finally {
        # Restore the original policy so this script doesn't leave the
        # runner's PSGallery trust in a different state than it found
        # it -- matches the comment's "for the duration of the install"
        # contract.
        if ($previousPolicy -and $previousPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy $previousPolicy `
                             -ErrorAction SilentlyContinue
        }
    }
}
# Deliberately NOT pre-importing powershell-yaml here. Step 05 runs in
# a fresh pwsh process and imports Invoke-AtomicRedTeam.psd1 cold,
# triggering auto-import of RequiredModules from disk. If we pre-loaded
# powershell-yaml in *this* step, the psd1 import below would test the
# pre-load path -- a false proxy for what step 05 actually does. By
# leaving auto-import to fire here too, step 04 exercises the exact
# code path step 05 will hit; an auto-import failure surfaces cheaply
# at step 04 instead of step 05.

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
