<#
.SYNOPSIS
    Disable Windows Defender so Atomic Red Team techniques don't get
    blocked at execution time.

.DESCRIPTION
    This is destructive and only acceptable inside the sandbox VM,
    which has no path to the public internet (see network/safe-fire-
    checklist.md). The script aborts if the VM has a default route or
    can resolve a public DNS name -- belt-and-suspenders against
    running on a host that didn't pass the safe-fire gates.

.NOTES
    Must be run as Administrator. The script is idempotent.
#>

$ErrorActionPreference = 'Stop'

# --- safe-fire gate -----------------------------------------------------

if (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) {
    Write-Error "ABORT: VM has a default route. Disable Defender only on an isolated VM."
    exit 1
}

if (Test-NetConnection -ComputerName '8.8.8.8' -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue) {
    Write-Error "ABORT: VM can reach 8.8.8.8:53. Disable Defender only on an isolated VM."
    exit 1
}

# --- disable Defender real-time and tamper protection ------------------

Write-Host 'Disabling Defender real-time + tamper protection...'

# Tamper protection must be off first; do that via the registry.
$tamperKey = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
if (-not (Test-Path $tamperKey)) {
    New-Item -Path $tamperKey -Force | Out-Null
}
Set-ItemProperty -Path $tamperKey -Name 'TamperProtection' -Value 0 -Type DWord -Force

# Disable real-time monitoring.
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2  # never submit
Set-MpPreference -MAPSReporting Disabled

# Add C:\sandbox\ as an exclusion path (where bootstrap + atomics live).
Add-MpPreference -ExclusionPath 'C:\sandbox\' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam\' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\Tools\' -ErrorAction SilentlyContinue

# Verify
$prefs = Get-MpPreference
if ($prefs.DisableRealtimeMonitoring -ne $true) {
    Write-Error "Defender real-time monitoring is still enabled. Check tamper-protection state."
    exit 1
}

Write-Host 'OK: Defender real-time + behavior + IOAV + script scanning all disabled.'
