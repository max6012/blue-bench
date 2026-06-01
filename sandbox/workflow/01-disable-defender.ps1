<#
.SYNOPSIS
    Disable Windows Defender on the GHA runner so atomics don't get
    blocked or quarantined.

.DESCRIPTION
    Runs as Administrator (every GHA step is admin by default on
    windows-latest). Tamper protection must be off first; the
    registry tweak handles that. Then real-time + behavior + IOAV +
    script scanning are all disabled.

    Note: unlike the Mac-local sandbox, this script does NOT abort
    on "VM has a default route". GHA runners by definition have a
    default route to the public internet -- that's the trade we
    accepted by choosing GHA over a fully-isolated local VM.
#>

$ErrorActionPreference = 'Stop'

Write-Host 'Disabling Defender tamper protection + real-time monitoring...'

$tamperKey = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
if (-not (Test-Path $tamperKey)) {
    New-Item -Path $tamperKey -Force | Out-Null
}
Set-ItemProperty -Path $tamperKey -Name 'TamperProtection' -Value 0 -Type DWord -Force

Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue

# Exclude paths that the bootstrap will use.
foreach ($p in @('C:\AtomicRedTeam','C:\Tools','C:\Sysmon')) {
    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
}

# Verification. GHA runners have been observed where TamperProtection
# is enforced at the policy level; in that case we log + continue
# rather than failing the step (the atomic invocation will still
# likely succeed because GHA's Defender baseline is permissive).
$prefs = Get-MpPreference
if ($prefs.DisableRealtimeMonitoring) {
    Write-Host 'OK: Defender real-time monitoring disabled.'
} else {
    Write-Warning 'Defender real-time monitoring is STILL enabled. The'
    Write-Warning 'atomic may be partially blocked. Some techniques will'
    Write-Warning 'still produce useful telemetry; others (T1003.001'
    Write-Warning 'LSASS dump in particular) may fail outright.'
}
