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

# NOTE: do NOT use $ErrorActionPreference = 'Stop' here. GHA's
# windows-latest runners lock the TamperProtection registry key at the
# policy level; the Set-ItemProperty below throws "Requested registry
# access is not allowed." That is expected and not fatal -- we still
# get useful telemetry as long as exclusions land and Set-MpPreference
# accepts at least some of the toggles. Make the whole script
# best-effort, log per-action outcomes, and exit 0 unconditionally.

Write-Host 'Best-effort Defender relaxation on GHA windows-latest...'

# --- TamperProtection registry write (may fail; that is OK) -----------

$tamperKey = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
try {
    if (-not (Test-Path $tamperKey)) {
        New-Item -Path $tamperKey -Force -ErrorAction Stop | Out-Null
    }
    Set-ItemProperty -Path $tamperKey -Name 'TamperProtection' -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host '  TamperProtection: registry write succeeded (rare on GHA).'
} catch {
    Write-Warning "  TamperProtection: registry write blocked by GHA policy ($($_.Exception.Message.Trim())). Continuing."
}

# --- Set-MpPreference toggles (some may silently no-op; many work) ----

$toggles = @{
    DisableRealtimeMonitoring  = $true
    DisableBehaviorMonitoring  = $true
    DisableBlockAtFirstSeen    = $true
    DisableIOAVProtection      = $true
    DisableScriptScanning      = $true
}
foreach ($k in $toggles.Keys) {
    $splat = @{ $k = $toggles[$k]; ErrorAction = 'Stop' }
    try {
        Set-MpPreference @splat
        Write-Host "  $k = $($toggles[$k]) applied"
    } catch {
        Write-Warning "  $k : failed ($($_.Exception.Message.Trim()))"
    }
}

# Submit / MAPS settings via separate calls (different param shape).
try { Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop } catch {}
try { Set-MpPreference -MAPSReporting Disabled -ErrorAction Stop } catch {}

# --- ExclusionPath (this is what reliably works on GHA) ---------------

foreach ($p in @('C:\AtomicRedTeam','C:\Tools','C:\Sysmon','C:\sandbox-transcripts')) {
    try {
        Add-MpPreference -ExclusionPath $p -ErrorAction Stop
        Write-Host "  ExclusionPath added: $p"
    } catch {
        Write-Warning "  ExclusionPath $p : failed ($($_.Exception.Message.Trim()))"
    }
}

# --- report final state, do not fail ---------------------------------

$prefs = Get-MpPreference -ErrorAction SilentlyContinue
if ($prefs) {
    Write-Host ''
    Write-Host ('  Final state: RealtimeMonitoring={0} BehaviorMonitoring={1} ScriptScanning={2}' -f `
        $prefs.DisableRealtimeMonitoring, $prefs.DisableBehaviorMonitoring, $prefs.DisableScriptScanning)
    if (-not $prefs.DisableRealtimeMonitoring) {
        Write-Warning '  Real-time monitoring is STILL on. Defender will likely detect'
        Write-Warning '  the T1059.001 mimikatz cradle download and block the script body,'
        Write-Warning '  but the PowerShell process spawn itself is still observable in'
        Write-Warning '  EVTX 4688 + Sysmon EventID 1 -- which is what the acceptance test'
        Write-Warning '  asserts on. Capture should still succeed.'
    }
}

Write-Host 'OK: 01-disable-defender best-effort pass complete.'
exit 0
