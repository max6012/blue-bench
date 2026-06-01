<#
.SYNOPSIS
    Enable verbose Windows EventLog channels needed for APT-detection
    capture on the GHA runner.

.DESCRIPTION
    Splits the work into LOAD-BEARING and BEST-EFFORT categories.

    LOAD-BEARING (failure here aborts the step with exit 1):
      - Registry: ProcessCreationIncludeCmdLine_Enabled  (4688 carries
        no command line without it)
      - auditpol.exe Process Creation success/failure   (4688 doesn't
        fire at all without success/failure auditing enabled)
      - Registry: PS ModuleLogging / ScriptBlockLogging / Transcription
        (Microsoft-Windows-PowerShell/Operational depends on these)

    BEST-EFFORT (failure here warns; the script still exits 0):
      - wevtutil.exe channel sizing for the listed log channels. Some
        channels (e.g. Microsoft-Windows-WMI-Activity/Operational) are
        not present on every Server 2022 SKU. Channel capture still
        works at default size; raising the limit is a hedge against
        long technique runs rolling the log over mid-capture.

    Runs as Administrator inside the runner. Transcripts go to
    C:\sandbox-transcripts\ so the harvest step's path glob doesn't
    have to know about the UTM variant's C:\sandbox\transcripts\.
#>

$ErrorActionPreference = 'Stop'

# Track which load-bearing actions actually succeeded. Anything that
# stays $false at the end fails the step.
$registryCmdline = $false
$auditpolProcCreate = $false
$registryPsLogging = $false

# --- LOAD-BEARING 1/3: 4688 includes command line ----------------------

Write-Host 'Enabling 4688 with full command line...'

try {
    $polKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $polKey)) { New-Item -Path $polKey -Force | Out-Null }
    Set-ItemProperty -Path $polKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    $registryCmdline = $true
    Write-Host '  registry ProcessCreationIncludeCmdLine_Enabled = 1'
} catch {
    Write-Error "  registry ProcessCreationIncludeCmdLine_Enabled write failed: $($_.Exception.Message)"
}

# --- LOAD-BEARING 2/3: 4688 fires at all -------------------------------

& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -eq 0) {
    $auditpolProcCreate = $true
    Write-Host '  auditpol Process Creation success+failure enabled'
} else {
    Write-Error "  auditpol Process Creation failed (exit=$LASTEXITCODE)"
    $global:LASTEXITCODE = 0   # don't leak as script exit code; we track via the flag
}

# --- LOAD-BEARING 3/3: PowerShell logging ------------------------------

Write-Host 'Enabling PowerShell module + script-block + transcription...'

try {
    $psRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    foreach ($sub in @('ModuleLogging','ScriptBlockLogging','Transcription')) {
        $p = "$psRoot\$sub"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    }

    Set-ItemProperty -Path "$psRoot\ModuleLogging" -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
    $mlNames = "$psRoot\ModuleLogging\ModuleNames"
    if (-not (Test-Path $mlNames)) { New-Item -Path $mlNames -Force | Out-Null }
    Set-ItemProperty -Path $mlNames -Name '*' -Value '*' -Type String -Force

    Set-ItemProperty -Path "$psRoot\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "$psRoot\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "$psRoot\Transcription" -Name 'EnableTranscripting' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "$psRoot\Transcription" -Name 'EnableInvocationHeader' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "$psRoot\Transcription" -Name 'OutputDirectory' -Value 'C:\sandbox-transcripts' -Type String -Force

    New-Item -ItemType Directory -Path 'C:\sandbox-transcripts' -Force | Out-Null

    $registryPsLogging = $true
    Write-Host '  registry PS ModuleLogging + ScriptBlockLogging + Transcription set'
} catch {
    Write-Error "  PS logging registry writes failed: $($_.Exception.Message)"
}

# --- BEST-EFFORT: channel sizing --------------------------------------

# $ErrorActionPreference = 'Stop' applies only to PS cmdlets; native
# command exit codes (wevtutil) are tracked via $LASTEXITCODE and do
# not raise PS exceptions. We handle them explicitly here.

Write-Host 'Raising channel sizes (best-effort)...'

$channels = @(
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-WinRM/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Windows PowerShell'
)

foreach ($ch in $channels) {
    & wevtutil.exe sl $ch /e:true /ms:524288000 /rt:false 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  $ch -> enabled, 500 MB, no retention overwrite"
    } else {
        Write-Warning "  $ch -> wevtutil exit=$LASTEXITCODE (channel may not exist on this image; non-fatal)"
        $global:LASTEXITCODE = 0
    }
}

# --- decide step outcome ----------------------------------------------

Write-Host ''
Write-Host ('  Load-bearing outcomes: registryCmdline={0} auditpolProcCreate={1} registryPsLogging={2}' -f `
    $registryCmdline, $auditpolProcCreate, $registryPsLogging)

if (-not ($registryCmdline -and $auditpolProcCreate -and $registryPsLogging)) {
    Write-Error 'One or more load-bearing EventLog configuration steps failed. Downstream EVTX telemetry would be incomplete (acceptance test asserts on 4688 + PS EventID 4104). Failing the step.'
    exit 1
}

Write-Host 'OK: EventLog channels configured (all load-bearing paths green).'
exit 0
