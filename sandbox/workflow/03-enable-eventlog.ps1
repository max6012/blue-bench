<#
.SYNOPSIS
    Enable verbose Windows EventLog channels needed for APT-detection
    capture on the GHA runner.

.DESCRIPTION
    Same content as the UTM-variant bootstrap (4688 + cmdline,
    PS module/script-block/transcripts, channel sizing). Runs as
    Administrator inside the runner.

    Transcripts go to C:\sandbox-transcripts\ rather than the UTM
    variant's C:\sandbox\transcripts\ so the harvest step's path
    glob is independent of the local-VM convention.
#>

$ErrorActionPreference = 'Stop'

# --- Process Creation includes command line (4688) ---------------------

Write-Host 'Enabling 4688 with full command line...'

$polKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $polKey)) { New-Item -Path $polKey -Force | Out-Null }
Set-ItemProperty -Path $polKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force

& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

# --- PowerShell logging ------------------------------------------------

Write-Host 'Enabling PowerShell module + script-block + transcription...'

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

# --- Channel sizing ----------------------------------------------------

Write-Host 'Raising channel sizes + enabling key channels...'

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
    try {
        & wevtutil.exe sl $ch /e:true /ms:524288000 /rt:false 2>&1 | Out-Null
        Write-Host "  $ch -> enabled, 500 MB, no retention overwrite"
    } catch {
        Write-Warning "  $ch -> failed to configure ($_)"
    }
}

Write-Host 'OK: EventLog channels configured.'
