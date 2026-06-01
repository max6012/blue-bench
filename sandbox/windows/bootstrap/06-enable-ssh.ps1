<#
.SYNOPSIS
    Install and enable Windows OpenSSH server so the orchestrator on
    the Mac host can drive technique runs and harvest captures.

.DESCRIPTION
    Configures key-only auth (no password). The orchestrator stages
    its public key into C:\Users\analyst\.ssh\authorized_keys before
    this script runs (handled in bootstrap.ps1).

    Listens on the sandbox-net interface only -- not bound to any
    other adapter.

.NOTES
    Must be run as Administrator. Idempotent.
#>

$ErrorActionPreference = 'Stop'

# --- install OpenSSH server -------------------------------------------

Write-Host 'Installing OpenSSH Server capability...'

$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
}

# --- service config ----------------------------------------------------

Set-Service -Name 'sshd' -StartupType Automatic
Start-Service -Name 'sshd'

# Set PowerShell as the default shell for SSH sessions (so the
# orchestrator can pipe PowerShell commands directly).
$psPath = (Get-Command powershell.exe).Source
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' `
                 -Value $psPath -PropertyType String -Force | Out-Null

# --- sshd_config: key-only, listen on sandbox-net IP ------------------

$sshdConfig = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path $sshdConfig) {
    # Backup once.
    if (-not (Test-Path "$sshdConfig.orig")) {
        Copy-Item $sshdConfig "$sshdConfig.orig"
    }

    $content = Get-Content $sshdConfig
    $content = $content `
        -replace '^#?PasswordAuthentication.*', 'PasswordAuthentication no' `
        -replace '^#?PubkeyAuthentication.*', 'PubkeyAuthentication yes' `
        -replace '^#?PermitRootLogin.*', 'PermitRootLogin no' `
        -replace '^#?ListenAddress .*', 'ListenAddress 192.168.66.10'

    # If ListenAddress wasn't present at all, append it.
    if (-not ($content -match '^ListenAddress ')) {
        $content += 'ListenAddress 192.168.66.10'
    }

    Set-Content -Path $sshdConfig -Value $content -Encoding ASCII
}

Restart-Service -Name 'sshd'

# --- firewall: allow 22 inbound only from sandbox-net ----------------

$ruleName = 'sandbox-ssh-in'
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) { $existing | Remove-NetFirewallRule }

New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress '192.168.66.0/24' `
    -LocalAddress '192.168.66.10' | Out-Null

Write-Host 'OK: OpenSSH server enabled with key-only auth on 192.168.66.10:22.'
