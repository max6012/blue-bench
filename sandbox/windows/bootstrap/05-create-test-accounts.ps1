<#
.SYNOPSIS
    Create the local-account population that mirrors the IT baseline
    topology's user model so captured EVTX events align cleanly with
    the corpus identity layer.

.DESCRIPTION
    Captures from the sandbox will be host-rewritten by t-apt-inject
    to fit into the IT baseline corpus, so the local accounts on the
    sandbox VM should resemble what the IT baseline topology emits:
      - one regular workstation user
      - one admin-equivalent account
      - one service account

    Names are deliberately generic and vendor-neutral. The IT baseline
    user-name pool is in blue_bench_generators/it_baseline/topology.py
    -- the names below intentionally use a different seed slice so a
    captured EVTX from the sandbox doesn't appear as a baseline user.

.NOTES
    Must be run as Administrator. Idempotent.
#>

$ErrorActionPreference = 'Stop'

# Strong randomish passwords; the orchestrator does not need them
# after SSH key push (06-enable-ssh.ps1 enforces key-only auth).
$accounts = @(
    @{
        Name = 'tomas.kowalski';
        Group = 'Users';
        Description = 'regular workstation user (sandbox-only)';
    },
    @{
        Name = 'tomas.kowalski.adm';
        Group = 'Administrators';
        Description = 'admin-equivalent account (sandbox-only)';
    },
    @{
        Name = 'svc-backup';
        Group = 'Users';
        Description = 'service account stand-in (sandbox-only)';
    }
)

foreach ($a in $accounts) {
    $existing = Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  $($a.Name) -> exists, skipping create"
    } else {
        $pwd = ConvertTo-SecureString -String "Sandbox-$(New-Guid)" -AsPlainText -Force
        New-LocalUser -Name $a.Name -Password $pwd -FullName $a.Name `
                      -Description $a.Description -PasswordNeverExpires `
                      -UserMayNotChangePassword | Out-Null
        Write-Host "  $($a.Name) -> created"
    }

    $inGroup = (Get-LocalGroupMember -Group $a.Group -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*\$($a.Name)" })
    if (-not $inGroup) {
        Add-LocalGroupMember -Group $a.Group -Member $a.Name
        Write-Host "  $($a.Name) -> added to $($a.Group)"
    }
}

Write-Host 'OK: test accounts created.'
