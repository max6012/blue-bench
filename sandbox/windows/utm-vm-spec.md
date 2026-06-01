# Windows VM specification

## VM properties

| Field | Value |
|---|---|
| Hypervisor | UTM (Apple hypervisor.framework) |
| Architecture | x86_64 (NOT aarch64 — most Sysmon / ART deps assume x86) |
| OS | Windows 11 Pro, 23H2 or later |
| vCPU | 4 |
| RAM | 8 GB |
| Disk | 60 GB qcow2, thin-provisioned |
| Network | `sandbox-net` only (host-only, no NAT, no en0 bridge) |
| Static IP | `192.168.66.10/24`, no default gateway |
| DNS | `127.0.0.1` (no public resolver) |
| Snapshot | UTM snapshot named `baseline` after bootstrap |

## OOBE choices

- Region: United States (any vendor-neutral default)
- Keyboard: US
- Network setup: skip — do NOT connect to Wi-Fi or Ethernet during OOBE.
  This avoids Microsoft account enrolment and forces local-account
  creation.
- Microsoft account: skip with the `OOBE\BYPASSNRO` trick if the
  installer pushes the account prompt anyway.
- Local account name: `analyst`
- Local account password: any 12+ char value, stored in your local
  password manager — the orchestrator does not need it after SSH key
  push.
- Privacy settings: all telemetry OFF.

## Disk-image source

Use the official Microsoft ISO from
[microsoft.com/software-download/windows11](https://www.microsoft.com/software-download/windows11)
(legitimate, no licensing issues for ATT&CK-evaluation use; UTM supports
unactivated Windows for 30+ days without functional restriction on
EventLog or Sysmon).

## Post-install verification

Before running `bootstrap.ps1`, confirm:

- `Get-NetIPAddress | Where-Object IPAddress -eq '192.168.66.10'` returns 1 row
- `Get-NetRoute -DestinationPrefix '0.0.0.0/0'` returns 0 rows (no default route)
- `Test-NetConnection 8.8.8.8` returns `PingSucceeded : False`
- `Test-NetConnection 192.168.66.20` returns `PingSucceeded : True`

If any of those fails, fix network isolation before proceeding —
the bootstrap script will disable Defender, and you do not want a
Defender-disabled box on a route to the public internet.
