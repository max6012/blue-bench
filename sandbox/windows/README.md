# Windows VM

UTM-provisioned Windows 11 Pro running on the sandbox-net host-only
network at static IP `192.168.66.10`.

| File | Purpose |
|---|---|
| `utm-vm-spec.md` | UTM VM creation spec + OOBE choices |
| `sysmon-config.xml` | Modular Sysmon config (event-ID scope documented inline) |
| `bootstrap/01-disable-defender.ps1` | Defender off (gated on isolation check) |
| `bootstrap/02-install-sysmon.ps1` | Install / reload Sysmon |
| `bootstrap/03-enable-eventlog.ps1` | 4688 + cmdline + PS module/script-block/transcript logging |
| `bootstrap/04-install-atomic-red-team.ps1` | ART + Invoke-AtomicTest from staged zips |
| `bootstrap/05-create-test-accounts.ps1` | Vendor-neutral local users |
| `bootstrap/06-enable-ssh.ps1` | OpenSSH server, key-only, sandbox-net only |
| `bootstrap/bootstrap.ps1` | Runs 01..06 in order; stops on first failure |

## Out-of-band staging required

The VM has no internet egress. Before running `bootstrap.ps1`, stage:

```
C:\sandbox\tools\Sysmon64.exe
C:\sandbox\tools\atomic-red-team.zip
C:\sandbox\tools\invoke-atomicredteam.zip
C:\Users\analyst\.ssh\authorized_keys      (orchestrator public key)
```

See `../runbook.md` for the full bootstrap procedure.
