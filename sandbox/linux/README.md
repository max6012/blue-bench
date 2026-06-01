# Linux VM

UTM-provisioned Ubuntu Server 22.04 LTS on the sandbox-net host-only
network at static IP `192.168.66.20`. Dual-purpose host: runs Linux
atomics AND captures the network tap.

| File | Purpose |
|---|---|
| `utm-vm-spec.md` | UTM VM creation spec + OOBE choices |
| `config/audit.rules` | Scoped auditd ruleset (EXECVE, connect, sensitive paths) |
| `config/zeek-site-local.zeek` | Zeek local.zeek configuration |
| `config/suricata.yaml` | Suricata config (eve.json output) |
| `bootstrap/01-install-packages.sh` | apt-install or .deb-fallback for auditd/zeek/suricata |
| `bootstrap/02-configure-auditd.sh` | Install rules + sizing + restart |
| `bootstrap/03-configure-zeek.sh` | local.zeek + node.cfg pinned to enp0s2 |
| `bootstrap/04-configure-suricata.sh` | Validate config + enable + start |
| `bootstrap/05-install-atomic-red-team.sh` | pwsh + ART Linux runner from staged zips |
| `bootstrap/bootstrap.sh` | Runs 01..05 in order |

## Out-of-band staging required

The VM has no internet egress. Stage the following into
`/tmp/sandbox-deps/` before running `bootstrap.sh`:

```
zeek_*.deb
suricata_*.deb
auditd_*.deb              (if not already installed)
powershell_*.deb          (pwsh -- Linux Invoke-AtomicTest host)
atomic-red-team.zip
invoke-atomicredteam.zip
```

Alternative: provision the VM briefly with internet on, run apt
install + git clone for the deps, then permanently switch to
sandbox-net + snapshot.

See `../runbook.md` for the full bootstrap procedure.
