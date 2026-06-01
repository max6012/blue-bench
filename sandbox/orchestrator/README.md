# Orchestrator scripts

Mac-side shell scripts that drive the sandbox VMs.

| Script | Purpose |
|---|---|
| `safe-fire-check.sh` | Verify isolation gates before every run |
| `snapshot.sh` | UTM snapshot one or both VMs |
| `restore.sh` | UTM restore one or both VMs to a named snapshot |
| `run-atomic.sh` | SSH into the target VM and invoke `Invoke-AtomicTest` |
| `harvest.sh` | Pull EVTX / Sysmon / Zeek / Suricata / auditd back to `data/raw/sandbox/<run_id>/` |

## Environment variables

All scripts respect the following with the defaults shown:

| Var | Default | Meaning |
|---|---|---|
| `SANDBOX_WIN_IP` | `192.168.66.10` | Windows VM static IP on sandbox-net |
| `SANDBOX_LNX_IP` | `192.168.66.20` | Linux VM static IP on sandbox-net |
| `SANDBOX_WIN_VM` | `sandbox-win` | UTM VM name for Windows |
| `SANDBOX_LNX_VM` | `sandbox-lnx` | UTM VM name for Linux |
| `SANDBOX_SSH_KEY` | `$HOME/.ssh/blue-bench-sandbox.key` | Orchestrator SSH private key |
| `SANDBOX_FLUSH_SECONDS` | `60` | Wait after technique exec for telemetry to flush |
| `BLUE_BENCH_ROOT` | `<repo root>` | Used to compute `data/raw/sandbox/` |

## Steady-state loop

```bash
./safe-fire-check.sh                       # gate
./restore.sh both baseline                 # clean slate
./run-atomic.sh T1003.001 -TestNumbers 1   # do the thing
./harvest.sh                               # pull telemetry
```

## utmctl

The snapshot / restore scripts wrap `utmctl`, which ships with UTM
4.5+ under `/Applications/UTM.app/Contents/MacOS/utmctl`. Either add
that to `PATH` or alias `utmctl` to the full path.
