# Sandbox runbook — first-time bootstrap to first capture

Step-by-step procedure for standing up the two-VM sandbox on a Mac and
running the T1059.001 acceptance test. Total wall-clock first time
through is ~90 minutes (mostly waiting on Windows installer + Sysmon
baseline draws).

## Prerequisites

- macOS host with UTM 4.5+ installed (`brew install --cask utm`)
- Windows 11 Pro ISO (Microsoft official, downloaded via the Windows
  Insider Preview download page or your Volume Licensing portal)
- Ubuntu Server 22.04 LTS ISO
- ~80 GB free disk for both VM images + baseline snapshots
- `jq` (`brew install jq`) — used by harvest scripts
- `sshpass` (`brew install hudochenkov/sshpass/sshpass`) — used by
  bootstrap to push the initial public key non-interactively. After
  the first push, key-only auth is enforced and `sshpass` is no longer
  needed.

## 1. UTM internal network

See `network/utm-network-setup.md`. One-time UTM-level config to create
a "Host Only" virtual switch named `sandbox-net` that both VMs will
attach to.

Verify with:

```bash
./orchestrator/safe-fire-check.sh
```

The check confirms:
- the `sandbox-net` network has no default route to en0
- no DNS resolver inside the sandbox-net reaches the public internet
- pfctl rules block any pkt sourced from the sandbox subnet from
  egressing the Mac

## 2. Linux VM

UTM-create a VM per `linux/utm-vm-spec.md`:

- 2 vCPU, 4 GB RAM, 30 GB disk
- Network: `sandbox-net` only
- Ubuntu Server 22.04 LTS, minimal install, no snap
- Username `analyst`, password set during install
- OpenSSH server enabled at install time

After first boot:

```bash
# From the Mac host (run while the Linux VM is booted and reachable via
# the UTM-assigned IP):
scp -r sandbox/linux/bootstrap analyst@<linux-vm-ip>:/tmp/
scp -r sandbox/linux/config analyst@<linux-vm-ip>:/tmp/
ssh analyst@<linux-vm-ip> sudo bash /tmp/bootstrap/bootstrap.sh
```

The bootstrap script installs auditd + Zeek + Suricata + Atomic Red
Team Linux runner, applies the audit/Zeek/Suricata configs, and
enables packet capture on `enp0s2` (the sandbox-net interface).

Once bootstrap succeeds, **take the UTM snapshot named `baseline`**:

```bash
./orchestrator/snapshot.sh linux baseline
```

## 3. Windows VM

UTM-create a VM per `windows/utm-vm-spec.md`:

- 4 vCPU, 8 GB RAM, 60 GB disk
- Network: `sandbox-net` only
- Windows 11 Pro, English (US)
- Skip Microsoft account at OOBE — local account `analyst` only
- Disable telemetry at install time

After first boot, copy the bootstrap directory in and run:

```powershell
# From an Administrator PowerShell prompt inside the Windows VM,
# after copying sandbox/windows/bootstrap/ to C:\sandbox\:
cd C:\sandbox\bootstrap
.\bootstrap.ps1
```

The bootstrap script:
1. Disables Defender (so atomics don't get blocked)
2. Installs Sysmon with the modular config
3. Enables verbose Windows EventLog channels (Security, System,
   PowerShell-Operational, Sysmon)
4. Installs Atomic Red Team Invoke-AtomicTest module
5. Creates test accounts (Domain Admin equivalent + standard user)
6. Enables OpenSSH server for orchestrator access

Reboot, then take the snapshot:

```bash
./orchestrator/snapshot.sh windows baseline
```

## 4. Acceptance test

With both VMs at baseline snapshot, run from the Mac host:

```bash
./tests/test_t1059_001_end_to_end.sh
```

The script:
1. Verifies safe-fire isolation
2. Restores both VMs to baseline (idempotent)
3. SSHes into the Windows VM and invokes:
   `Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs`
4. Waits 60 seconds for telemetry to flush
5. Harvests EVTX / Sysmon / Zeek / Suricata to
   `data/raw/sandbox/<run_id>/`
6. Asserts:
   - EVTX contains EventID 4688 with `CommandLine` matching the
     atomic's invocation
   - Sysmon JSONL contains EventID 1 (ProcessCreate) with the same
     CommandLine
   - Zeek `conn.log` covers the test window

A clean run exits 0 and prints `ACCEPTANCE OK: run_id=<id>`.

## Recurring use

After bootstrap, the steady-state loop is:

```bash
# Restore both VMs to the baseline snapshot (clean slate)
./orchestrator/restore.sh both baseline

# Run a technique
./orchestrator/run-atomic.sh T1003.001 -TestNumbers 1

# Harvest the captured telemetry
./orchestrator/harvest.sh
```

Each harvest writes to a new `data/raw/sandbox/<run_id>/` directory and
appends a row to `data/raw/sandbox/manifest.csv` recording the run_id,
technique, timestamp, snapshot ID, and per-stream byte counts.
