# Mac-local VM capture substrate — t-utm-perf

Gate for the t-sandbox VM rebuild (p-w3i5). Target: a Mac-local
autonomous capture substrate that produces EVTX + Sysmon (and
eventually Zeek) for arbitrary Atomic Red Team techniques without
manual operator input per run. The "perf smoke" framing is
preserved as the GO/NO-GO acceptance, but the work is structurally
the Windows half of t-sandbox itself.

**Host stack** (Max's pick 2026-06-09):

```
macOS arm64 (Apple Silicon)
└── QEMU x86_64 (Homebrew)             — raw, no UTM GUI wrapper
    └── Windows 11 (x86_64 emulated)
        ├── autounattend.xml           — drives OOBE end-to-end
        ├── WinRM service (TCP/5985)   — Mac-side control channel
        ├── Sysmon + Atomic Red Team   — same config the GHA path uses
        └── EVTX channels (Sysmon/PS/Security/System)
```

UTM is QEMU with a GUI; bypassing the GUI gives us scriptable
provisioning + snapshot/clone primitives we can drive from
`sandbox/vm/*.sh` instead of clicking through a launcher.

## Acceptance — three binary criteria

The smoke is PASS when all three hold:

1. **End-to-end T1059.001 PowerShell run completes in < 30 minutes
   wall-clock** from "qemu-system-x86_64 invoked on a clone of the
   tooled baseline" to "EVTX harvested to host disk." This is the
   only hard quantitative gate; the one-time install of Windows +
   tooling is NOT counted (it's amortised across all future runs).
2. **Sysmon EID 1 + EID 22 fire** in the harvested Sysmon.evtx, for
   the same T1059.001-1 test the GHA path captured. Confirms the
   guest's Sysmon agent has the same fidelity as the GHA shape.
3. **Capture layout matches the GHA harvest schema**:
   `windows/Sysmon.evtx`, `windows/PowerShell.evtx`,
   `windows/Security.evtx`, `windows/System.evtx`, `manifest.json`.
   Confirms downstream harvest tooling (`sandbox/orchestrator/`,
   the assertion scripts) consumes VM captures unchanged.

If (1) misses: stop. Produce the perf report (Phase 7) with
escalation recommendation. Do NOT push deeper VM-stack work
(Linux+Zeek, isolation network, multi-technique batch).

## Phase budget — measured, not gated

x86_64-on-arm64 emulation typically costs 5–10x. Numbers below
assume the 10x worst case. Per-phase wall-clocks land in
`sandbox/vm/perf-timings.json`.

| Phase                            | GHA baseline | UTM target  |
|----------------------------------|--------------|-------------|
| VM cold boot → WinRM reachable   | n/a          | ≤ 5 min     |
| WinRM-driven atomic execution    | ≤ 10s        | ≤ 1 min     |
| EVTX flush + harvest to host     | ≤ 30s        | ≤ 5 min     |
| **E2E per-capture (gates on 30 min)** | ~3 min  | ≤ 30 min    |

One-time setup phases (not in the per-capture E2E):
- QEMU install: ≤ 5 min
- Windows unattended install: ≤ 60 min
- Sysmon + ART deploy via WinRM: ≤ 20 min

## VM configuration

| Field          | Value                                                            |
|----------------|------------------------------------------------------------------|
| Hypervisor     | qemu-system-x86_64 (Homebrew, latest stable)                     |
| Acceleration   | TCG (full software emulation; HVF is arm64-only, can't accelerate x86_64) |
| Guest OS       | Windows 11 Enterprise Evaluation 23H2 (x64)                      |
| ISO            | Win11_23H2_English_x64.iso from microsoft.com/evalcenter         |
| CPU            | -smp 4                                                           |
| RAM            | -m 8192                                                          |
| Disk           | qcow2, 80 GB, compressed, snapshot-friendly                      |
| Network        | -netdev user with `hostfwd=tcp::5985-:5985` (WinRM forwarded)    |
| Display        | -nographic (after install completes) / -display cocoa during install |

Fallback path (only if x86_64 misses the 30-min E2E gate):
- ARM64 Windows 11 (Insider Preview) under HVF acceleration.
- Coverage caveat: some atomics use x86-only payloads.
- Re-run the smoke; document the coverage delta in the perf report.

## Sub-task map (PlanDB)

The decomposition lives in p-w3i5 under t-utm-perf. Each row below
is a self-contained sub-task with its own description in PlanDB.

| Sub-task         | Deliverable                                    | Depends on        |
|------------------|------------------------------------------------|-------------------|
| t-qemu-host      | QEMU installed + version + accel-mode note     | —                 |
| t-win-unattend   | sandbox/vm/autounattend.xml + ISO build script | t-qemu-host       |
| t-winrm-client   | sandbox/vm/winrm-exec.sh                       | t-qemu-host       |
| t-win-install    | bb-sandbox-win11-baseline.qcow2 (NOT in repo)  | t-win-unattend    |
| t-guest-tooling  | sandbox/vm/deploy-tooling.sh                   | t-win-install + t-winrm-client |
| t-atomic-perf    | sandbox/vm/fire-and-harvest.sh + perf-timings.json | t-guest-tooling |
| t-perf-report    | sandbox/vm/perf-report.md + GO/NO-GO           | t-atomic-perf     |

The qcow2 baselines are NOT committed (large, env-specific). They
live under `~/Library/Application Support/bb-sandbox-vm/` and the
scripts know how to find them.

## Phase 1 — QEMU host setup (t-qemu-host)

```bash
brew install qemu
qemu-system-x86_64 --version
# Note: HVF acceleration is arm64-only; x86_64 guest runs TCG.
qemu-system-x86_64 -machine help | grep -i accel || true
```

Document in perf-report: QEMU version, accel mode (expect TCG).

## Phase 2 — autounattend.xml (t-win-unattend)

Author `sandbox/vm/autounattend.xml`. Required behaviour:

- Skip every OOBE prompt (region, keyboard, MSA, privacy, Edge).
- Local user `sandbox`, password `Sb!4-bench-2026` (or similar non-empty).
- Auto-logon as `sandbox` for 1 boot (long enough to provision tooling).
- **Enable WinRM**: `winrm quickconfig -force` and a basic-auth
  firewall rule for TCP/5985 from any source. (Smoke runs on
  loopback via QEMU hostfwd; tighten before any non-local exposure.)
- **Enable PowerShell Remoting**: `Enable-PSRemoting -Force -SkipNetworkProfileCheck`.
- Set ExecutionPolicy=Bypass for LocalMachine.
- Disable Windows Update during install (the auto-restart loop
  destroys the unattended timing).
- Disable Defender real-time monitoring (matches the GHA shape).

Build script: `sandbox/vm/build-unattended-iso.sh` repackages the
upstream ISO with `autounattend.xml` at the ISO root so Windows
Setup picks it up automatically.

## Phase 3 — Unattended Windows install (t-win-install)

```bash
sandbox/vm/install-windows.sh
# Inside: qemu-system-x86_64 \
#   -drive file=bb-sandbox-win11-baseline.qcow2,if=virtio \
#   -cdrom Win11_23H2_unattended.iso \
#   -m 8192 -smp 4 \
#   -netdev user,id=net0,hostfwd=tcp::5985-:5985 \
#   -device virtio-net,netdev=net0 \
#   -display cocoa
#
# Polls WinRM on localhost:5985 until reachable (max 90 min).
# Times boot→WinRM-reachable for the perf report.
```

Output: a baseline qcow2 with a bootable Windows + WinRM, ready
for tooling. Snapshot once (`qemu-img snapshot -c baseline`) so
the guest-tooling step starts from a known clean state.

## Phase 4 — WinRM client (t-winrm-client)

Choose between:

- **pwsh-on-Mac** + `Invoke-Command -ComputerName localhost -Port 5985 -Credential ...`
- **python pywinrm** (`pip install pywinrm`) + a small `winrm-exec.py`

The deliverable is `sandbox/vm/winrm-exec.sh` — a thin wrapper that
runs arbitrary PowerShell in the guest and streams stdout/stderr to
the Mac terminal. The choice between pwsh and pywinrm is an
implementation detail; whichever tools up faster wins. Document
the pick in the sub-task close-out.

## Phase 5 — Sysmon + ART deploy (t-guest-tooling)

```bash
sandbox/vm/deploy-tooling.sh
# Inside, via WinRM:
#  1. Push sandbox/workflow/sysmon-config.xml into the guest.
#  2. Install Sysmon64 with that config (same as GHA step 02).
#  3. Install Invoke-AtomicRedTeam + atomics (same as GHA step 04).
#  4. Verify Sysmon EID 1 fires on a Get-Process probe.
#  5. Snapshot the qcow2 as 'tooled'.
```

This is a one-time cost amortised across all future captures. The
tooled qcow2 becomes the per-capture clone source.

## Phase 6 — T1059.001 fire + harvest (t-atomic-perf)

```bash
sandbox/vm/fire-and-harvest.sh T1059.001 1
# Inside:
#  1. Clone the tooled qcow2 to a per-run scratch path.
#  2. Boot the clone with QEMU; wait for WinRM.
#  3. Time it. (boot_to_winrm_seconds)
#  4. Over WinRM: Invoke-AtomicTest T1059.001 -TestNumbers 1.
#  5. Time it. (atomic_seconds)
#  6. Start-Sleep 30 (flush).
#  7. Over WinRM: wevtutil epl ... for all 4 channels + manifest.json.
#  8. scp/winrm-pull the harvest dir to data/raw/sandbox/utm-perf-smoke/.
#  9. Time it. (harvest_seconds)
# 10. Shut down + delete the per-run clone.
# 11. Emit sandbox/vm/perf-timings.json with every phase number.
```

## Phase 7 — Perf report + go/no-go (t-perf-report)

`sandbox/vm/perf-report.md` is the final deliverable. Required
fields:

- QEMU version, host machine model, host macOS version, host CPU
- VM config snapshot (CPU/RAM/disk/network)
- Windows ISO build, Sysmon version, ART version
- Per-phase wall-clock from `perf-timings.json`
- Capture validation: EID 1 count, EID 22 count, schema-match PASS/FAIL
- **Explicit recommendation**: GO / GO-WITH-DEGRADATION / NO-GO.
  - GO: proceed with t-sandbox decomposition for the Linux/Zeek
    VM, isolation network, snapshot/restore workflow,
    multi-technique batch capture.
  - GO-WITH-DEGRADATION: x86_64 missed but ARM64 fallback works;
    accept the atomic-coverage delta; document affected techniques.
  - NO-GO: escalate. Recommend cdex.cloud or AWS, with cost +
    latency estimate. Do NOT silently fall back to GHA-as-acceptance.

## What this runbook deliberately does NOT cover

- Linux VM / Zeek / Suricata bring-up. Separate work after the
  smoke is green.
- Network isolation between the two VMs (and between Win VM and
  the Mac host). Separate.
- Multi-technique batch capture orchestration. Separate.
- Snapshot/restore beyond the qcow2 'baseline' / 'tooled' tags.
  The deeper snapshot workflow is part of t-sandbox proper.

## Appendix — UTM GUI fallback

If the autonomous-drive path stalls (autounattend issues, QEMU
networking problems, WinRM not coming up), the UTM-GUI flow below
can be used as a manual fallback to validate the perf gate
independently of the automation work.

(Original UTM-GUI walkthrough preserved here for reference;
intentionally less detail than the automation flow above. If you
end up running this, scope creep: pause and check with Max before
making it the actual path.)

1. `brew install --cask utm`
2. UTM → Create New VM → Emulate → Windows → attach the ISO →
   4 CPU / 8 GB / 80 GB disk → Save as `bb-sandbox-win11-x64`.
3. Walk through OOBE with Shift+F10 → `OOBE\BYPASSNRO` to skip MSA.
4. Install Sysmon + ART manually (paste sysmon-config.xml via
   UTM clipboard, run the same PowerShell as Phase 5).
5. Run `Invoke-AtomicTest T1059.001 -TestNumbers 1`, harvest by
   hand, copy out via UTM shared dir.
6. Compile perf-report.md the same way the automated path does.
