# VM perf-smoke report — t-utm-perf

**Verdict: NO-GO for QEMU-TCG on Apple Silicon. Escalate to cloud x86_64 (AWS).**

Date: 2026-06-09 · Project: p-w3i5 · Gate task: t-utm-perf

## Question

`t-utm-perf` exists to answer one binary question before committing to
the deeper VM-stack build (Linux+Zeek, isolation network, multi-technique
batch): **is QEMU on Apple Silicon a viable host for the Windows half of
the t-sandbox capture substrate?**

## Environment

| Field          | Value                                              |
|----------------|----------------------------------------------------|
| Host           | Apple Silicon Mac (arm64), macOS 25.5.0            |
| Hypervisor     | qemu-system-x86_64 11.0.1 (Homebrew)               |
| Acceleration   | **TCG only** — HVF cannot accelerate a foreign (x86_64) guest on an arm64 host |
| Guest          | Windows 11 Enterprise Evaluation 25H2 (build 26200.6584), x86_64 |
| VM config      | q35, 4 vCPU, 8 GB RAM, AHCI disk, e1000e NIC, VNC console |

## Findings

### 1. Install time — FAIL (hard gate was < 30 min E2E per capture)

Two full install attempts were run:

- **WinRM-transport autounattend:** reached a reachable state in **44.3 min**
  (2663 s) boot-to-port. Already 1.5x over the 30-min per-capture gate, and
  that was the *one-time* install, not a per-capture cycle.
- **SSH-transport autounattend:** the `Add-WindowsCapability -Online -Name
  OpenSSH.Server` FirstLogonCommand (DISM/CBS — component-store servicing,
  CPU-bound) ran for **5+ hours without completing**. CBS is precisely the
  workload TCG makes 5–10x pathological. qcow2 crept 15 → 23 GB over the
  window; sshd never came up because the capability install (Order=1 in a
  blocking SynchronousCommand chain) never returned.

### 2. Interactive responsiveness — FAIL

With the VM running, the guest was reported "virtually inoperable" — the
desktop and the in-guest PowerShell console were too slow to drive. A
substrate whose entire purpose is repeatable per-capture runs cannot be
built on a host where the guest is unusable interactively.

### 3. Capture fidelity (EID 1 / EID 22 schema match) — NOT REACHED

The install never reached a tooled state, so Sysmon was never deployed and
the EID-1/EID-22 capture-schema assertions could not be evaluated. Moot
given findings 1 and 2.

## Root cause

x86_64 is a foreign architecture on Apple Silicon. QEMU's only option is
TCG (full software binary translation); Apple's Hypervisor.framework (HVF)
accelerates *same-architecture* guests only. Every guest instruction is
translated, so CPU-bound workloads — Windows Setup, CBS servicing,
Defender, the interactive shell — run at a small fraction of native. This
is structural, not a tuning problem; no QEMU flag recovers it.

## What worked (carries forward)

The substrate logic is transport- and host-agnostic and ports to the cloud
target with small edits:

- `autounattend.xml` — unattended Windows provisioning + OpenSSH bring-up
- `install-windows.sh` / `boot-vm.sh` — QEMU lifecycle (replaced by an AMI
  on AWS, but the SSH-poll + timing harness is reusable)
- `ssh-exec.sh` — host→guest PowerShell-over-SSH wrapper (works as-is
  against any reachable Windows SSH endpoint)
- `deploy-tooling.sh` — Sysmon + ART deploy over SSH (host-agnostic)
- `sandbox/workflow/sysmon-config.xml` — capture schema (unchanged)

## Recommendation — escalate to AWS x86_64

Per the pre-sanctioned fallback. AWS gives:

- **Real virtualization** (Nitro) — native x86_64 speed, no emulation tax.
- **Full atomic coverage** — no ARM64 x86-emulation asterisk; matches the
  May-24 acceptance (EVTX + Sysmon + Zeek) at faithful fidelity.
- **No throwaway** — the stack migrates to the cloud range by end-Sept 2026
  regardless (see project_infra_timeline), so cloud-native substrate work
  is on the eventual path, not a detour.

ARM64-Windows-under-HVF was considered (fast + free + local) but rejected
as the primary: the corpus exists to discriminate *real* techniques, and a
permanent x86-payload fidelity asterisk is the wrong tradeoff for a
discrimination benchmark.

## Open inputs before the AWS build

Needed from the operator before re-planning the substrate on AWS:

- Account / region / how credentials are handled on this Mac
- Budget ceiling (instance hours; Windows + Linux pair, likely on-demand)
- Whether captures egress telemetry to S3 or pull back over SSH
- Instance types (Windows capture host + Linux Zeek host on a mirrored subnet)
