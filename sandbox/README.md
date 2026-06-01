# Sandbox — Atomic Red Team / Caldera capture substrate

**PlanDB:** `t-sandbox` (project `p-w3i5`, bb-heavy-telemetry).

Two-VM isolated sandbox whose sole purpose is to run **real** Atomic Red
Team and Caldera techniques and capture the resulting EVTX / Sysmon /
Zeek / Suricata / auditd telemetry. The captured output then becomes
the fixture library consumed by `t-apt-inject`, which time-shifts and
host-rewrites it into the IT baseline corpus at realistic LotL pacing.

## Why we run our own sandbox

Per `project_research_questions`, the APT signal in Blue-Bench is
deliberately sourced from **techniques actually executed in our sandbox**,
not from external pre-captured datasets (Mordor / Security-Datasets) or
MTA-style PCAP splices. Three reasons make that choice load-bearing for
RQ2 (APT detection):

1. **Topology + Sysmon-config + binary-version alignment.** Captures
   from an external lab carry their lab's user accounts, paths,
   account naming, Sysmon ruleset, and OS build. A model can
   pattern-match those as "this isn't really from the corpus," which
   short-circuits the detection question. Our captures use the same
   account-naming and host-naming conventions the IT baseline
   generator emits.
2. **Technique selection driven by our campaigns.** The kill-chain
   templates `t-apt-inject` composes (initial-access → execution →
   persistence → C2 → lateral → collection → exfil) need specific
   ATT&CK techniques in specific orderings. We run what we need.
3. **Provenance.** Every captured artifact carries a known invocation:
   exact technique, parameters, host, time, sandbox snapshot ID.

## Architecture

Two **UTM** VMs on macOS, sharing a single UTM internal (isolated)
network. Docker is intentionally not in the loop — Windows-in-Docker
on macOS requires KVM acceleration the host doesn't provide, and the
sandbox is single-tenant single-shot work that doesn't benefit from
container orchestration.

```
┌──────────────────────────────────────────────────────────────┐
│  Mac host (macOS, UTM 4+)                                    │
│                                                              │
│  UTM internal network "sandbox-net" (no NAT, no host bridge) │
│    ├──────────────────────────────────────────────┐          │
│    │                                              │          │
│    ▼                                              ▼          │
│  ┌────────────────────┐                ┌──────────────────┐  │
│  │ Windows VM         │                │ Linux VM         │  │
│  │  (sandbox-win)     │                │  (sandbox-lnx)   │  │
│  │  - Windows 11 Pro  │                │  - Ubuntu 22.04  │  │
│  │  - Sysmon          │                │  - auditd        │  │
│  │  - EventLog        │                │  - Zeek (tap)    │  │
│  │  - ART Powershell  │                │  - Suricata (tap)│  │
│  │  - Defender OFF    │                │  - ART Bash      │  │
│  │  - SSH (OpenSSH)   │                │  - SSH server    │  │
│  └────────────────────┘                └──────────────────┘  │
│                                                              │
│  Safe-fire policy:                                           │
│   - UTM network is "Host Only" mode (no NAT, no en0 bridge)  │
│   - Mac pfctl rules drop any pkt from the sandbox subnet     │
│   - Linux VM iptables drops egress except DNS-to-stub        │
│   - Windows firewall blocks outbound except DNS-to-stub      │
└──────────────────────────────────────────────────────────────┘
```

The Linux VM is dual-purpose: it runs Linux atomics AND captures the
network tap (Zeek + Suricata listening on its `enp0s2` interface, which
sees all sandbox-net traffic because UTM's internal-network mode forms
a virtual switch).

## Layout

```
sandbox/
├── README.md                     <- you are here
├── runbook.md                    <- step-by-step first-time bootstrap
├── network/
│   ├── utm-network-setup.md      <- UTM internal-network configuration
│   └── safe-fire-checklist.md    <- verifying no leak before run
├── windows/
│   ├── README.md
│   ├── utm-vm-spec.md            <- CPU/RAM/disk/ISO/network knobs
│   ├── sysmon-config.xml         <- modular Sysmon config (SwiftOnSecurity-derived)
│   └── bootstrap/
│       ├── 01-disable-defender.ps1
│       ├── 02-install-sysmon.ps1
│       ├── 03-enable-eventlog.ps1
│       ├── 04-install-atomic-red-team.ps1
│       ├── 05-create-test-accounts.ps1
│       ├── 06-enable-ssh.ps1
│       └── bootstrap.ps1         <- runs 01..06 in order
├── linux/
│   ├── README.md
│   ├── utm-vm-spec.md
│   ├── bootstrap/
│   │   ├── 01-install-packages.sh
│   │   ├── 02-configure-auditd.sh
│   │   ├── 03-configure-zeek.sh
│   │   ├── 04-configure-suricata.sh
│   │   ├── 05-install-atomic-red-team.sh
│   │   └── bootstrap.sh
│   └── config/
│       ├── audit.rules
│       ├── zeek-site-local.zeek
│       └── suricata.yaml
├── orchestrator/
│   ├── snapshot.sh               <- UTM snapshot of both VMs
│   ├── restore.sh                <- restore both VMs to baseline snapshot
│   ├── run-atomic.sh             <- SSH into VM, invoke Invoke-AtomicTest <T#>
│   ├── harvest.sh                <- pull EVTX/Sysmon/Zeek/Suricata back to host
│   └── safe-fire-check.sh        <- verify isolation pre-run
├── atomics/
│   ├── README.md
│   ├── manifest.yaml             <- techniques + status (covered / pending)
│   └── T1059.001-powershell.yaml <- acceptance reference
└── tests/
    └── test_t1059_001_end_to_end.sh
```

Output of a harvest run lands under `data/raw/sandbox/<run_id>/`
(gitignored). The run_id encodes timestamp + technique + sandbox snapshot
ID; downstream `t-apt-inject` reads from there.

## What this directory does NOT include

- **No tracked atomic-technique outputs.** Real captured EVTX / Sysmon /
  Zeek belong in `data/raw/` (gitignored). The yaml files under
  `atomics/` are invocation specs only.
- **No range deployment.** The sandbox runs on a Mac for one-time-use
  telemetry capture; the captured fixtures are what gets shipped, not
  the sandbox itself.
- **No production safety guarantees.** Atomics are still real
  attack-code invocations. The safe-fire policy + isolated network are
  defence-in-depth; the operator (you) verifies isolation before every
  run via `orchestrator/safe-fire-check.sh`.

## Acceptance

Per `t-sandbox` description:

> A single Atomic technique (e.g., T1059.001 PowerShell) runs end-to-end
> and produces captured EVTX + Sysmon + Zeek output.

`tests/test_t1059_001_end_to_end.sh` is the acceptance script. It
assumes both VMs are already bootstrapped to baseline snapshot; it
runs the atomic and asserts that the harvest produces a non-empty
EVTX file with the expected EventID, a non-empty Sysmon JSONL with
the expected ProcessCreate event, and a non-empty Zeek conn.log
covering the run window.
