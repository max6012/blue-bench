# Sandbox — GitHub Actions Atomic Red Team capture

**PlanDB:** `t-sandbox` (project `p-w3i5`, bb-heavy-telemetry).

Ephemeral GitHub Actions Windows runner whose sole purpose is to run
**real** Atomic Red Team / Caldera techniques on an isolated cloud
runner and capture the resulting EVTX / Sysmon / PowerShell telemetry.
The captured fixtures are pulled into `data/raw/sandbox/<run_id>/`
locally and consumed by `t-apt-inject`, which time-shifts and
host-rewrites them into the IT baseline corpus.

## Why GHA (and not Mac local / Docker)

- **Zero local infrastructure.** No VMs to provision, no UTM, no
  Docker. The runner is gone the moment the workflow exits.
- **Reproducible.** Every run starts from the same vanilla Azure
  Windows Server 2022 image; no snapshot drift, no "did I forget to
  revert."
- **Defender / EventLog / Sysmon all behave as on real Windows** —
  GHA's `windows-latest` is a real Windows installation, not a
  container.
- **Free for the public Blue-Bench repo** (GitHub-hosted minutes).

The trade is that the runner has **real internet egress**. Atomics
with active network behaviour (T1071.001 HTTP C2, T1041 exfil, etc.)
need destinations pinned to loopback/RFC1918 via Atomic Red Team's
`--input-args` so the workflow's outbound traffic stays inside the
runner. Per-technique YAML in `atomics/` documents the pin.

## Architecture

```
Operator (Mac)
   │  trigger-capture.sh T1059.001 -TestNumbers 1
   ▼
gh workflow run sandbox-atomic.yml  --inputs technique=T1059.001 test_numbers=1
   │
   ▼
GitHub Actions: ephemeral windows-latest runner (Azure)
   ├── 01 disable Defender
   ├── 02 install Sysmon + modular config
   ├── 03 enable EventLog channels (4688 + cmdline, PS module/script-block/transcripts)
   ├── 04 install Atomic Red Team (Invoke-AtomicTest)
   ├── 05 run the technique
   ├── 06 flush wait
   └── 07 harvest -> upload artifact "sandbox-capture-<run_id>"
   │
   ▼
Operator: harvest-from-run.sh <run_id>
   │  gh run download -> data/raw/sandbox/<run_id>/
   ▼
   Captures available for t-apt-inject ingestion
```

## Layout

```
.github/workflows/
└── sandbox-atomic.yml                <- the workflow definition

sandbox/
├── README.md                         <- you are here
├── runbook.md                        <- step-by-step first capture
├── workflow/                         <- scripts run inside the GHA runner
│   ├── 01-disable-defender.ps1
│   ├── 02-install-sysmon.ps1
│   ├── 03-enable-eventlog.ps1
│   ├── 04-install-atomic-red-team.ps1
│   ├── sysmon-config.xml
│   └── harvest.ps1                   <- in-runner EVTX export + zip
├── orchestrator/                     <- scripts run on the operator's Mac
│   ├── trigger-capture.sh            <- gh workflow run + poll
│   ├── harvest-from-run.sh           <- gh run download -> data/raw/sandbox/
│   └── README.md
├── atomics/                          <- technique catalogue
│   ├── manifest.yaml
│   ├── T1059.001-powershell.yaml
│   └── README.md
└── tests/
    └── test_t1059_001_end_to_end.sh  <- acceptance: trigger + harvest + assert
```

Output of a harvest run lands under `data/raw/sandbox/<run_id>/`
(gitignored). The `<run_id>` encodes timestamp + technique + random
suffix; downstream `t-apt-inject` reads from there.

## What this directory does NOT include

- **No tracked atomic-technique outputs.** Real captured EVTX /
  Sysmon belong in `data/raw/`. The YAML files under `atomics/` are
  invocation specs only.
- **No range deployment.** The sandbox runs on GHA for one-time-use
  telemetry capture; the captured fixtures are what gets shipped, not
  the workflow itself.
- **No network tap.** GHA runners are single-host VMs; we capture
  Sysmon EventID 3 (NetworkConnect) + EventID 22 (DNSQuery) in-band
  rather than running Zeek/Suricata on a separate interface. For
  techniques requiring richer network capture (PCAP-level), we fold
  in `pktmon` (Windows built-in) as a per-technique opt-in inside the
  workflow.

## Acceptance

> A single Atomic technique (e.g., T1059.001 PowerShell) runs end-to-end
> and produces captured EVTX + Sysmon output.

`tests/test_t1059_001_end_to_end.sh` is the acceptance script. It
triggers the workflow, waits for completion, downloads the artifact,
and asserts that the harvested EVTX files contain the expected
EventID 4688 and Sysmon EventID 1 records referencing
`powershell.exe`.
