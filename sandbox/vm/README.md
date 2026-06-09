# sandbox/vm/ — Mac-local VM capture substrate

Work-in-progress. Authoritative state lives in PlanDB (project
`p-w3i5`, task `t-utm-perf`). This file is a navigation pointer
only; do not duplicate task descriptions here.

## Acceptance (binary)

1. T1059.001 E2E < 30 min wall-clock per capture.
2. Sysmon EID 1 + EID 22 fire in the harvested EVTX.
3. Capture schema matches GHA harvest output.

## PlanDB sub-tasks

```
t-qemu-host        ─┬─▶ t-win-unattend ─▶ t-win-install ─┬─▶ t-guest-tooling ─▶ t-atomic-perf ─▶ t-perf-report
                    └─▶ t-winrm-client ──────────────────┘
```

Read each with `plandb task get <id>`. The `c-hbmj` context entry
records why we pivoted off the GHA-runner shape on 2026-06-09.

## What lands here

`autounattend.xml`, plus shell scripts `build-unattended-iso.sh`,
`install-windows.sh`, `winrm-exec.sh`, `deploy-tooling.sh`,
`fire-and-harvest.sh`. The qcow2 baselines do NOT — they live
under `~/Library/Application Support/bb-sandbox-vm/`.
