# Atomics catalogue

Manifest of Atomic Red Team techniques the sandbox is expected to run,
plus per-technique invocation records.

| File | Purpose |
|---|---|
| `manifest.yaml` | Master list (technique, test_number, target_os, status, purpose) |
| `T1059.001-powershell.yaml` | Acceptance reference invocation + expected telemetry |

## Adding a technique

1. Add an entry to `manifest.yaml` with status `pending`.
2. Optionally write a per-technique YAML alongside `T1059.001-powershell.yaml`
   if the invocation has non-trivial `--input-args` or expected-output
   assertions.
3. Run the technique via `orchestrator/run-atomic.sh T1xxx.xxx`.
4. Update the manifest entry to `captured` (or `failed` with a reason).

## What's tracked in this directory

YAML invocation specs only. **No captured telemetry.** Real EVTX /
Sysmon / Zeek / Suricata outputs go to `data/raw/sandbox/<run_id>/`
(gitignored).
