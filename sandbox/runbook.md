# Sandbox runbook — first capture via GitHub Actions

Step-by-step from a fresh Mac to first `ACCEPTANCE OK`. Wall-clock
~10 minutes the first time (mostly Atomic Red Team download inside
the runner + the runner's own boot). Subsequent runs take ~3-5 min.

## Prerequisites (one-time host setup)

```bash
brew install gh jq python3
gh auth login              # authenticate against github.com
pip3 install python-evtx   # optional but lets the test assert on EVTX content
```

Verify `gh` is wired to this repo:

```bash
cd /Users/max/Blue-Bench
gh repo view                # should print 'max6012/blue-bench ...'
```

## 1. First capture

Trigger the workflow + wait for it:

```bash
./sandbox/orchestrator/trigger-capture.sh T1059.001
```

What you'll see:

- `gh workflow run` fires the workflow
- The script polls until the run appears (~10s)
- `gh run watch` streams the in-progress steps until terminal state
- Stamp step output prints `run_id=<utc-timestamp>-T1059.001-<rand>`
- Capture step uploads `sandbox-capture-<run_id>` artifact

When the workflow finishes:

```bash
./sandbox/orchestrator/harvest-from-run.sh
```

That downloads the artifact and lays it out under
`data/raw/sandbox/<run_id>/` with the in-runner `manifest.json`.

## 2. Acceptance gate

```bash
./sandbox/tests/test_t1059_001_end_to_end.sh
```

The script:
1. Triggers a fresh workflow run (so the acceptance is reproducible)
2. Waits for completion
3. Downloads the artifact
4. Asserts the EVTX content (powershell.exe in Security 4688 + Sysmon EventID 1)

Successful exit prints:

```
ACCEPTANCE OK: workflow_run_id=<...> gha_run_id=<...>
```

## 3. Recurring use

```bash
./sandbox/orchestrator/trigger-capture.sh T1003.001 -TestNumbers 1
./sandbox/orchestrator/harvest-from-run.sh
```

Each run produces a new `data/raw/sandbox/<run_id>/` and appends a
row to `data/raw/sandbox/manifest.csv` recording (run_id, gha_run_id,
timestamp, total_bytes, file_count).

## Bail-out conditions

- **Workflow fails at the "Run atomic" step** → check `gh run view <id> --log`. Most likely cause: the atomic's GetPrereqs needs binary deps that Atomic Red Team couldn't download (rare; usually GHA's outbound is open).
- **`harvest-from-run.sh` says no artifact** → workflow failed before the upload-artifact step. Check the run logs.
- **Test fails on EVTX content** → the technique ran but didn't generate the expected events. Usually a Defender issue (some channels stay enabled despite the disable step on certain GHA Win images). Inspect the captured EVTX manually via `python -m Evtx.evtx_dump <path>` or load into a Windows host's Event Viewer.

## What the operator does NOT need to do

- Install UTM, VirtualBox, or any local hypervisor
- Maintain a Windows ISO or installation
- Snapshot/restore anything — every workflow run is a fresh runner
- Configure network isolation — GHA runners are sandboxed by Microsoft

## What this trades

- **No isolated network.** GHA runners have real internet egress. Techniques with active network behaviour (HTTP C2, exfil, lateral movement) need destinations pinned to loopback/RFC1918 via `Invoke-AtomicTest --input-args`. Per-technique YAML in `sandbox/atomics/` documents the pin.
- **No Zeek/Suricata tap.** GHA runner is a single host, not a tapped segment. Network observability is via Sysmon EventID 3 (NetworkConnect) + EventID 22 (DNSQuery), captured in-band. For techniques that need PCAP-level capture, fold `pktmon` into the per-technique workflow (not in v1).
- **Baseline OS is Win Server 2022, not Win 11 Pro.** Less mismatch with the IT baseline than an external lab dataset would have, but not zero. Sysmon + EVTX work identically; field shapes are stable.
