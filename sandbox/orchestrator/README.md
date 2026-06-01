# Orchestrator scripts (operator's Mac)

Two shell scripts that drive the GHA-based sandbox from the
operator's local machine.

| Script | Purpose |
|---|---|
| `trigger-capture.sh` | `gh workflow run` + poll until done; records `WORKFLOW_RUN_ID` and `GHA_RUN_ID` |
| `harvest-from-run.sh` | `gh run download` of the sandbox-capture artifact into `data/raw/sandbox/<run_id>/` |

## Requirements

- `gh` CLI authenticated against the repo's GitHub (`brew install gh && gh auth login`)
- `jq` (`brew install jq`)
- `python3` (used for parsing the artifact's manifest.json)

## Steady-state loop

```bash
./trigger-capture.sh T1003.001 -TestNumbers 1     # fire + wait
./harvest-from-run.sh                             # pull artifact
```

Each run lands under `data/raw/sandbox/<run_id>/` with the in-runner
`manifest.json` carrying per-file sha256s plus the `gha_run_url`
pointing back at the workflow run on GitHub.

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `BLUE_BENCH_ROOT` | repo root (auto-detected) | Where `data/raw/sandbox/` lives |

`trigger-capture.sh` writes `/tmp/sandbox-current-run.id` so
`harvest-from-run.sh` can be called with no arguments.
