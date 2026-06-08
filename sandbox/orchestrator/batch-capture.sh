#!/usr/bin/env bash
# Fire the sandbox-atomic-capture workflow once per queued technique
# (sequentially), harvest each artifact, and record outcomes. Does NOT
# write back to sandbox/atomics/manifest.yaml -- per-capture provenance
# lives in data/raw/sandbox/manifest.csv + the per-run manifest.json.
#
# Designed for "capture every queued technique in one orchestration
# pass" so per-technique bugs surface together and can be addressed
# in a single fix PR rather than scattered one-at-a-time iterations.
#
# Usage:
#   ./batch-capture.sh                  # fire the full default queue
#   ./batch-capture.sh --dry-run        # print the plan without firing
#   ./batch-capture.sh --only T1003.001 # fire only the named technique(s); comma OK
#   ./batch-capture.sh --skip T1041     # skip the named technique(s)
#
# Per-technique outcomes go to /tmp/sandbox-batch-<timestamp>.log and
# are summarised on stdout at the end. Failures don't abort the
# orchestration; the summary tells you which to re-run after the fix.

set -uo pipefail   # NOT -e: a single technique failure must NOT abort the batch

# ---------------------------------------------------------------------
# Technique queue.
#
# Format: tab-separated lines of
#     <id>  <test_numbers>  <start_local_listener>  <input_args_ps_literal>
# where:
#   - input_args is a PowerShell-hashtable literal evaluated inside the
#     workflow at runtime ("" = use atomic defaults)
#   - start_local_listener is "true" or "false"; when true the workflow
#     starts a python http.server on 127.0.0.1:8000 before the atomic
#
# T1059.004 (Linux) and T1021.002 (multi-host lateral) are out of
# scope for the current windows-latest single-runner workflow and are
# omitted from the default queue.
# ---------------------------------------------------------------------
QUEUE=$(cat <<'EOF'
T1059.001	1	false
T1059.003	1	false
T1003.001	1	false
T1547.001	1	false
T1053.005	1	false
T1218.005	1	false
T1071.001	1	true	@{ domain = 'http://127.0.0.1:8000' }
T1041	1	true	@{ destination_url = 'http://127.0.0.1:8000/' }
EOF
)

# ---------------------------------------------------------------------

WORKFLOW=sandbox-atomic.yml
DRY_RUN=0
ONLY=""
SKIP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --only)    ONLY="$2"; shift 2 ;;
        --skip)    SKIP="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if ! command -v gh >/dev/null 2>&1; then
    echo "ABORT: gh CLI not found." >&2; exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ABORT: jq not found." >&2; exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

ts=$(date -u +%Y%m%dT%H%M%SZ)
LOG="/tmp/sandbox-batch-${ts}.log"
SUMMARY=()   # one element per technique: "<id>:<status>:<run_id_or_err>"

in_csv() { [[ ",$1," == *",$2,"* ]]; }

fire_one() {
    local tech="$1" tns="$2" listen="$3" iargs="$4"
    local label="$tech tests=$tns listener=$listen"
    [[ -n $iargs ]] && label="$label input_args=$iargs"

    echo ""
    echo "=========================================================="
    echo "  $label"
    echo "=========================================================="

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY RUN] would fire: gh workflow run $WORKFLOW -f technique=$tech \
-f test_numbers=$tns -f start_local_listener=$listen ${iargs:+-f input_args=\"$iargs\"}"
        SUMMARY+=("$tech:DRY:n/a")
        return 0
    fi

    # Capture the latest run id before firing so we can identify the new one.
    local prev_id
    prev_id=$(gh run list --workflow "$WORKFLOW" --limit 1 --json databaseId \
              --jq '.[0].databaseId // "0"')

    local fire_args=( -f "technique=$tech" -f "test_numbers=$tns"
                       -f "start_local_listener=$listen" )
    if [[ -n $iargs ]]; then
        fire_args+=( -f "input_args=$iargs" )
    fi

    if ! gh workflow run "$WORKFLOW" "${fire_args[@]}" 2>&1 | tee -a "$LOG"; then
        SUMMARY+=("$tech:DISPATCH_FAILED:see-$LOG")
        return 0
    fi

    # Poll up to 90s for the new run to appear in the list.
    local new_id="" cand
    for i in $(seq 1 30); do
        sleep 3
        cand=$(gh run list --workflow "$WORKFLOW" --limit 1 --json databaseId \
               --jq '.[0].databaseId // "0"')
        if [[ "$cand" != "$prev_id" && "$cand" != "0" ]]; then
            new_id="$cand"; break
        fi
    done
    if [[ -z $new_id ]]; then
        echo "  ABORT: new run id never appeared" | tee -a "$LOG"
        SUMMARY+=("$tech:RUN_ID_TIMEOUT:n/a")
        return 0
    fi

    echo "  run id: $new_id  $(gh run view "$new_id" --json url --jq .url)" | tee -a "$LOG"

    # Wait for completion. 25min hard ceiling per workflow's own
    # timeout-minutes: 30 so we exit polling before the workflow does.
    local elapsed=0
    while :; do
        local st
        st=$(gh run view "$new_id" --json status --jq .status 2>/dev/null || echo "unknown")
        if [[ "$st" == "completed" ]]; then break; fi
        if (( elapsed > 1500 )); then
            echo "  ABORT: poll timeout after ${elapsed}s; run may still be running" | tee -a "$LOG"
            SUMMARY+=("$tech:POLL_TIMEOUT:run=$new_id")
            return 0
        fi
        sleep 30
        elapsed=$((elapsed + 30))
        echo "  ... still $st (${elapsed}s elapsed)"
    done

    local conclusion
    conclusion=$(gh run view "$new_id" --json conclusion --jq .conclusion)
    echo "  conclusion: $conclusion" | tee -a "$LOG"

    if [[ "$conclusion" != "success" ]]; then
        SUMMARY+=("$tech:WORKFLOW_FAILED:run=$new_id conclusion=$conclusion")
        return 0
    fi

    # Harvest the artifact.
    if "$HERE/harvest-from-run.sh" "$new_id" 2>&1 | tee -a "$LOG"; then
        # Extract the run_id (workflow-side) from the artifact name.
        local artifact
        artifact=$(gh api "repos/{owner}/{repo}/actions/runs/${new_id}/artifacts" \
                   --jq '.artifacts[] | select(.name | startswith("sandbox-capture-")) | .name' | head -1)
        local wf_run_id="${artifact#sandbox-capture-}"
        SUMMARY+=("$tech:OK:run=$new_id wf_run=$wf_run_id")
    else
        SUMMARY+=("$tech:HARVEST_FAILED:run=$new_id")
    fi
}

# ---------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------

while IFS=$'\t' read -r tech tns listen iargs; do
    [[ -z $tech || $tech == '#'* ]] && continue
    if [[ -n $ONLY ]] && ! in_csv "$ONLY" "$tech"; then continue; fi
    if [[ -n $SKIP ]] &&     in_csv "$SKIP" "$tech"; then continue; fi
    fire_one "$tech" "$tns" "$listen" "$iargs"
done <<< "$QUEUE"

# ---------------------------------------------------------------------
# Summary
#
# manifest.yaml write-back is OUT of scope for this script -- the
# manifest stays as candidate-pool documentation; per-capture
# provenance lives in data/raw/sandbox/manifest.csv (written by
# harvest-from-run.sh) and the per-run manifest.json. A status-flip
# from `pending` -> `captured` in manifest.yaml is a separate small
# change if we want the manifest to become a real ledger.
# ---------------------------------------------------------------------

echo ""
echo "=========================================================="
echo "  BATCH SUMMARY  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "=========================================================="
ok=0; fail=0
# Guard the expansion: on bash 3.2 + `set -u`, `"${SUMMARY[@]}"` on an
# empty array throws `SUMMARY[@]: unbound variable` and aborts the
# summary entirely. Reproduces on the operator's default macOS bash
# under `--only T-typo` (no matching technique) or
# `--skip T1059.001,...` covering the full queue.
if (( ${#SUMMARY[@]} )); then
    for line in "${SUMMARY[@]}"; do
        tech="${line%%:*}"
        rest="${line#*:}"
        status="${rest%%:*}"
        detail="${rest#*:}"
        printf "  %-12s %-20s %s\n" "$tech" "$status" "$detail"
        case "$status" in
            OK)  ok=$((ok+1))   ;;
            DRY) : ;;
            *)   fail=$((fail+1));;
        esac
    done
else
    echo "  (no techniques selected -- --only filter matched nothing, or --skip emptied the queue)"
fi
echo ""
echo "  $ok ok, $fail failed.  Full log: $LOG"

[[ $fail -eq 0 ]] || exit 1
