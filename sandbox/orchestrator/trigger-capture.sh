#!/usr/bin/env bash
# Trigger a sandbox-atomic-capture workflow run on GitHub Actions and
# wait for it to finish.
#
# Usage:
#   ./trigger-capture.sh T1059.001                  # default TestNumbers=1
#   ./trigger-capture.sh T1059.001 -TestNumbers 1,2
#   ./trigger-capture.sh T1003.001 -TestNumbers 1 --retention-days 7
#
# What it does:
#   1. gh workflow run sandbox-atomic.yml -f technique=... -f test_numbers=...
#   2. Polls `gh run list` until the new run reaches a terminal state
#   3. Prints the run_id (workflow-side) AND the gh run ID (github-side)
#   4. Saves both into /tmp/sandbox-current-run.id for harvest-from-run.sh
#
# Requires:
#   - gh CLI authenticated against the repo's GitHub
#   - jq (brew install jq)

set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
    echo "ABORT: gh CLI not found. Install via: brew install gh" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ABORT: jq not found. Install via: brew install jq" >&2
    exit 1
fi

WORKFLOW=sandbox-atomic.yml

TECH=${1:-}
shift || true

TEST_NUMBERS=1
RETENTION=30

while [[ $# -gt 0 ]]; do
    case "$1" in
        -TestNumbers|--test-numbers) TEST_NUMBERS="$2"; shift 2 ;;
        --retention-days)            RETENTION="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z $TECH ]]; then
    cat >&2 <<EOF
usage: $0 <T-number> [-TestNumbers N[,N...]] [--retention-days D]

examples:
    $0 T1059.001
    $0 T1059.001 -TestNumbers 1,2
    $0 T1003.001 -TestNumbers 1 --retention-days 7
EOF
    exit 2
fi

# --- 1. trigger ------------------------------------------------------

echo "Triggering $WORKFLOW: technique=$TECH test_numbers=$TEST_NUMBERS retention=$RETENTION"

# Record the latest run id BEFORE we trigger so we can identify the new one.
prev_id=$(gh run list --workflow "$WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId // "0"')

gh workflow run "$WORKFLOW" \
    -f technique="$TECH" \
    -f test_numbers="$TEST_NUMBERS" \
    -f retention_days="$RETENTION"

# --- 2. find the new run (poll for ~30s for it to appear) -----------

new_id=""
for i in $(seq 1 30); do
    sleep 2
    candidate=$(gh run list --workflow "$WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId // "0"')
    if [[ "$candidate" != "$prev_id" && "$candidate" != "0" ]]; then
        new_id="$candidate"
        break
    fi
done

if [[ -z $new_id ]]; then
    echo "ABORT: new workflow run did not appear within 60s. Check 'gh run list -w $WORKFLOW'." >&2
    exit 1
fi

echo "Workflow run: $new_id"
echo "  $(gh run view "$new_id" --json url --jq .url)"

# --- 3. poll until terminal -----------------------------------------

echo "Polling for completion..."
gh run watch "$new_id" --exit-status --interval 10

# --- 4. extract the workflow-internal run_id ------------------------

# The "stamp" step echoes "run_id=<id>" to stdout, captured in the log.
log=$(gh run view "$new_id" --log)
workflow_run_id=$(echo "$log" | grep -oE 'run_id=[0-9a-zA-Z-]+' | head -1 | cut -d= -f2 || true)

if [[ -z $workflow_run_id ]]; then
    echo "WARN: could not extract workflow_run_id from logs; using GHA run id as fallback."
    workflow_run_id="gha-$new_id"
fi

# --- 5. record both ids ---------------------------------------------

cat > /tmp/sandbox-current-run.id <<EOF
WORKFLOW_RUN_ID=$workflow_run_id
GHA_RUN_ID=$new_id
TECHNIQUE=$TECH
TEST_NUMBERS=$TEST_NUMBERS
EOF

echo ""
echo "DONE."
echo "WORKFLOW_RUN_ID: $workflow_run_id"
echo "GHA_RUN_ID:      $new_id"
echo ""
echo "Pull captures with:"
echo "    ./harvest-from-run.sh"
