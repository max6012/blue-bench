#!/usr/bin/env bash
# Download the sandbox-capture artifact from a completed GHA workflow
# run and land it under data/raw/sandbox/<run_id>/.
#
# Usage:
#   ./harvest-from-run.sh                  # uses /tmp/sandbox-current-run.id
#   ./harvest-from-run.sh <gha_run_id>     # explicit GHA run id

set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
    echo "ABORT: gh CLI not found." >&2
    exit 1
fi

REPO_ROOT=${BLUE_BENCH_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}

GHA_RUN_ID=${1:-}
WORKFLOW_RUN_ID=""

if [[ -z $GHA_RUN_ID ]]; then
    if [[ -f /tmp/sandbox-current-run.id ]]; then
        # shellcheck disable=SC1091
        source /tmp/sandbox-current-run.id
        GHA_RUN_ID=${GHA_RUN_ID:-}
    fi
fi

if [[ -z $GHA_RUN_ID ]]; then
    echo "ABORT: no GHA run id (arg) and /tmp/sandbox-current-run.id missing." >&2
    echo "       Run trigger-capture.sh first, or pass the run id explicitly:" >&2
    echo "       gh run list --workflow sandbox-atomic.yml" >&2
    exit 2
fi

# Find the artifact name (sandbox-capture-<workflow_run_id>).
artifact=$(gh run view "$GHA_RUN_ID" --json artifacts \
           --jq '.artifacts[] | select(.name | startswith("sandbox-capture-")) | .name' | head -1)
if [[ -z $artifact ]]; then
    echo "ABORT: no sandbox-capture-* artifact attached to run $GHA_RUN_ID" >&2
    exit 1
fi
echo "Artifact: $artifact"

# Extract the workflow_run_id from the artifact name suffix.
run_id="${artifact#sandbox-capture-}"
out_dir="$REPO_ROOT/data/raw/sandbox/$run_id"
mkdir -p "$out_dir"

echo "Downloading $artifact -> $out_dir"
gh run download "$GHA_RUN_ID" -n "$artifact" -D "$out_dir"

# gh extracts the artifact contents into out_dir/. The harvest.ps1
# laid them out as ./harvest/<run_id>/{windows,manifest.json}; the
# artifact upload preserves that under the artifact's content root.
# Normalise: if there's a nested directory, hoist its contents up.
nested=$(find "$out_dir" -maxdepth 2 -type d -name "$run_id" | head -1)
if [[ -n $nested && $nested != "$out_dir" ]]; then
    mv "$nested"/* "$out_dir/"
    rmdir "$nested" 2>/dev/null || true
fi

# Append to the per-corpus manifest index.
INDEX="$REPO_ROOT/data/raw/sandbox/manifest.csv"
if [[ ! -f $INDEX ]]; then
    echo "run_id,gha_run_id,harvested_at_utc,total_bytes,file_count" > "$INDEX"
fi

mpath="$out_dir/manifest.json"
if [[ -f $mpath ]]; then
    total_bytes=$(python3 -c "import json; print(json.load(open('$mpath'))['total_bytes'])")
    file_count=$(python3 -c "import json; print(len(json.load(open('$mpath'))['files']))")
else
    total_bytes=$(find "$out_dir" -type f -not -name 'manifest.csv' -exec stat -f '%z' {} \; 2>/dev/null | awk '{s+=$1} END {print s+0}')
    file_count=$(find "$out_dir" -type f -not -name 'manifest.csv' | wc -l | awk '{print $1}')
fi
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$run_id,$GHA_RUN_ID,$ts,$total_bytes,$file_count" >> "$INDEX"

echo ""
echo "OK: harvested -> $out_dir"
echo "    $file_count files, $total_bytes bytes total."
