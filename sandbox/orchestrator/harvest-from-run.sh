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
#
# `gh run view --json artifacts` is NOT a valid field on the gh CLI;
# artifacts live on a different REST endpoint than the run object.
# Verified live during the run-5 acceptance: `gh run view --json
# artifacts` errors out with "Unknown JSON field". `gh api` resolves
# {owner}/{repo} from the cwd's git remote (same as `gh run download`
# below), so no separate lookup is needed.
artifact=$(gh api "repos/{owner}/{repo}/actions/runs/${GHA_RUN_ID}/artifacts" \
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

# gh extracts the artifact contents into out_dir/. harvest.ps1 laid
# them out as ./harvest/<run_id>/{windows,manifest.json}; the
# upload-artifact action preserves that path under the artifact root,
# so on disk we end up with out_dir/<run_id>/{windows,manifest.json}.
# Hoist the contents one level up.
#
# Use the explicit nested path rather than find -- find -name "$run_id"
# (without -mindepth 1) matches the out_dir itself, since its basename
# equals $run_id. Subtle but bites: the original find-based logic
# returned out_dir as the first hit, the `!= "$out_dir"` check failed,
# and the hoist was silently skipped.
nested="$out_dir/$run_id"
if [[ -d $nested ]]; then
    # dotglob: hoist hidden files too if the artifact ever ships them.
    # compgen guard: an empty nested dir would expand `$nested/*` to
    # zero words and run `mv` with only a destination arg, which exits
    # non-zero and aborts under `set -e`. (nullglob alone does NOT
    # prevent this; it CAUSES the zero-arg case.)
    shopt -s dotglob
    if compgen -G "$nested/*" >/dev/null; then
        mv "$nested"/* "$out_dir/"
    fi
    shopt -u dotglob
    rmdir "$nested" 2>/dev/null || true
fi

# Manifest is load-bearing for both the corpus index row below and the
# acceptance test's downstream assertions. The workflow-side harvest.ps1
# always writes it; absence means the artifact layout has drifted or
# the hoist broke silently. Fail fast rather than recording a
# misleading-success row in manifest.csv.
if [[ ! -f "$out_dir/manifest.json" ]]; then
    echo "ABORT: $out_dir/manifest.json missing after hoist; harvest layout broken." >&2
    echo "       Investigate: $(ls -la "$out_dir" 2>&1 | head -5)" >&2
    exit 1
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
