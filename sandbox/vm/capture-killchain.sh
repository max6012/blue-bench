#!/usr/bin/env bash
# Capture the full APT kill-chain technique set (generators/apt_inject/
# killchain.tsv) from the AWS sandbox, one technique per
# fire-and-harvest run. Each lands its own data/raw/sandbox/<run>/
# (EVTX+Sysmon+Zeek). Writes a chain index mapping stage->run dir so
# the apt_inject harness knows which capture is which kill-chain stage.
#
# Usage: ./capture-killchain.sh

set -uo pipefail   # NOT -e: one technique failing must not abort the chain
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
MANIFEST="$REPO_ROOT/generators/apt_inject/killchain.tsv"
IDX="$REPO_ROOT/data/raw/sandbox/killchain-index.tsv"

mkdir -p "$(dirname "$IDX")"
echo -e "# stage\ttechnique\ttest\trun_dir\tstatus\t$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$IDX"

# Read the manifest on FD 3, not stdin: fire-and-harvest.sh runs ssh,
# which reads stdin by default and would drain the rest of the
# manifest after the first iteration (the run stopped after 1/10).
ok=0; fail=0
while IFS=$'\t' read -r stage tech test attack note <&3; do
  [[ -z $stage || $stage == \#* ]] && continue
  echo ""
  echo "=================================================================="
  echo "  $stage  ->  $tech test $test  ($note)"
  echo "=================================================================="
  before=$(ls -d "$REPO_ROOT"/data/raw/sandbox/*-"$tech"-* 2>/dev/null | wc -l)
  if "$HERE/fire-and-harvest.sh" "$tech" "$test" 2>&1 | tail -8; then
    run_dir=$(ls -dt "$REPO_ROOT"/data/raw/sandbox/*-"$tech"-* 2>/dev/null | head -1)
    after=$(ls -d "$REPO_ROOT"/data/raw/sandbox/*-"$tech"-* 2>/dev/null | wc -l)
    if [[ $after -gt $before && -n $run_dir ]]; then
      echo -e "$stage\t$tech\t$test\t$(basename "$run_dir")\tOK" >> "$IDX"
      ok=$((ok+1))
    else
      echo -e "$stage\t$tech\t$test\t-\tNO_NEW_DIR" >> "$IDX"; fail=$((fail+1))
    fi
  else
    echo -e "$stage\t$tech\t$test\t-\tFIRE_FAILED" >> "$IDX"; fail=$((fail+1))
  fi
done 3< "$MANIFEST"

echo ""
echo "=================================================================="
echo "  KILL-CHAIN CAPTURE SUMMARY: $ok ok, $fail failed"
echo "=================================================================="
column -t -s$'\t' "$IDX" | grep -v '^#'
echo ""
echo "index: $IDX"
