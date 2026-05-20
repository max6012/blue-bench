# Blue-Bench Phase 2 Evaluation Skill

How to run, score, and interpret Phase 2 (live tool call) evaluations.

## What Phase 2 tests

Ten prompts across nine categories, each requiring live tool calls against Elasticsearch, Wazuh, OpenEDR, and forensic tools via the Blue-Bench MCP server:

| Category | Prompt | Key tools |
|----------|--------|-----------|
| triage | p2-01 | search_alerts, count_by_field |
| malware | p2-02 | search_alerts, get_connections, count_by_field |
| exfil | p2-03 | search_alerts, get_connections |
| lateral | p2-04 | search_alerts, get_connections |
| account | p2-05 | get_agent_alerts, wazuh_list_agents |
| detection | p2-06 | validate_sigma_rule |
| recon | p2-07 | nmap_scan |
| correlation | p2-08 | search_alerts, get_connections, get_agent_alerts, get_detections |
| forensic | p2-09 | list_evidence, file_hash |
| forensic | p2-10 | file_metadata, strings_extract |

Four scoring dimensions (0–3 each, 120 pts max): `tool_usage`, `findings`, `reasoning`, `response_quality`

Thresholds to clear: `overall ≥ 80%`, `tool_usage ≥ 85%`, `findings ≥ 95%`

## Task class and engagement scope

The analyst CLI prompts for a task class at session start (`require_task_class: true` by default). For eval runs and open-ended investigation, disable the prompt in the profile:

```yaml
require_task_class: false
```

The banner then reads `Task class: (disabled by profile)`. To scope a session to specific verifiable classes (reduces hallucination risk by constraining what the model is asked to do):

```yaml
require_task_class: true
allowed_task_classes:
  - ALERT_TRIAGE
  - LOG_QUERY
  - IOC_EXTRACTION
  - SIGMA_DRAFT
```

Verifiable classes (`ALERT_TRIAGE`, `LOG_QUERY`, `IOC_EXTRACTION`, `SIGMA_DRAFT`) have mechanical acceptance criteria and are safer for unattended or parallel sessions. `THREAT_NARRATIVE` and `INTENT_ASSESSMENT` are operator-led only — the model may assist but cannot own the conclusion. For Phase 2 eval, `require_task_class: false` is the right setting; scoring is handled by the rubric, not the engagement scope layer.

## Pre-flight (CRITICAL — do not skip)

```bash
source .venv/bin/activate

# 1. Reseed Elasticsearch immediately before starting qualify.
#    All docs are stamped with timestamps spread over the last 45 minutes.
#    The MCP tools default to a 240-minute lookback — safe for runs up to ~3 hours.
python scripts/seed_es.py

# 2. Verify counts
curl -s "http://localhost:9200/_cat/indices?h=index,docs.count" | sort
# Expect: logstash-suricata-alerts ~169, zeek-conn ~394, wazuh-alerts ~109
```

If the run takes longer than ~3 hours (unlikely with GPU, possible on CPU-only), reseed before the run starts and confirm `timerange_minutes` defaults in `blue_bench_mcp/tools/elastic.py` are ≥ 240.

## Run qualify

```bash
source .venv/bin/activate
blue-bench qualify --profile <profile-name> --phase 2
# e.g.: blue-bench qualify --profile qwen35-9b-uncoached --phase 2
```

Output lands in `results/<YYYYMMDD-HHMMSS>-<profile>/`.  
Each prompt trace: `results/<run_dir>/prompts/p2-0N.json`

Typical wall time: 40 min (GPU) to 4 hours (CPU-only 9B model).

Run in background for CPU-bound runs:

```bash
nohup blue-bench qualify --profile <profile> --phase 2 > /tmp/p2-run.log 2>&1 &
# Monitor:
tail -f /tmp/p2-run.log
```

## Diagnosing tool-looping (key failure mode)

Tool-looping: the model makes tool calls every turn and never writes a final text response. Symptoms in the log:

```
[ 3/10] p2-03 (exfil) ...
         225.7s  turns= 8  tool_calls= 6  answer=1962c    ← good
[ 4/10] p2-04 (lateral) ...
         171.4s  turns=10  tool_calls=10  answer=0c ERROR: max_turns (10) exhausted without final answer  ← loop
```

Key indicators of looping:
- `turns=10  tool_calls=10` — one tool call per turn, no synthesis turns
- `answer=0c` or very short (< 200c) with ERROR
- `final_answer` in trace = empty string or just an opening sentence like "I'll investigate..."

Root causes by model family:
- Qwen 3.5 9B (uncoached): loops on deep investigation prompts (malware, lateral, account). Triage, forensic, recon, correlation categories complete successfully.
- Likely fix: coaching hints to "synthesize after 4-5 tool calls" or system prompt instruction to limit exploration depth.

To read a trace directly:
```bash
python3 -c "
import json
d = json.load(open('results/<run_dir>/prompts/p2-04.json'))
print('answer:', d.get('final_answer','')[:200])
print('error:', d.get('error'))
"
```

## Score each trace

For prompts that produced an answer, score against the rubric dimensions and the `expected_findings` synonym sets in each prompt YAML.

Findings scoring shortcut — check each synonym set against the final_answer:
```python
import json, re
spec = yaml.safe_load(open('blue_bench_eval/prompts/p2-04.yaml'))
answer = json.load(open('results/<run_dir>/prompts/p2-04.json'))['final_answer'] or ''
for fset in spec['expected_findings']:
    matched = any(s.lower() in answer.lower() for s in fset['synonyms'])
    print(fset['synonyms'][0], '✓' if matched else '✗')
```

Write scored JSON to `results/<run_dir>/scored/p2-0N.json`:

```json
{
  "prompt_id": "p2-01",
  "dimensions": {
    "tool_usage": {"score": 3, "justification": "..."},
    "findings": {"score": 3, "justification": "..."},
    "reasoning": {"score": 3, "justification": "..."},
    "response_quality": {"score": 3, "justification": "..."}
  },
  "verdict": "PASS",
  "hallucinations": []
}
```

Verdicts:
- `PASS` — all dims ≥ 2 AND tool_usage ≥ 2 AND findings ≥ 2
- `PARTIAL` — no dim is 0, at least one is 1
- `FAIL` — any dim is 0 (tool-looping produces findings=0, reasoning=0, response_quality=0 → automatic FAIL)

## Run aggregate

```bash
blue-bench aggregate results/<run_dir> --phase 2
```

Writes `results/<run_dir>/BLUF.md` with threshold table, per-dimension scores, per-category breakdown, and per-prompt verdict table.

## Interpreting results

Phase 2 failures fall into two distinct patterns:

**Pattern A — Complete failure (tool-looping)**:  
`tool_usage ≈ 1-2, findings = 0, reasoning = 0, response_quality = 0`  
The model made all its turns on tool calls. No synthesis. Category-level score ≈ 8-17%.  
Fix: coaching system prompt with explicit synthesis instruction.

**Pattern B — Partial failure (missing tools)**:  
`tool_usage = 1, findings ≥ 1, reasoning ≥ 1, response_quality ≥ 1`  
The model answered but skipped expected tools or used wrong field names.  
Fix: tool docstring improvements or coaching hints about tool selection order.

**Pattern C — Success**:  
`tool_usage = 3, findings = 3, reasoning = 3, response_quality = 3`  
All expected tools called, all findings matched, coherent synthesis.

## Baselines

| Model | Overall | Tool Usage | Findings | Phase 2 verdict |
|-------|---------|------------|---------|-----------------|
| Gemma 4 uncoached (archive) | ~83% | ~87% | ~96% | PASS |
| **Qwen 3.5 9B uncoached** | **73.3%** | **83.3%** | **70.0%** | **FAIL** |

Qwen 9B fails Phase 2 uncoached. 7/10 prompts score 100% individually — the failure is concentrated in three deep-investigation categories (malware, lateral, account) where the model loops. This is a coaching problem, not a capability ceiling.

## Data staleness debugging

If ES queries return `(no results — check field name, index pattern, or time range)`:

```bash
# Check latest doc timestamp
curl -s "http://localhost:9200/logstash-suricata-alerts/_search?size=1&sort=@timestamp:desc" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['hits']['hits'][0]['_source']['@timestamp'])"

# Check current time
date -u
```

If the latest doc is older than the `timerange_minutes` default (240 min), reseed:
```bash
source .venv/bin/activate && python scripts/seed_es.py
```

Kill the running qualify and restart after reseeding — stale data causes the model to loop trying different queries.
