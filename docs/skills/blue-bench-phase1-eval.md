# Blue-Bench Phase 1 Evaluation Skill

How to run, score, and interpret Phase 1 (no-tool) evaluations.

## What Phase 1 tests

Nine prompts across three categories — each embeds all required data inline so no live tool calls are needed:

| Category | Prompts | What it measures |
|----------|---------|-----------------|
| `threat_hunting` | p1-01, p1-02, p1-03 | Log analysis on embedded Zeek/Suricata data |
| `detection_rules` | p1-04, p1-05, p1-06 | Sigma + YARA authoring and refinement |
| `forensics` | p1-07, p1-08, p1-09 | Timeline reconstruction, artifact interpretation, Wazuh triage |

Five scoring dimensions (0–3 each, 135 pts max):  
`technical_accuracy`, `completeness`, `operational_utility`, `reasoning_quality`, `hallucination_rate`

Thresholds to clear: `overall ≥ 74%`, `technical_accuracy ≥ 70%`, `operational_utility ≥ 70%`.

## Pre-flight

Phase 1 uses embedded data only — no Elasticsearch dependency. But confirm the venv is active:

```bash
source .venv/bin/activate
blue-bench --help   # should respond
```

No `seed_es.py` needed for Phase 1.

## Run qualify

```bash
source .venv/bin/activate
blue-bench qualify --profile <profile-name> --phase 1
# e.g.: blue-bench qualify --profile qwen35-9b-uncoached --phase 1
```

Output lands in `results/<YYYYMMDD-HHMMSS>-<profile>-phase1/prompts/`.

Typical wall time: ~25 min for a 9B model on CPU.

**Critical**: prompts have `expected_tools: []`, which triggers `disable_tools=True` in the runner. Models that call tools anyway get their calls silently dropped and must produce a text answer within `max_turns=1`.

### Known Qwen 3.5 9b behavior

Qwen fabricates pseudo tool-call markdown blocks (e.g., `search_alerts(...)` with invented result rows) even with tools disabled. This is a hallucination pattern, not a system bug. Score the final analysis on its merits; document the fabricated block in `hallucinations[]`.

## Score each trace manually

Read each trace from `results/<run_dir>/prompts/p1-0N.json`, then write a scored JSON to `results/<run_dir>/scored/p1-0N.json`:

```json
{
  "prompt_id": "p1-01",
  "dimensions": {
    "technical_accuracy": {"score": 2, "justification": "..."},
    "completeness": {"score": 3, "justification": "..."},
    "operational_utility": {"score": 2, "justification": "..."},
    "reasoning_quality": {"score": 3, "justification": "..."},
    "hallucination_rate": {"score": 3, "justification": "..."}
  },
  "verdict": "PASS",
  "hallucinations": []
}
```

Verdicts:
- `PASS` — all dimensions ≥ 2 AND both key dims (`technical_accuracy`, `operational_utility`) ≥ 2
- `PARTIAL` — no dimension is 0, at least one dimension is 1
- `FAIL` — any dimension is 0

## Run aggregate

```bash
blue-bench aggregate results/<run_dir> --phase 1
```

Writes `results/<run_dir>/BLUF.md` with threshold table, per-dimension scores, per-category breakdown, and per-prompt verdict table.

## Interpreting results

| Hallucination rate (avg) | What it means |
|--------------------------|---------------|
| ≥ 77% (avg score ≥ 2.3) | Model stays grounded; minor fabrications only |
| 55–77% (avg 1.7–2.3) | Structural hallucinations present — tool pseudo-calls, invented fields |
| < 55% (avg < 1.7) | Pervasive fabrication; unreliable for no-tool tasks |

Qwen 3.5 9B uncoached baseline: **66.7% hallucination_rate** (avg score 2.0) — structural fabrications on 4/9 prompts but final analyses mostly grounded.

Detection rules (p1-04 to p1-06) are the hardest category — Sigma syntax errors and validation fabrications are common.

## Comparing to baselines

| Model | Overall | Tech Acc | Op Util | Hall Rate |
|-------|---------|----------|---------|-----------|
| Gemma 3 4B coached (archive) | ~76% | ~72% | ~78% | ~72% |
| Gemma 3 12B coached (archive) | ~80% | ~78% | ~83% | ~78% |
| **Qwen 3.5 9B uncoached** | **77.8%** | **74.1%** | **81.5%** | **66.7%** |

Qwen 9B uncoached sits between the G3 4B and G3 12B coached baselines on overall, with stronger operational_utility but weaker hallucination control.
