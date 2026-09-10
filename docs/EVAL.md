# Blue-Bench Evaluation Methodology

This document describes the evaluation harness — what it measures, how it measures it, and what the results mean. The harness is one consumer of the scaffold, not its purpose.

## What this is and isn't

The Phase 2 corpus is a **smoke harness with a rubric**, not a benchmark in the SWE-bench sense. Ten prompts × four dimensions is a coarse surface: it tells you whether the wiring is sound and whether the model can complete representative investigation tasks. It does not produce statistically robust capability rankings across models, and it is not designed to.

If you want rigorous model comparison, expand the corpus. If you want to know whether a new profile is wired correctly and the coaching is effective, ten prompts is enough signal.

## Frontier-as-oracle methodology

Runs fall into two classes:

- **Frontier reference runs** (Claude Sonnet / Opus via the Anthropic API) establish the configuration ceiling. If a frontier model does not score near the top of the rubric on a well-formed prompt, the problem is in the wiring — tool schemas, data fixtures, coaching, system prompt — not in the model. This catches infrastructure bugs before they get attributed to local-model capability.
- **Local runs** (Ollama-hosted open-weight models) are measured against the same corpus and rubric. When you change the tool surface, site overlay, or coaching, a frontier run is the fastest way to confirm the wiring is still sound before scoring any local model.

The ceiling is a moving target as frontier models improve. Fix the corpus and rubric version before comparing runs.

**Budget asymmetry (read before quoting "% of frontier"):** the frontier ceiling
is measured with an *unbounded* tool-call budget — the `anthropic-cli` transport
drives `claude -p`, which runs its own loop and exposes no `--max-turns` flag —
while local open-weight models are capped at `max_turns: 30`. A "% of frontier"
number therefore compares a capped local run against an uncapped ceiling; the
gap is partly budget, not purely capability. State this caveat wherever the
percentage is quoted.

**Guidelines asymmetry (read before quoting "% of frontier"):** the two coaching
guidelines files ship with *opposite* stopping rules —
`investigation_protocol.md` ("stop after 4-6 calls") vs
`threat_hunting_protocol.md` ("corroborate across two layers and rule out
competing explanations"). The frontier ceiling profiles (`claude-opus-5`,
`claude-opus-4-8`) use the hunting protocol; the committed local profiles use
the investigation protocol. A "% of frontier" number is only a capability
measurement when both arms run the same guidance. Each run's `run_meta.json`
stamps its `guidelines` file so the arm is observable; do not compare across
arms without accounting for it.

## Rubric design

Four dimensions, each scored 0–3 by a Claude judge (not self-scoring). The judge writes per-dimension justifications in the scored JSON — every number has a cited reason, which prevents score inflation and makes regressions diagnosable.

### tool_usage

Were the expected tool categories invoked, in a reasonable order, with reasonable arguments?

| Score | Meaning |
| --- | --- |
| 0 | No expected tool called, every call failed, or the model hallucinated a tool that doesn't exist |
| 1 | At least one expected tool called but most were skipped, OR excessive redundant calls (same tool >3× with no new information) |
| 2 | Most expected tools called; arguments mostly correct; no catastrophic misuse. Minor order issues OK |
| 3 | All expected tools called in a sensible order with well-formed arguments. No redundant looping. Tool chaining where the question called for it |

Notes:
- Calling *extra* tools beyond expected is not penalized — only missing expected tools and redundant looping.
- Hallucinated tools (names not in the registered set) score 0 automatically.

### findings

Did the final answer identify the correct security findings? Scored against the prompt's `expected_findings` synonym sets.

| Score | Meaning |
| --- | --- |
| 0 | Core finding missed entirely, OR a material hallucination (fabricated IP/hostname/CVE presented as real) |
| 1 | Some findings identified but primary conclusion wrong or critically incomplete |
| 2 | Primary finding correct; one or more secondary findings missed or unclear |
| 3 | All expected finding synonym sets matched in the answer (fuzzy match against the synonym list). No hallucinations |

Findings synonyms are fuzzy-matched (substring, case-insensitive). A match anywhere in `final_answer` counts.

### reasoning

Is the analysis coherent, well-structured, and appropriately cautious where data is thin?

| Score | Meaning |
| --- | --- |
| 0 | Incoherent, contradictory, or wild speculation with no grounding in tool output |
| 1 | Reasoning present but jumps conclusions or ignores tool output that contradicts it |
| 2 | Sound reasoning; minor gaps or over-reach; mostly grounded in tool output |
| 3 | Tight, well-sourced reasoning. Tool outputs cited inline. Uncertainty surfaced where appropriate |

### response_quality

Does the response follow the `prompt_style` from the profile (terse vs verbose) and actually deliver what the analyst asked for?

| Score | Meaning |
| --- | --- |
| 0 | Didn't answer the question, OR massively over/under-length for the profile style |
| 1 | Answered tangentially OR style-mismatched |
| 2 | Answered the question; style roughly matches profile |
| 3 | Directly answers the question; style matches profile exactly; actionable and appropriately complete |

## Aggregation

- Per-prompt per-dimension: `dimension_pct = (score / 3) * 100`
- Per-prompt overall: simple average of the four dimension percentages
- Corpus percentages: arithmetic mean across prompts per dimension
- Categorical verdict per prompt:
  - `PASS`: all dimensions ≥ 2 AND tool_usage ≥ 2 AND findings ≥ 2
  - `PARTIAL`: no dimension is 0 AND at least one dimension is 1
  - `FAIL`: any dimension is 0 OR tool_usage == 0 OR findings == 0

## Thresholds (Phase 2)

| Dimension | Threshold |
| --- | --- |
| overall_pct | ≥ 80% |
| tool_usage_pct | ≥ 85% |
| findings_pct | ≥ 95% |

The findings threshold is high (95%) because hallucinated or missed findings are the failure mode that matters most operationally — a model that calls the right tools but reports the wrong conclusion is worse than useless.

## Running an evaluation

```bash
# Run corpus against a profile
blue-bench qualify --profile gemma4-e4b

# Results land in results/<timestamp>-<profile>/
# Aggregate and judge:
blue-bench aggregate results/<run-dir>/
```

The BLUF (`results/<run-dir>/BLUF.md`) summarizes overall%, per-dimension%, pass/fail verdict, and per-prompt breakdown. The `scored/` directory holds the full judge output with per-dimension justifications.

## Interpreting results

A low `tool_usage` score usually means a coaching or schema problem — the model either doesn't know the tools exist or misforms arguments. Fix in `prompts/coaching/<model>.md` or check the tool schema.

A low `findings` score with adequate `tool_usage` means the model is calling the right tools but not synthesizing the output correctly. Check the system prompt guidelines and the coaching.

A low `reasoning` score alongside adequate `findings` means the model is reaching the right answer through a suspicious path — worth investigating even if the verdict passes.

`response_quality` mismatches (terse prompt, verbose answer or vice versa) are fixed by adjusting `prompt_style` in the profile YAML and tuning the coaching file accordingly.

## Known limitations — read before citing any number

Recorded 2026-09-10, from a corpus-integrity audit of the re-measurement
harness. The harness code is exercised by the offline suite; **the corpus and
answer keys it grades against are not yet valid.** Every item below is a reason
a produced number does not mean what its label says.

### Phase-3 grades are not currently gradeable

- **A prompt's `tier` does not bind it to a corpus containing its evidence.**
  24 of 28 phase-3 prompts are unanswerable or mis-keyed on any tier but L.
  Running the phase-3 slate against an S or M corpus produces numbers, and
  they are meaningless. (Audit D10.)
- **The tier→adversary map makes `wkst-03` a different attacker per tier.** S
  and M carry only the cybercrime foil; L carries the APT on `wkst-03` and the
  foil on `wkst-07`. S/M contain no APT and no credential bundles, so every
  RQ2/RQ3 prompt is unanswerable there and any tier-agnostic answer key is
  wrong. (Audit D8.)
- **The credential bundles reference identities and hosts that exist nowhere in
  the corpus.** A model cannot corroborate them, and is scored down for the
  data's absence rather than its own performance. (Audit D7.)
- **The RQ2 beacon is disabled.** `merge/__main__.py` sets
  `_BEACON_SPECS = {}`, so `detect_beaconing` — shipped as a headline analytic
  — has nothing to find in any built corpus. (Audit D5.)

An earlier phase-3 run is separately void: the SIEM was 100% empty at run time.

### The published coaching A/B number is mislabeled

`blue_bench_client/cloud_models.py:99,134` selects the guidelines file from the
same `coached` flag that selects the hints:

```python
g = guidelines or ("threat_hunting_protocol.md" if coached else "investigation_protocol.md")
```

**Historically the hints were never applied.** `compose()` builds the prompt from
`prompt_parts` in `SECTION_ORDER = (role, site, guidelines, coaching)`, and
`profile.coaching_hints` is not a `prompt_parts` file, so before `847bd4c` it
never reached the composed system prompt. The coached arm therefore differed
from the baseline *only* in its guidelines file.

So the published **"overall 21.7% coached vs 13.3% uncoached"** (measured at
`e4cb6ca`, which predates `847bd4c`) is a **hunting-protocol vs
investigation-protocol delta, not a coaching delta.** The measurement is real;
the label is wrong. Cite it as a protocol comparison.

**As of `847bd4c` the mechanism is fixed** — `prompts_compose.py:56-62` appends
a `## Coaching hints` block, run through the same HTML-comment strip and
placeholder substitution as every other part. Future coached runs do apply the
five hints.

That leaves a narrower but still real confound: `coached` now flips **two**
things at once — the hints *and* the guidelines file. To attribute an effect to
the hints, pass `guidelines=` explicitly so it is held constant across arms.

The same confound exists across the committed profiles. The two protocols have
opposite stopping rules:

```
blue_bench_mcp/prompts/guidelines/investigation_protocol.md:13
    "Stop when you have enough to answer. After 4-6 tool calls, or sooner
     when the picture is clear..."
blue_bench_mcp/prompts/guidelines/threat_hunting_protocol.md:50
    "Let the data, not your narrative, decide when you're done. Stop when
     your leading hypothesis is corroborated across at least two layers..."
```

and exactly 2 of the 10 profiles in `blue_bench_mcp/profiles/` use the hunting
one — `claude-opus-5.yaml` and `claude-opus-4-8.yaml`, the two frontier oracles.
The other 8 use investigation. **Any comparison across those profiles varies
turn-budget discipline as well as model capability.** Hold the guidelines file
constant across arms you intend to compare, or vary it deliberately as the
treatment.

`qualify.py` stamps the composed guidelines file into `run_meta.json`, written
before the prompt loop, so runs from here on are self-documenting. Runs before
that have unrecoverable invocation provenance.

### No CI runs the test suite

`.github/workflows/` contains CodeQL and a sandbox-atomic job only. **No
workflow runs `pytest`.** Every "N tests pass" claim in a PR or commit message
on this repo is self-reported and was not independently verified by CI. Treat
it accordingly, and run the suite locally before relying on it.

### Corpus builds require a UTC clock

`build_corpus()` aborts on a non-UTC clock. The OT generators emit tz-aware UTC
epochs while `it_baseline/` and `c2/` still interpret naive datetimes as local
time, so a non-UTC build desyncs IT from OT by the local offset — invisibly, as
every file parses and every gate passes. Build with `TZ=UTC` until that is
resolved.

### Two tool surfaces, two different defaults

`blue_bench_mcp/tools/` (the registered MCP surface) and
`blue_bench_mcp/tool_classes/` (the direct/CLI path) declare **different**
default lookbacks for the same logical tool — 240 vs 60 minutes. The documented
default depends on which surface a caller uses, and the 60-minute path cannot
reach a multi-day corpus.
