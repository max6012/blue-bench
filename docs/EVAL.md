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
