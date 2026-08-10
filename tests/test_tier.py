"""Tier (complexity axis) — schema parsing, loader coverage, aggregate rollup.

Tier is orthogonal to `category` (RQ/topic axis): 1 = simple/single-pivot,
2 = middle/scoped-work-mode, 3 = complex/leading. Prompts that omit `tier`
default to 3 (the hardest tier).
"""
import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from blue_bench_eval.aggregate import aggregate, render_bluf
from blue_bench_eval.prompts._schema import PromptSpec, load_all

REPO = Path(__file__).parent.parent
RUBRIC = REPO / "blue_bench_eval" / "rubrics" / "phase2.yaml"
REAL_PROMPTS = REPO / "blue_bench_eval" / "prompts"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def _spec(**overrides) -> dict:
    base = {"id": "p3-99", "category": "apt_detection", "title": "t", "question": "q"}
    base.update(overrides)
    return base


def test_spec_parses_tier():
    s = PromptSpec.model_validate(_spec(tier=1))
    assert s.tier == 1


def test_spec_defaults_tier_to_3_when_absent():
    s = PromptSpec.model_validate(_spec())
    assert s.tier == 3


@pytest.mark.parametrize("bad", [0, 4, 5, -1])
def test_spec_rejects_out_of_range_tier(bad):
    with pytest.raises(ValidationError):
        PromptSpec.model_validate(_spec(tier=bad))


def test_real_p3_prompts_are_tier_3():
    # The original complex slate (p3-01..05) is the Tier-3 top tier; the later
    # p3-06+ prompts are the added Tier-1/Tier-2 slate, so assert per-id.
    specs = {s.id: s for s in load_all(REAL_PROMPTS, prefix="p3-")}
    assert specs
    for pid in ("p3-01", "p3-02", "p3-03", "p3-04", "p3-05"):
        assert specs[pid].tier == 3, f"{pid} should be Tier 3, got {specs[pid].tier}"
    # every prompt has a valid tier in {1,2,3}
    assert all(s.tier in (1, 2, 3) for s in specs.values())


# ---------------------------------------------------------------------------
# Loader auto-includes new tiers (glob by prefix, tier is orthogonal)
# ---------------------------------------------------------------------------

def _write_prompt(d: Path, pid: str, category: str, tier: int | None) -> None:
    body = {
        "id": pid,
        "category": category,
        "title": pid,
        "question": "q",
        "expected_tools": ["search_alerts"],
        "expected_findings": [{"synonyms": ["x"]}],
    }
    if tier is not None:
        body["tier"] = tier
    (d / f"{pid}.yaml").write_text(yaml.safe_dump(body))


def test_loader_includes_all_tiers_by_prefix(tmp_path: Path):
    _write_prompt(tmp_path, "p3-01", "apt_detection", 3)
    _write_prompt(tmp_path, "p3-06", "apt_detection", 1)  # new lower-tier prompt
    _write_prompt(tmp_path, "p3-07", "discrimination", 2)
    _write_prompt(tmp_path, "p3-08", "ot_segment", None)  # omitted -> defaults to 3
    specs = {s.id: s for s in load_all(tmp_path, prefix="p3-")}
    assert set(specs) == {"p3-01", "p3-06", "p3-07", "p3-08"}
    assert specs["p3-06"].tier == 1
    assert specs["p3-07"].tier == 2
    assert specs["p3-08"].tier == 3


# ---------------------------------------------------------------------------
# Aggregate per-tier breakdown
# ---------------------------------------------------------------------------

def _write_trace(run_dir: Path, pid: str) -> None:
    (run_dir / "prompts").mkdir(parents=True, exist_ok=True)
    trace = {
        "prompt_id": pid,
        "profile_name": "gemma4-e4b",
        "model_id": "gemma4:e4b",
        "turns": [],
        "final_answer": "a",
        "total_duration_ms": 1000,
        "error": None,
    }
    (run_dir / "prompts" / f"{pid}.json").write_text(json.dumps(trace))


def _write_scored(run_dir: Path, pid: str, tool, find, reas, resp) -> None:
    (run_dir / "scored").mkdir(parents=True, exist_ok=True)
    scores = {"tool_usage": tool, "findings": find, "reasoning": reas, "response_quality": resp}
    if any(s == 0 for s in scores.values()):
        verdict = "FAIL"
    elif all(s >= 2 for s in scores.values()):
        verdict = "PASS"
    else:
        verdict = "PARTIAL"
    scored = {
        "prompt_id": pid,
        "dimensions": {k: {"score": v, "justification": "j"} for k, v in scores.items()},
        "verdict": verdict,
        "hallucinations": [],
    }
    (run_dir / "scored" / f"{pid}.json").write_text(json.dumps(scored))


def _mixed_tier_prompts(prompts_dir: Path) -> None:
    # phase2 rubric globs by prefix p2-.
    _write_prompt(prompts_dir, "p2-01", "triage", 1)
    _write_prompt(prompts_dir, "p2-02", "triage", 2)
    _write_prompt(prompts_dir, "p2-03", "detection", 3)


def test_aggregate_produces_per_tier_breakdown(tmp_path: Path):
    prompts = tmp_path / "prompts_src"
    prompts.mkdir()
    _mixed_tier_prompts(prompts)

    run = tmp_path / "run"
    # tier1 perfect, tier2 mid, tier3 falls off.
    _write_trace(run, "p2-01"); _write_scored(run, "p2-01", 3, 3, 3, 3)
    _write_trace(run, "p2-02"); _write_scored(run, "p2-02", 2, 2, 2, 2)
    _write_trace(run, "p2-03"); _write_scored(run, "p2-03", 1, 1, 1, 1)

    result = aggregate(run, RUBRIC, prompts_dir=prompts)

    assert set(result.per_tier) == {1, 2, 3}
    assert result.per_tier[1]["count"] == 1.0
    assert result.per_tier[1]["overall"] == 100.0
    assert abs(result.per_tier[2]["overall"] - 66.666) < 0.1
    assert abs(result.per_tier[3]["overall"] - 33.333) < 0.1
    # Complexity curve: tier1 > tier2 > tier3.
    assert result.per_tier[1]["overall"] > result.per_tier[2]["overall"] > result.per_tier[3]["overall"]

    md = render_bluf(result)
    assert "## Per tier" in md
    assert "1 (simple)" in md and "3 (complex)" in md


def test_aggregate_per_tier_single_tier_renders(tmp_path: Path):
    # A run of only tier-3 prompts still renders a (one-row) per-tier table.
    prompts = tmp_path / "prompts_src"
    prompts.mkdir()
    _write_prompt(prompts, "p2-01", "triage", 3)
    _write_prompt(prompts, "p2-02", "detection", 3)

    run = tmp_path / "run"
    _write_trace(run, "p2-01"); _write_scored(run, "p2-01", 3, 3, 3, 3)
    _write_trace(run, "p2-02"); _write_scored(run, "p2-02", 2, 2, 2, 2)

    result = aggregate(run, RUBRIC, prompts_dir=prompts)
    assert set(result.per_tier) == {3}
    assert result.per_tier[3]["count"] == 2.0
    md = render_bluf(result)
    assert "## Per tier" in md
    assert "3 (complex)" in md


def test_aggregate_tier_defaults_to_3_when_prompt_omits_field(tmp_path: Path):
    prompts = tmp_path / "prompts_src"
    prompts.mkdir()
    _write_prompt(prompts, "p2-01", "triage", None)  # no tier field

    run = tmp_path / "run"
    _write_trace(run, "p2-01"); _write_scored(run, "p2-01", 3, 3, 3, 3)

    result = aggregate(run, RUBRIC, prompts_dir=prompts)
    assert set(result.per_tier) == {3}
