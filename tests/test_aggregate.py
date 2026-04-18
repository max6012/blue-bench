"""Unit tests for blue_bench_eval.aggregate — fake traces + fake scored JSON."""
import json
from pathlib import Path

import pytest

from blue_bench_eval.aggregate import aggregate, diff_runs, render_bluf

REPO = Path(__file__).parent.parent
RUBRIC = REPO / "blue_bench_eval" / "rubrics" / "phase2.yaml"
PROMPTS = REPO / "blue_bench_eval" / "prompts"


def _write_trace(run_dir: Path, pid: str, profile="gemma4-e4b", model="gemma4:e4b", duration_ms=5000) -> None:
    (run_dir / "prompts").mkdir(parents=True, exist_ok=True)
    trace = {
        "prompt_id": pid,
        "profile_name": profile,
        "model_id": model,
        "tool_protocol": "native",
        "question": "q",
        "composed_system_prompt": "sys",
        "tools_available": ["search_alerts"],
        "turns": [],
        "final_answer": "answer",
        "turns_used": 3,
        "max_turns": 10,
        "total_duration_ms": duration_ms,
        "error": None,
    }
    (run_dir / "prompts" / f"{pid}.json").write_text(json.dumps(trace))


def _write_scored(run_dir: Path, pid: str, tool=3, find=3, reas=3, resp=3) -> None:
    (run_dir / "scored").mkdir(parents=True, exist_ok=True)
    # Derive verdict from the rubric rules.
    scores = {"tool_usage": tool, "findings": find, "reasoning": reas, "response_quality": resp}
    if any(s == 0 for s in scores.values()):
        verdict = "FAIL"
    elif all(s >= 2 for s in scores.values()):
        verdict = "PASS"
    else:
        verdict = "PARTIAL"
    scored = {
        "prompt_id": pid,
        "dimensions": {
            "tool_usage":       {"score": tool, "justification": "j"},
            "findings":         {"score": find, "justification": "j"},
            "reasoning":        {"score": reas, "justification": "j"},
            "response_quality": {"score": resp, "justification": "j"},
        },
        "verdict": verdict,
        "hallucinations": [],
    }
    (run_dir / "scored" / f"{pid}.json").write_text(json.dumps(scored))


def test_aggregate_all_perfect(tmp_path: Path):
    run = tmp_path / "run"
    for pid in ("p2-01", "p2-02", "p2-03"):
        _write_trace(run, pid)
        _write_scored(run, pid, 3, 3, 3, 3)

    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    assert result.prompt_count == 3
    assert result.overall_pct == 100.0
    assert result.dim_pct["findings"] == 100.0
    assert result.passes_overall and result.passes_tool_usage and result.passes_findings
    assert all(v["verdict"] == "PASS" for v in result.verdicts)


def test_aggregate_below_threshold(tmp_path: Path):
    run = tmp_path / "run"
    # Scores that average to 2/3 = 66.7% — below 80% overall threshold.
    for pid in ("p2-01", "p2-02", "p2-03"):
        _write_trace(run, pid)
        _write_scored(run, pid, 2, 2, 2, 2)

    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    assert abs(result.overall_pct - 66.666) < 0.1
    assert not result.passes_overall
    assert not result.passes_tool_usage
    assert not result.passes_findings
    assert all(v["verdict"] == "PASS" for v in result.verdicts)  # all dims >= 2


def test_aggregate_partial_verdict(tmp_path: Path):
    run = tmp_path / "run"
    _write_trace(run, "p2-01")
    _write_scored(run, "p2-01", 2, 3, 1, 2)  # reasoning=1 → PARTIAL
    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    assert result.verdicts[0]["verdict"] == "PARTIAL"


def test_aggregate_fail_on_zero(tmp_path: Path):
    run = tmp_path / "run"
    _write_trace(run, "p2-01")
    _write_scored(run, "p2-01", 0, 3, 3, 3)  # tool_usage=0 → FAIL
    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    assert result.verdicts[0]["verdict"] == "FAIL"


def test_aggregate_missing_scored_dir(tmp_path: Path):
    run = tmp_path / "run"
    (run / "prompts").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        aggregate(run, RUBRIC)


def test_aggregate_empty_scored_dir(tmp_path: Path):
    run = tmp_path / "run"
    (run / "scored").mkdir(parents=True)
    with pytest.raises(ValueError):
        aggregate(run, RUBRIC)


def test_aggregate_category_rollup(tmp_path: Path):
    run = tmp_path / "run"
    # p2-01 is triage (archive id 1), p2-06 is detection.
    _write_trace(run, "p2-01")
    _write_trace(run, "p2-06")
    _write_scored(run, "p2-01", 3, 3, 3, 3)
    _write_scored(run, "p2-06", 1, 1, 1, 1)

    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    assert "triage" in result.per_category
    assert "detection" in result.per_category
    assert result.per_category["triage"]["overall"] == 100.0
    assert abs(result.per_category["detection"]["overall"] - 33.333) < 0.1


def test_render_bluf_smoke(tmp_path: Path):
    run = tmp_path / "run"
    _write_trace(run, "p2-01")
    _write_scored(run, "p2-01", 3, 3, 3, 3)
    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    md = render_bluf(result)
    assert "# Phase 2 BLUF" in md
    assert "gemma4-e4b" in md
    assert "CLEARS THRESHOLD" in md
    assert "| p2-01 |" in md


def test_render_bluf_below_threshold_flagged(tmp_path: Path):
    run = tmp_path / "run"
    _write_trace(run, "p2-01")
    _write_scored(run, "p2-01", 2, 2, 2, 2)
    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    md = render_bluf(result)
    assert "BELOW THRESHOLD" in md
    assert "✗" in md


def test_diff_runs_shows_delta(tmp_path: Path):
    run_a = tmp_path / "runA"
    run_b = tmp_path / "runB"
    for pid in ("p2-01", "p2-02"):
        _write_trace(run_a, pid)
        _write_trace(run_b, pid)
    # A: borderline. B: improved findings.
    _write_scored(run_a, "p2-01", 2, 1, 2, 2)
    _write_scored(run_a, "p2-02", 2, 2, 2, 2)
    _write_scored(run_b, "p2-01", 2, 3, 2, 2)
    _write_scored(run_b, "p2-02", 3, 3, 2, 2)

    a = aggregate(run_a, RUBRIC, prompts_dir=PROMPTS)
    b = aggregate(run_b, RUBRIC, prompts_dir=PROMPTS)
    md = diff_runs(a, b)
    assert "Dimension deltas" in md
    assert "↑" in md  # findings went up
    assert "p2-01" in md
    assert "PARTIAL → PASS" in md or "PASS → PASS" in md


def test_verdict_reports_hallucination_count(tmp_path: Path):
    run = tmp_path / "run"
    _write_trace(run, "p2-01")
    scored = {
        "prompt_id": "p2-01",
        "dimensions": {
            "tool_usage":       {"score": 2, "justification": "j"},
            "findings":         {"score": 0, "justification": "hallucinated IP"},
            "reasoning":        {"score": 2, "justification": "j"},
            "response_quality": {"score": 2, "justification": "j"},
        },
        "verdict": "FAIL",
        "hallucinations": ["203.0.114.200 (not in any trace output)"],
    }
    (run / "scored").mkdir(parents=True)
    (run / "scored" / "p2-01.json").write_text(json.dumps(scored))
    result = aggregate(run, RUBRIC, prompts_dir=PROMPTS)
    md = render_bluf(result)
    assert result.verdicts[0]["hallucinations"] == ["203.0.114.200 (not in any trace output)"]
    assert "| p2-01 | triage | FAIL |" in md
    # Hallucination count column shows 1.
    assert " 1 |" in md
