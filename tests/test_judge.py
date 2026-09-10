"""LLM-as-judge unit tests — mock the single Anthropic call, no network.

judge_run/score_trace accept a `call` hook so the grader response is injected;
this checks JSON parsing, dimension filtering, the mechanically-computed verdict,
scored/*.json output, and --overwrite semantics.
"""
import json

from pathlib import Path

import pytest

from blue_bench_eval.judge import judge_run, score_trace, load_rubric

RUBRIC = Path("blue_bench_eval/rubrics/phase3.yaml")


def _trace(pid="p3-01"):
    return {
        "prompt_id": pid, "profile_name": "t", "model_id": "m", "tool_protocol": "native",
        "question": "hunt the enterprise", "composed_system_prompt": "", "tools_available": ["get_process_events"],
        "turns": [{"role": "assistant", "content": "looking", "tool_calls": [
            {"name": "get_process_events", "args": {"host": "wkst-03"}}]},
                  {"role": "tool", "tool_name": "get_process_events", "content": "[{...}]"}],
        "final_answer": "wkst-03 is compromised: comsvcs LSASS dump.", "turns_used": 2, "max_turns": 30,
    }


def _mock_call(scores):
    def _c(cfg, system, user):
        return json.dumps({"dimensions": {k: {"score": v, "justification": "x"} for k, v in scores.items()},
                           "hallucinations": [], "tuning_recommendations": ["widen the window"]})
    return _c


def test_score_trace_computes_verdict_mechanically():
    rub = load_rubric(RUBRIC)
    # findings=3, tool_usage=2, attribution=2 -> all >=2, key dims ok -> PASS
    s = score_trace(_trace(), None, rub, call=_mock_call({"tool_usage": 2, "findings": 3, "attribution": 2}))
    assert s.verdict == "PASS"
    assert s.dimensions["findings"].score == 3
    assert s.tuning_recommendations == ["widen the window"]


def test_findings_zero_forces_fail():
    rub = load_rubric(RUBRIC)
    s = score_trace(_trace(), None, rub, call=_mock_call({"tool_usage": 3, "findings": 0, "attribution": 2}))
    assert s.verdict == "FAIL"   # findings is a key dim; 0 -> FAIL


def test_judge_run_writes_scored_and_overwrite(tmp_path):
    run = tmp_path / "run"
    (run / "prompts").mkdir(parents=True)
    (run / "prompts" / "p3-01.json").write_text(json.dumps(_trace()))
    calls = {"n": 0}
    def counting(scores):
        base = _mock_call(scores)
        def _c(cfg, s, u):
            calls["n"] += 1
            return base(cfg, s, u)
        return _c

    out = judge_run(run, RUBRIC, prompts_dir=None, call=counting({"tool_usage": 2, "findings": 2, "attribution": 2}))
    assert len(out) == 1
    scored = json.loads((run / "scored" / "p3-01.json").read_text())
    assert scored["verdict"] == "PASS"
    assert calls["n"] == 1
    # re-run without overwrite -> reads cached, no new judge call
    judge_run(run, RUBRIC, prompts_dir=None, call=counting({"tool_usage": 2, "findings": 2, "attribution": 2}))
    assert calls["n"] == 1
    # with overwrite -> re-judges
    judge_run(run, RUBRIC, prompts_dir=None, overwrite=True,
              call=counting({"tool_usage": 2, "findings": 2, "attribution": 2}))
    assert calls["n"] == 2


# ── B5: the void-run guard must refuse a run with NO tool results at all ──────

def test_guard_not_void_refuses_no_tool_results(tmp_path):
    from blue_bench_eval.judge import VoidRunError, _guard_not_void

    # A transport that crashed before its first dispatch yields traces with no
    # tool-result turns at all — the guard must refuse to grade them.
    traces = [
        {
            "prompt_id": "p3-01",
            "turns": [{"role": "assistant", "content": "", "tool_calls": []}],
            "final_answer": "",
            "error": "ValueError: dictionary update sequence element #0 has length 1",
        }
    ]
    with pytest.raises(VoidRunError):
        _guard_not_void(traces, tmp_path)


def test_guard_not_void_allows_real_tool_results(tmp_path):
    from blue_bench_eval.judge import _guard_not_void

    traces = [
        {
            "prompt_id": "p3-01",
            "turns": [
                {"role": "assistant", "content": "", "tool_calls": []},
                {"role": "tool", "content": "[{...}]"},
            ],
            "final_answer": "found it",
        }
    ]
    # A run with a non-empty tool result must pass the guard.
    _guard_not_void(traces, tmp_path)


def test_guard_not_void_refuses_partial_transport_death(tmp_path):
    from blue_bench_eval.judge import VoidRunError, _guard_not_void

    # A transport that died partway: most traces carry an error and no
    # final_answer, but a few have real tool results (so total > 0 and the
    # empty-ratio check misses it). The guard must still refuse.
    traces = [
        {
            "prompt_id": "p3-01",
            "turns": [{"role": "tool", "content": "[{...}]"}],
            "final_answer": "found it",
        },
        {"prompt_id": "p3-02", "turns": [], "final_answer": "", "error": "boom"},
        {"prompt_id": "p3-03", "turns": [], "final_answer": "", "error": "boom"},
    ]
    with pytest.raises(VoidRunError):
        _guard_not_void(traces, tmp_path)


# ── D3: a partial judge run must not silently grade the survivors ────────────

def test_judge_run_refuses_partial_without_allow_partial(tmp_path, monkeypatch):
    from blue_bench_eval.judge import PartialRunError

    monkeypatch.setenv("JUDGE_PACE_SECONDS", "0")
    run = tmp_path / "run"
    (run / "prompts").mkdir(parents=True)
    (run / "prompts" / "p3-01.json").write_text(json.dumps(_trace("p3-01")))
    (run / "prompts" / "p3-02.json").write_text(json.dumps(_trace("p3-02")))

    def _flaky(cfg, system, user):
        # First prompt scores fine; second raises (malformed judge reply).
        if "p3-02" in user:
            raise RuntimeError("malformed judge reply")
        return json.dumps({"dimensions": {"tool_usage": {"score": 2, "justification": "x"},
                                          "findings": {"score": 2, "justification": "x"},
                                          "attribution": {"score": 2, "justification": "x"}},
                           "hallucinations": [], "tuning_recommendations": []})

    with pytest.raises(PartialRunError):
        judge_run(run, RUBRIC, prompts_dir=None, call=_flaky)


def test_judge_run_allow_partial_grades_survivors(tmp_path, monkeypatch):
    monkeypatch.setenv("JUDGE_PACE_SECONDS", "0")
    run = tmp_path / "run"
    (run / "prompts").mkdir(parents=True)
    (run / "prompts" / "p3-01.json").write_text(json.dumps(_trace("p3-01")))
    (run / "prompts" / "p3-02.json").write_text(json.dumps(_trace("p3-02")))

    def _flaky(cfg, system, user):
        if "p3-02" in user:
            raise RuntimeError("malformed judge reply")
        return json.dumps({"dimensions": {"tool_usage": {"score": 2, "justification": "x"},
                                          "findings": {"score": 2, "justification": "x"},
                                          "attribution": {"score": 2, "justification": "x"}},
                           "hallucinations": [], "tuning_recommendations": []})

    out = judge_run(run, RUBRIC, prompts_dir=None, call=_flaky, allow_partial=True)
    assert len(out) == 1


# ── D-D: the judge must never be the model under test ────────────────────────

def test_judge_run_refuses_self_scoring(tmp_path):
    from blue_bench_eval.judge import SelfScoringError

    run = tmp_path / "run"
    (run / "prompts").mkdir(parents=True)
    # The trace's model_id matches the rubric's judge model (claude-opus-4-8).
    t = _trace("p3-01")
    t["model_id"] = "claude-opus-4-8"
    (run / "prompts" / "p3-01.json").write_text(json.dumps(t))

    with pytest.raises(SelfScoringError):
        judge_run(run, RUBRIC, prompts_dir=None, call=_mock_call({"tool_usage": 2, "findings": 2, "attribution": 2}))
