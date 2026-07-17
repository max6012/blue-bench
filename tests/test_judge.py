"""LLM-as-judge unit tests — mock the single Anthropic call, no network.

judge_run/score_trace accept a `call` hook so the grader response is injected;
this checks JSON parsing, dimension filtering, the mechanically-computed verdict,
scored/*.json output, and --overwrite semantics.
"""
import json

from pathlib import Path

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
