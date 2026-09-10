"""t-pfwire — the preflight guard is wired into the run + judge paths.

Two layers, both fully offline (no live ES, no live model):

  1. Primary gate: ``run_corpus`` calls ``run_preflight`` once at the start and
     ABORTS (``PreflightError``) before any model calls when it is not ok;
     ``--skip-preflight`` / ``skip_preflight=True`` bypasses it entirely.
  2. Defensive layer: ``judge_run`` refuses (``VoidRunError``) to score a run
     whose tool results are ~100% empty (the empty-SIEM signature), and scores a
     normal run unchanged.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

# Imported as a module (not `from ... import`) because the tests monkeypatch
# attributes ON it -- `monkeypatch.setattr(qualify, "run_preflight", ...)` only
# affects callers that resolve through the module, which is how run_corpus does
# it. Importing the same module both ways is also a CodeQL code-quality finding.
import blue_bench_eval.qualify as qualify
from blue_bench_eval.judge import VoidRunError, judge_run

RUBRIC = Path("blue_bench_eval/rubrics/phase3.yaml")


# --- fixtures / fakes --------------------------------------------------------


class _Report:
    """Stand-in for PreflightReport with just the surface run_corpus uses."""

    def __init__(self, ok: bool) -> None:
        self._ok = ok

    @property
    def ok(self) -> bool:
        return self._ok

    def summary(self) -> str:
        return f"[fake preflight summary ok={self._ok}]"


def _fake_profile() -> SimpleNamespace:
    return SimpleNamespace(name="fake", model_id="fake:1b", tool_protocol="native")


def _fake_trace_obj() -> SimpleNamespace:
    # Only the attrs run_corpus touches after _run_one returns.
    return SimpleNamespace(turns=[], turns_used=1, final_answer="", error=None)


@pytest.fixture
def prompts_dir(tmp_path: Path) -> Path:
    d = tmp_path / "prompts"
    d.mkdir()
    (d / "p2-01.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "p2-01",
                "category": "triage",
                "title": "t",
                "question": "q",
                "expected_tools": ["search_alerts"],
                "expected_findings": [{"synonyms": ["x"]}],
                "pass_criteria": "c",
            }
        )
    )
    (d / "p3-01.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "p3-01",
                "category": "triage",
                "title": "t",
                "question": "q",
                "expected_tools": ["search_alerts"],
                "expected_findings": [{"synonyms": ["x"]}],
                "pass_criteria": "c",
            }
        )
    )
    return d


def _wire_run_corpus(monkeypatch, tmp_path: Path, run_called: dict) -> None:
    """Stub the model-spending parts so a proceed path never touches a model."""
    monkeypatch.setattr(qualify, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(qualify, "load_profile", lambda *_a, **_k: _fake_profile())

    async def _fake_run_one(profile, spec, config_path, out_dir):
        run_called["n"] += 1
        return _fake_trace_obj()

    monkeypatch.setattr(qualify, "_run_one", _fake_run_one)


# --- 1. primary gate ---------------------------------------------------------


def test_qualify_aborts_when_preflight_not_ok(monkeypatch, tmp_path, prompts_dir):
    run_called = {"n": 0}
    _wire_run_corpus(monkeypatch, tmp_path, run_called)
    monkeypatch.setattr(qualify, "run_preflight", lambda *a, **k: _Report(ok=False))

    with pytest.raises(qualify.PreflightError):
        asyncio.run(
            qualify.run_corpus(
                "fake",
                config_path=tmp_path / "config.yaml",
                prompts_dir=prompts_dir,
                phase="2",
            )
        )
    assert run_called["n"] == 0  # no model calls spent


def test_qualify_proceeds_when_preflight_ok(monkeypatch, tmp_path, prompts_dir):
    run_called = {"n": 0}
    _wire_run_corpus(monkeypatch, tmp_path, run_called)
    seen = {"called": False}

    def _pf(*a, **k):
        seen["called"] = True
        return _Report(ok=True)

    monkeypatch.setattr(qualify, "run_preflight", _pf)

    out_dir = asyncio.run(
        qualify.run_corpus(
            "fake",
            config_path=tmp_path / "config.yaml",
            prompts_dir=prompts_dir,
            phase="2",
        )
    )
    assert seen["called"] is True
    assert run_called["n"] == 1              # the one prompt ran
    assert (out_dir / "run_meta.json").exists()


def test_skip_preflight_bypasses_gate(monkeypatch, tmp_path, prompts_dir):
    run_called = {"n": 0}
    _wire_run_corpus(monkeypatch, tmp_path, run_called)

    def _boom(*a, **k):  # must never be reached when skipping
        raise AssertionError("run_preflight called despite skip_preflight=True")

    monkeypatch.setattr(qualify, "run_preflight", _boom)

    out_dir = asyncio.run(
        qualify.run_corpus(
            "fake",
            config_path=tmp_path / "config.yaml",
            prompts_dir=prompts_dir,
            phase="2",
            skip_preflight=True,
        )
    )
    assert run_called["n"] == 1
    assert (out_dir / "run_meta.json").exists()


def test_gate_scopes_probe_prefix_to_phase(monkeypatch, tmp_path, prompts_dir):
    """The gate passes prompts_prefix=f'p{phase}-' so a phase run only demands
    that tier's indices."""
    captured = {}
    _wire_run_corpus(monkeypatch, tmp_path, {"n": 0})

    def _pf(config_path, *, prompts_dir=None, prompts_prefix="p", **k):
        captured["prefix"] = prompts_prefix
        return _Report(ok=True)

    monkeypatch.setattr(qualify, "run_preflight", _pf)
    asyncio.run(
        qualify.run_corpus("fake", config_path=tmp_path / "c.yaml", prompts_dir=prompts_dir, phase="3")
    )
    assert captured["prefix"] == "p3-"


# --- 2. defensive judge layer ------------------------------------------------


def _trace(pid: str, tool_contents: list[str]) -> dict:
    turns = [{"role": "assistant", "content": "look", "tool_calls": [{"name": "search_alerts", "args": {}}]}]
    for c in tool_contents:
        turns.append({"role": "tool", "tool_name": "search_alerts", "content": c})
    return {
        "prompt_id": pid,
        "question": "hunt",
        "turns": turns,
        "final_answer": "nothing found" if not any(tool_contents) else "wkst-03 compromised",
        "turns_used": len(turns),
        "max_turns": 30,
    }


def _mock_call(scores):
    def _c(cfg, system, user):
        return json.dumps(
            {
                "dimensions": {k: {"score": v, "justification": "x"} for k, v in scores.items()},
                "hallucinations": [],
                "tuning_recommendations": [],
            }
        )
    return _c


def _write_traces(run: Path, traces: list[dict]) -> None:
    (run / "prompts").mkdir(parents=True)
    for t in traces:
        (run / "prompts" / f"{t['prompt_id']}.json").write_text(json.dumps(t))


def test_judge_refuses_void_run(tmp_path):
    run = tmp_path / "run"
    # Every tool result empty across the run — the void-SIEM signature.
    _write_traces(
        run,
        [_trace("p3-01", ["[]"]), _trace("p3-02", ["[]", "  [ ]  "]), _trace("p3-03", ['""'])],
    )
    graded = {"n": 0}

    def _c(cfg, s, u):
        graded["n"] += 1
        return _mock_call({"tool_usage": 2, "findings": 2, "attribution": 2})(cfg, s, u)

    with pytest.raises(VoidRunError):
        judge_run(run, RUBRIC, prompts_dir=None, call=_c)
    assert graded["n"] == 0                       # aborted before any judge call
    assert list((run / "scored").glob("*.json")) == []  # nothing scored


def test_judge_scores_normal_run(tmp_path):
    run = tmp_path / "run"
    # A real hit somewhere -> not void -> scored normally.
    _write_traces(
        run,
        [_trace("p3-01", ['[{"host": "wkst-03"}]']), _trace("p3-02", ["[]"])],
    )
    out = judge_run(
        run,
        RUBRIC,
        prompts_dir=None,
        call=_mock_call({"tool_usage": 2, "findings": 2, "attribution": 2}),
    )
    assert len(out) == 2
    assert all((run / "scored" / f"{s.prompt_id}.json").exists() for s in out)
