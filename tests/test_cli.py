"""CLI smoke tests via typer.testing.CliRunner — no subprocess."""
import json
from pathlib import Path

from typer.testing import CliRunner

from blue_bench_cli.main import app

runner = CliRunner()


def _write_run(
    run_dir: Path, prompt_id: str = "p2-01", *, scores=(3, 3, 3, 3)
) -> None:
    (run_dir / "prompts").mkdir(parents=True, exist_ok=True)
    (run_dir / "scored").mkdir(parents=True, exist_ok=True)
    trace = {
        "prompt_id": prompt_id,
        "profile_name": "gemma4-e4b",
        "model_id": "gemma4:e4b",
        "tool_protocol": "native",
        "question": "q",
        "composed_system_prompt": "sys",
        "tools_available": [],
        "turns": [],
        "final_answer": "a",
        "turns_used": 1,
        "max_turns": 10,
        "total_duration_ms": 1000,
        "error": None,
    }
    (run_dir / "prompts" / f"{prompt_id}.json").write_text(json.dumps(trace))
    tool, find, reas, resp = scores
    verdict = (
        "PASS"
        if all(s >= 2 for s in scores)
        else "FAIL"
        if any(s == 0 for s in scores)
        else "PARTIAL"
    )
    scored = {
        "prompt_id": prompt_id,
        "dimensions": {
            "tool_usage": {"score": tool, "justification": "j"},
            "findings": {"score": find, "justification": "j"},
            "reasoning": {"score": reas, "justification": "j"},
            "response_quality": {"score": resp, "justification": "j"},
        },
        "verdict": verdict,
        "hallucinations": [],
    }
    (run_dir / "scored" / f"{prompt_id}.json").write_text(json.dumps(scored))


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("qualify", "aggregate", "diff", "server"):
        assert cmd in result.stdout


def test_aggregate_writes_bluf(tmp_path: Path):
    _write_run(tmp_path)
    result = runner.invoke(app, ["aggregate", str(tmp_path)])
    assert result.exit_code == 0, result.stdout + result.stderr
    bluf = (tmp_path / "BLUF.md").read_text()
    assert "Phase 2 BLUF" in bluf
    assert "CLEARS THRESHOLD" in bluf
    assert "overall=100.0%" in result.stderr


def test_aggregate_no_write_mode(tmp_path: Path):
    _write_run(tmp_path)
    result = runner.invoke(app, ["aggregate", str(tmp_path), "--no-write"])
    assert result.exit_code == 0
    assert "Phase 2 BLUF" in result.stdout
    assert not (tmp_path / "BLUF.md").exists()


def test_aggregate_below_threshold(tmp_path: Path):
    _write_run(tmp_path, scores=(2, 2, 2, 2))
    result = runner.invoke(app, ["aggregate", str(tmp_path)])
    assert result.exit_code == 0
    assert "pass=False" in result.stderr


def test_diff_outputs_delta(tmp_path: Path):
    run_a = tmp_path / "run_a"
    run_b = tmp_path / "run_b"
    _write_run(run_a, scores=(2, 1, 2, 2))
    _write_run(run_b, scores=(3, 3, 3, 3))
    result = runner.invoke(app, ["diff", str(run_a), str(run_b)])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Dimension deltas" in result.stdout
    assert "↑" in result.stdout


def test_diff_write_to_file(tmp_path: Path):
    run_a = tmp_path / "run_a"
    run_b = tmp_path / "run_b"
    _write_run(run_a, scores=(2, 2, 2, 2))
    _write_run(run_b, scores=(3, 3, 3, 3))
    out = tmp_path / "delta.md"
    result = runner.invoke(app, ["diff", str(run_a), str(run_b), "--out", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "Dimension deltas" in out.read_text()


def test_server_rejects_unknown_transport():
    result = runner.invoke(app, ["server", "--transport", "websocket"])
    assert result.exit_code == 2
    assert "not yet implemented" in result.stderr or "not yet implemented" in result.stdout
