from pathlib import Path

import pytest

from blue_bench_mcp.guardrails import truncate_results, validate_path_under, TRUNC_MARKER


def test_truncate_below_cap():
    assert truncate_results("abc", 100) == "abc"


def test_truncate_above_cap():
    out = truncate_results("x" * 1000, 100)
    assert len(out) <= 100 + len(TRUNC_MARKER)
    assert TRUNC_MARKER in out
    assert out.startswith("x")
    assert out.endswith("x")


def test_validate_path_happy(tmp_path: Path):
    (tmp_path / "a.txt").write_text("hi")
    got = validate_path_under(tmp_path / "a.txt", tmp_path)
    assert got == (tmp_path / "a.txt").resolve()


def test_validate_path_traversal_rejected(tmp_path: Path):
    # Attempted traversal out of the root must raise.
    with pytest.raises(ValueError):
        validate_path_under(tmp_path / ".." / "evil", tmp_path)
