"""Unit tests for qualify helpers — selection, run_dir, git head."""
import asyncio
from pathlib import Path

import pytest

from blue_bench_eval.prompts._schema import PromptSpec, FindingSynonymSet
from blue_bench_eval.qualify import _select, _run_dir, _git_head


def _mk(pid, category, tags):
    return PromptSpec(
        id=pid,
        category=category,
        title=pid,
        question="q",
        expected_tools=["t"],
        expected_findings=[FindingSynonymSet(synonyms=["x"])],
        pass_criteria="crit",
        tags=tags,
    )


def test_select_no_filter():
    specs = [_mk("p2-01", "triage", ["TH"]), _mk("p2-02", "malware", ["TH"])]
    assert _select(specs, tag="", limit=None) == specs


def test_select_by_tag():
    specs = [_mk("p2-01", "triage", ["TH"]), _mk("p2-02", "detection", ["DR"])]
    out = _select(specs, tag="DR", limit=None)
    assert len(out) == 1
    assert out[0].id == "p2-02"


def test_select_by_category():
    specs = [_mk("p2-01", "triage", ["TH"]), _mk("p2-02", "detection", ["DR"])]
    out = _select(specs, tag="triage", limit=None)
    assert len(out) == 1
    assert out[0].id == "p2-01"


def test_select_limit_applied_after_filter():
    specs = [_mk(f"p2-{i:02d}", "triage", ["TH"]) for i in range(1, 6)]
    out = _select(specs, tag="", limit=2)
    assert len(out) == 2
    assert [s.id for s in out] == ["p2-01", "p2-02"]


def test_run_dir_format():
    d = _run_dir("20260419-080000", "gemma4-e4b", "")
    assert d.name == "20260419-080000-gemma4-e4b"


def test_run_dir_with_tag():
    d = _run_dir("20260419-080000", "gemma4-e4b", "DR")
    assert d.name == "20260419-080000-gemma4-e4b-DR"


def test_git_head_format():
    head = _git_head()
    # Either 40-char SHA or empty (if not a git repo / git unavailable).
    assert head == "" or (len(head) == 40 and all(c in "0123456789abcdef" for c in head))
