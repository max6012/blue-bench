"""Unit tests for blue_bench_eval.preflight — fully offline (stubbed ESClient).

Covers: all-green, ES-unreachable, an empty index, and a stale-window
(old max @timestamp) case. No live Elasticsearch required.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from blue_bench_eval import preflight
from blue_bench_eval.preflight import (
    ESError,
    PreflightReport,
    _indices_for_tools,
    run_preflight,
)
from blue_bench_mcp.config import ServerConfig


# --- fixtures ----------------------------------------------------------------

# Concrete index names used across the fake corpus.
INDEX_PATTERN = "logstash-suricata-alerts,wazuh-alerts,zeek-conn"
PATTERN_INDICES = INDEX_PATTERN.split(",")
SYSMON_INDEX = "windows-sysmon"


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    cfg = {
        "elastic": {"url": "http://localhost:9200", "index_pattern": INDEX_PATTERN},
        "zeek": {"index": "zeek-conn", "use_elastic": True},
        "sysmon": {"index": SYSMON_INDEX},
        "wazuh": {"es_fallback_index": "wazuh-alerts"},
    }
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


@pytest.fixture
def prompts_dir(tmp_path: Path) -> Path:
    d = tmp_path / "prompts"
    d.mkdir()
    # An ES-backed prompt (main pattern), a sysmon-backed prompt, and a
    # non-ES prompt (nmap only) that must report n/a without dragging ok false.
    (d / "p2-01.yaml").write_text(yaml.safe_dump({
        "id": "p2-01", "category": "triage", "title": "t", "question": "q",
        "expected_tools": ["search_alerts", "count_by_field"],
    }))
    (d / "p2-02.yaml").write_text(yaml.safe_dump({
        "id": "p2-02", "category": "host", "title": "t", "question": "q",
        "expected_tools": ["get_process_events"],
    }))
    (d / "p2-03.yaml").write_text(yaml.safe_dump({
        "id": "p2-03", "category": "recon", "title": "t", "question": "q",
        "expected_tools": ["nmap_scan"],
    }))
    return d


class FakeES:
    """Stub ESClient. Configure per-scenario behavior via constructor args."""

    def __init__(
        self,
        *,
        reachable: bool = True,
        counts: dict[str, int | None] | None = None,
        max_ts: datetime | None = None,
        probe_map: dict[str, int] | None = None,
        raise_on: str | None = None,
    ) -> None:
        self._reachable = reachable
        self._counts = counts or {}
        self._max_ts = max_ts
        self._probe_map = probe_map or {}
        self._raise_on = raise_on  # method name that should raise ESError

    def ping(self) -> tuple[bool, str]:
        if self._reachable:
            return True, "cluster health: green"
        return False, "unreachable at http://localhost:9200: ConnectError"

    def count(self, index: str) -> int | None:
        if self._raise_on == "count":
            raise ESError("count boom")
        return self._counts.get(index, 0)

    def max_timestamp(self, indices: list[str]) -> datetime | None:
        if self._raise_on == "max_timestamp":
            raise ESError("max_ts boom")
        return self._max_ts

    def probe_hits(self, indices: list[str], window_hours: int) -> int:
        if self._raise_on == "probe_hits":
            raise ESError("probe boom")
        # Real client does one union search returning the summed hit count
        # (">=1 hit somewhere"); mirror that here.
        return sum(self._probe_map.get(i, 0) for i in indices)


def _check(report: PreflightReport, name: str):
    for c in report.checks:
        if c.name == name:
            return c
    raise AssertionError(f"check {name!r} not found in {[c.name for c in report.checks]}")


# --- tool -> index mapping ---------------------------------------------------


def test_indices_for_tools_maps_backends():
    cfg = ServerConfig.model_validate({
        "elastic": {"index_pattern": INDEX_PATTERN},
        "sysmon": {"index": SYSMON_INDEX},
    })
    assert _indices_for_tools(["search_alerts"], cfg) == PATTERN_INDICES
    assert _indices_for_tools(["get_process_events"], cfg) == [SYSMON_INDEX]
    assert _indices_for_tools(["get_connections"], cfg) == ["zeek-conn"]
    assert _indices_for_tools(["get_agent_alerts"], cfg) == ["wazuh-alerts"]
    # Non-ES tool contributes nothing.
    assert _indices_for_tools(["nmap_scan"], cfg) == []


# --- scenario: all green -----------------------------------------------------


def test_all_green(config_path: Path, prompts_dir: Path):
    now = datetime.now(timezone.utc)
    fake = FakeES(
        counts={i: 100 for i in PATTERN_INDICES},
        max_ts=now - timedelta(hours=2),
        probe_map={i: 10 for i in PATTERN_INDICES + [SYSMON_INDEX]},
    )
    report = run_preflight(config_path, prompts_dir=prompts_dir, client=fake)
    assert report.ok is True
    assert _check(report, "es_reachable").passed
    assert _check(report, "indices_populated").passed
    assert _check(report, "window_covers_now").passed
    assert _check(report, "probe:p2-01").passed
    assert _check(report, "probe:p2-02").passed  # sysmon-only coverage
    # non-ES prompt: n/a, non-critical, passed.
    na = _check(report, "probe:p2-03")
    assert na.passed and na.critical is False and "n/a" in na.detail


def test_future_max_ts_still_covers_now(config_path: Path):
    # anchor-to-now / clock skew: max_ts slightly in the future must pass.
    now = datetime.now(timezone.utc)
    fake = FakeES(
        counts={i: 5 for i in PATTERN_INDICES},
        max_ts=now + timedelta(minutes=30),
    )
    report = run_preflight(config_path, client=fake)
    assert _check(report, "window_covers_now").passed
    assert report.ok is True


# --- scenario: ES unreachable ------------------------------------------------


def test_es_unreachable(config_path: Path, prompts_dir: Path):
    fake = FakeES(reachable=False)
    report = run_preflight(config_path, prompts_dir=prompts_dir, client=fake)
    assert report.ok is False
    assert _check(report, "es_reachable").passed is False
    # Downstream checks reported as failed (not silently skipped).
    assert _check(report, "indices_populated").passed is False
    assert _check(report, "window_covers_now").passed is False
    assert _check(report, "prompt_probes").passed is False
    assert "unreachable" in report.summary().lower()


# --- scenario: an empty index ------------------------------------------------


def test_empty_index_fails(config_path: Path):
    now = datetime.now(timezone.utc)
    counts = {i: 100 for i in PATTERN_INDICES}
    counts["wazuh-alerts"] = 0  # one empty index
    fake = FakeES(counts=counts, max_ts=now - timedelta(hours=1))
    report = run_preflight(config_path, client=fake)
    assert report.ok is False
    chk = _check(report, "indices_populated")
    assert chk.passed is False
    assert "wazuh-alerts" in chk.detail and "empty" in chk.detail


def test_missing_index_fails(config_path: Path):
    now = datetime.now(timezone.utc)
    counts: dict[str, int | None] = {i: 100 for i in PATTERN_INDICES}
    counts["zeek-conn"] = None  # 404 / missing
    fake = FakeES(counts=counts, max_ts=now - timedelta(hours=1))
    report = run_preflight(config_path, client=fake)
    assert report.ok is False
    chk = _check(report, "indices_populated")
    assert "MISSING" in chk.detail and "zeek-conn" in chk.detail


# --- scenario: stale window --------------------------------------------------


def test_stale_window_fails(config_path: Path):
    # The core bug: indices populated, but max @timestamp is months in the past
    # (un-anchored ingest). Lookback-from-now queries would return [].
    stale = datetime(2026, 3, 1, tzinfo=timezone.utc)
    fake = FakeES(counts={i: 100 for i in PATTERN_INDICES}, max_ts=stale)
    report = run_preflight(config_path, now_tolerance_hours=48, client=fake)
    assert report.ok is False
    # Indices are populated — so THIS check is what catches the bug.
    assert _check(report, "indices_populated").passed is True
    win = _check(report, "window_covers_now")
    assert win.passed is False
    assert "STALE" in win.detail
    assert "2026-03-01" in win.detail


def test_null_max_ts_fails_closed(config_path: Path):
    # ES up, pattern matched, but no usable @timestamp → fail closed.
    fake = FakeES(counts={i: 100 for i in PATTERN_INDICES}, max_ts=None)
    report = run_preflight(config_path, client=fake)
    assert report.ok is False
    win = _check(report, "window_covers_now")
    assert win.passed is False
    assert "cannot confirm" in win.detail.lower()


# --- per-prompt probe edge cases ---------------------------------------------


def test_prompt_probe_empty_for_prompt(config_path: Path, prompts_dir: Path):
    now = datetime.now(timezone.utc)
    # Everything populated + fresh, but sysmon has 0 docs in-window → the
    # sysmon-backed prompt probe fails while the pattern-backed one passes.
    fake = FakeES(
        counts={i: 100 for i in PATTERN_INDICES},
        max_ts=now - timedelta(hours=1),
        probe_map={i: 10 for i in PATTERN_INDICES},  # SYSMON_INDEX -> 0
    )
    report = run_preflight(config_path, prompts_dir=prompts_dir, client=fake)
    assert _check(report, "probe:p2-01").passed is True
    p2 = _check(report, "probe:p2-02")
    assert p2.passed is False
    assert "SIEM empty" in p2.detail
    assert report.ok is False


def test_transport_error_midrun_is_clean_failure(config_path: Path):
    now = datetime.now(timezone.utc)
    fake = FakeES(
        counts={i: 1 for i in PATTERN_INDICES},
        max_ts=now,
        raise_on="max_timestamp",
    )
    report = run_preflight(config_path, client=fake)
    win = _check(report, "window_covers_now")
    assert win.passed is False
    assert "boom" in win.detail  # ESError message surfaced, no traceback
    assert report.ok is False


# --- CLI ---------------------------------------------------------------------


def test_cli_exit_nonzero_when_not_ok(config_path: Path, monkeypatch):
    fake = FakeES(reachable=False)
    monkeypatch.setattr(
        preflight, "HttpxESClient", lambda cfg, **kw: fake
    )
    rc = preflight.main(["--config", str(config_path)])
    assert rc == 1


def test_cli_exit_zero_when_ok(config_path: Path, monkeypatch):
    now = datetime.now(timezone.utc)
    fake = FakeES(
        counts={i: 100 for i in PATTERN_INDICES},
        max_ts=now - timedelta(hours=1),
    )
    monkeypatch.setattr(
        preflight, "HttpxESClient", lambda cfg, **kw: fake
    )
    rc = preflight.main(["--config", str(config_path)])
    assert rc == 0
