"""Tests for blue_bench_eval.reanchor and preflight's anchor check.

Offline (stubbed ES admin / stubbed preflight client):
  * preflight branching: gap under tolerance -> no-op; over + reanchor on ->
    shift then re-check; over + reanchor off -> actionable failure; no anchor
    document -> bootstrap instructions; dry run -> delta printed, gate fails.
  * reanchor(): skips indices with no @timestamp, refuses under the ingest
    lock, advances the anchor by exactly the delta, raises on conflicts /
    noops, is a no-op within tolerance.
  * bootstrap: median of the large indices, refuses on a wide spread.

Live (skipped when ES at localhost:9200 is down):
  * Painless == _shift_embedded_times, field by field, on representative
    documents of every shape pushed through a real _update_by_query on a
    throwaway index. The script under test is imported from the module, not
    restated here.
  * Idempotency on the real corpus: with the anchor fresh, a second call is a
    no-op and leaves the anchor document byte-identical.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from blue_bench_eval import preflight, reanchor as ra
from blue_bench_eval.preflight import run_preflight
from blue_bench_eval.reanchor import (
    AnchorDoc,
    ESAdmin,
    IndexShift,
    ReanchorError,
    ReanchorResult,
    bootstrap_anchor,
    plan_delta,
    reanchor,
    script_params,
)

ES_URL = "http://localhost:9200"


def _es_up() -> bool:
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


live = pytest.mark.skipif(not _es_up(), reason="live Elasticsearch at localhost:9200 not reachable")


def _ingest_ef():
    spec = importlib.util.spec_from_file_location(
        "ingest_ef_for_reanchor", Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


def _anchor(hours_ago: float) -> AnchorDoc:
    end = NOW - timedelta(hours=hours_ago)
    return AnchorDoc(
        original_window_start="2026-03-02T05:00:00+00:00",
        original_window_end="2026-03-20T05:00:00+00:00",
        current_window_end=end.isoformat(),
        applied_delta_seconds=(end - datetime(2026, 3, 20, 5, tzinfo=timezone.utc)).total_seconds(),
        anchored_at=end.isoformat(),
        build_hash="abc",
        tier="L",
    )


# --- stub admin for reanchor() ----------------------------------------------


class FakeAdmin:
    """In-memory ESAdmin. Records every update-by-query submitted."""

    def __init__(self, *, anchor: AnchorDoc | None, indices: dict[str, int],
                 no_ts_mapping: set[str] = frozenset(), no_ts_docs: set[str] = frozenset(),
                 lock: dict | None = None, results: dict[str, dict] | None = None,
                 tasks_running: list[str] | None = None, busy: set[str] = frozenset()):
        self.anchor = anchor
        self._indices = indices
        self._no_map = set(no_ts_mapping)
        self._no_docs = set(no_ts_docs)
        self._lock = lock
        self._results = results or {}
        self._tasks = tasks_running or []
        self._busy = set(busy)
        self.submitted: list[tuple[str, dict]] = []
        self.refreshed: list[str] = []
        self.writes: list[AnchorDoc] = []

    def indices(self):
        return dict(self._indices)

    def has_timestamp_mapping(self, index):
        return index not in self._no_map

    def count_with_timestamp(self, index):
        return 0 if index in self._no_docs else self._indices[index]

    def read_anchor(self):
        return copy.deepcopy(self.anchor)

    def write_anchor(self, doc):
        self.anchor = copy.deepcopy(doc)
        self.writes.append(copy.deepcopy(doc))

    def read_ingest_lock(self):
        return self._lock

    def byquery_tasks(self):
        return list(self._tasks)

    def indexing_in_flight(self, index):
        return 1 if index in self._busy else 0

    def submit_update_by_query(self, index, params, **kw):
        self.submitted.append((index, dict(params)))
        return f"node:{len(self.submitted)}"

    def task_status(self, task_id):
        index = self.submitted[int(task_id.split(":")[1]) - 1][0]
        n = self._indices[index]
        resp = {"total": n, "updated": n, "noops": 0, "version_conflicts": 0, "failures": []}
        resp.update(self._results.get(index, {}))
        return {"completed": True, "response": resp}

    def refresh(self, index):
        self.refreshed.append(index)


L_INDICES = {
    "windows-sysmon": 938_504, "ecar-edr": 3_439_129, "zeek-conn": 1_401_748,
    "ot-modbus": 622_080, "ot-assets": 40, "wazuh-alerts": 2, "empty-idx": 0,
}


def test_reanchor_noop_within_tolerance():
    fa = FakeAdmin(anchor=_anchor(hours_ago=1.5), indices=L_INDICES)
    assert reanchor(fa, tolerance_hours=2, now=NOW) is None
    assert fa.submitted == [] and fa.writes == []


def test_reanchor_shifts_every_timestamped_index_and_advances_anchor():
    fa = FakeAdmin(anchor=_anchor(hours_ago=65.5), indices=L_INDICES, no_ts_docs={"ot-assets"})
    logs: list[str] = []
    res = reanchor(fa, tolerance_hours=2, now=NOW, log=logs.append)
    assert isinstance(res, ReanchorResult)
    # Whole seconds, exactly the gap.
    assert res.delta_seconds == int(65.5 * 3600)
    shifted = [i for i, _ in fa.submitted]
    assert shifted == ["ecar-edr", "ot-modbus", "wazuh-alerts", "windows-sysmon", "zeek-conn"]
    assert fa.refreshed == shifted
    skipped = {s.index: s.skipped_reason for s in res.shifts if s.skipped_reason}
    assert skipped == {"ot-assets": "no document carries @timestamp", "empty-idx": "empty"}
    # Params are what ingest would compute for the same delta.
    assert fa.submitted[0][1] == script_params(timedelta(seconds=res.delta_seconds))
    # Anchor advanced by exactly the delta; in_progress flagged during, cleared after.
    assert fa.writes[0].in_progress is True
    final = fa.anchor
    assert final.in_progress is False
    assert final.current_end == NOW - timedelta(hours=65.5) + timedelta(seconds=res.delta_seconds)
    assert final.reanchor_runs == 1
    assert final.applied_delta_seconds == _anchor(65.5).applied_delta_seconds + res.delta_seconds
    assert res.docs_updated == sum(L_INDICES[i] for i in shifted)
    assert res.gap_before_hours == pytest.approx(65.5)
    assert res.gap_after_hours == pytest.approx(0, abs=1 / 3600)
    assert "delta = +" in res.summary()


def test_reanchor_dry_run_writes_nothing():
    fa = FakeAdmin(anchor=_anchor(hours_ago=65.5), indices=L_INDICES)
    res = reanchor(fa, tolerance_hours=2, now=NOW, dry_run=True)
    assert res.dry_run and res.delta_seconds == int(65.5 * 3600)
    assert fa.submitted == [] and fa.writes == []
    assert "would apply" in res.summary()


def test_reanchor_refuses_under_ingest_lock_and_running_tasks():
    fa = FakeAdmin(anchor=_anchor(65.5), indices=L_INDICES, lock={"started_at": "x", "ef_dir": "/c", "pid": 1})
    with pytest.raises(ReanchorError, match="ingest holds"):
        reanchor(fa, tolerance_hours=2, now=NOW)
    assert fa.submitted == []
    fa = FakeAdmin(anchor=_anchor(65.5), indices=L_INDICES, tasks_running=["n:1: update-by-query [zeek-conn]"])
    with pytest.raises(ReanchorError, match="already running"):
        reanchor(fa, tolerance_hours=2, now=NOW)
    fa = FakeAdmin(anchor=_anchor(65.5), indices=L_INDICES, busy={"zeek-conn"})
    with pytest.raises(ReanchorError, match="in flight on: zeek-conn"):
        reanchor(fa, tolerance_hours=2, now=NOW)
    a = _anchor(65.5)
    a.in_progress = True
    fa = FakeAdmin(anchor=a, indices=L_INDICES)
    with pytest.raises(ReanchorError, match="in progress"):
        reanchor(fa, tolerance_hours=2, now=NOW)


def test_reanchor_raises_on_conflicts_but_still_advances_anchor():
    fa = FakeAdmin(anchor=_anchor(65.5), indices=L_INDICES,
                   results={"zeek-conn": {"version_conflicts": 3, "updated": 1_401_745}})
    with pytest.raises(ReanchorError, match="MIXED") as ei:
        reanchor(fa, tolerance_hours=2, now=NOW)
    assert "zeek-conn: updated=1401745 noops=0 version_conflicts=3" in str(ei.value)
    # The other indices DID move, so a retry must not double-shift them.
    assert fa.anchor.in_progress is False
    assert fa.anchor.current_end == NOW - timedelta(hours=65.5) + timedelta(seconds=int(65.5 * 3600))


def test_reanchor_without_anchor_says_bootstrap():
    fa = FakeAdmin(anchor=None, indices=L_INDICES)
    with pytest.raises(ReanchorError, match="--bootstrap-anchor"):
        reanchor(fa, tolerance_hours=2, now=NOW)


def test_plan_delta_is_whole_seconds():
    a = _anchor(0)
    a.current_window_end = (NOW - timedelta(seconds=100, microseconds=999_999)).isoformat()
    assert plan_delta(a, NOW) == timedelta(seconds=100)


# --- bootstrap ----------------------------------------------------------------


class BootstrapAdmin(FakeAdmin):
    def __init__(self, maxes: dict[str, datetime], counts: dict[str, int], mins: dict[str, datetime] | None = None):
        super().__init__(anchor=None, indices=counts)
        self._maxes = maxes
        self._mins = mins or {}

    def max_timestamp(self, index):
        return self._maxes.get(index)

    def _req(self, method, path, **kw):
        idx = path.split("/")[1]
        mn = self._mins.get(idx)
        return {"aggregations": {"mn": {"value_as_string": mn.isoformat() if mn else None}}}


def _manifest(tmp_path: Path) -> Path:
    p = tmp_path / "corpus-manifest.yaml"
    p.write_text(yaml.safe_dump({
        "tier": "L", "build_hash": "efe42d",
        "window": {"start": "2026-03-02T05:00:00", "end": "2026-03-20T05:00:00"},
    }))
    return p


def test_bootstrap_uses_median_of_large_indices(tmp_path):
    tail = datetime(2026, 9, 11, 16, 19, 30, tzinfo=timezone.utc)
    maxes = {
        "windows-sysmon": tail + timedelta(hours=3),   # clock-skew outlier
        "windows-security": tail + timedelta(hours=3),
        "ecar-edr": tail - timedelta(seconds=2),
        "zeek-conn": tail - timedelta(seconds=13),
        "ot-modbus": tail - timedelta(seconds=1),
        "zeek-files": tail - timedelta(minutes=9),
        "linux-syslog": tail + timedelta(minutes=41),
        "wazuh-alerts": tail - timedelta(hours=2),     # 2 docs: must not vote
    }
    counts = {k: 500_000 for k in maxes}
    counts["wazuh-alerts"] = 2
    fa = BootstrapAdmin(maxes, counts, mins={"zeek-conn": tail - timedelta(days=18)})
    res = bootstrap_anchor(fa, _manifest(tmp_path))
    assert "wazuh-alerts" not in res.voters and len(res.voters) == 7
    assert res.anchor.current_end == tail - timedelta(seconds=1)   # median of 7
    assert res.anchor.original_window_end == "2026-03-20T05:00:00+00:00"
    assert res.anchor.build_hash == "efe42d" and res.anchor.tier == "L"
    assert res.anchor.applied_delta_seconds == (tail - timedelta(seconds=1) - datetime(2026, 3, 20, 5, tzinfo=timezone.utc)).total_seconds()
    assert res.spread_hours == pytest.approx(3 + 9 / 60, abs=0.01)
    assert res.min_based_estimate == tail.isoformat()
    assert fa.anchor is not None and "median" in res.summary()


def test_bootstrap_refuses_partial_corpus(tmp_path):
    tail = datetime(2026, 9, 11, 16, 19, 30, tzinfo=timezone.utc)
    maxes = {"a": tail, "b": tail, "c": tail - timedelta(hours=30)}   # c ingested on another day
    fa = BootstrapAdmin(maxes, {k: 500_000 for k in maxes})
    with pytest.raises(ReanchorError, match="disagree by 30.0h"):
        bootstrap_anchor(fa, _manifest(tmp_path))
    assert fa.anchor is None


def test_bootstrap_refuses_to_overwrite_without_force(tmp_path):
    fa = BootstrapAdmin({"a": NOW, "b": NOW, "c": NOW}, {"a": 1, "b": 1, "c": 1})
    fa.anchor = _anchor(1)
    with pytest.raises(ReanchorError, match="already exists"):
        bootstrap_anchor(fa, _manifest(tmp_path))


# --- preflight branching ------------------------------------------------------


class FakePreflightES:
    """Stub preflight ESClient with an anchor and a recording reanchor()."""

    def __init__(self, *, anchor: AnchorDoc | None, max_ts: datetime, shift_result: ReanchorResult | None = None,
                 raise_on_reanchor: str | None = None):
        self.anchor = anchor
        self.max_ts = max_ts
        self.calls: list[dict] = []
        self._result = shift_result
        self._raise = raise_on_reanchor

    def ping(self):
        return True, "cluster health: green"

    def count(self, index):
        return 100

    def max_timestamp(self, indices):
        return self.max_ts

    def probe_hits(self, indices, window_hours):
        return 5

    def read_anchor(self):
        return self.anchor

    def reanchor(self, *, tolerance_hours, dry_run):
        self.calls.append({"tolerance_hours": tolerance_hours, "dry_run": dry_run})
        if self._raise:
            raise ReanchorError(self._raise)
        if self._result is None:
            return None
        if not dry_run:
            # The corpus moved: the window check that follows must see it.
            self.max_ts = self.max_ts + timedelta(seconds=self._result.delta_seconds)
            self.anchor.current_window_end = self._result.anchor_after
        return self._result


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump({"elastic": {"url": ES_URL, "index_pattern": "zeek-conn"}}))
    return p


def _check(report, name):
    for c in report.checks:
        if c.name == name:
            return c
    raise AssertionError(f"{name!r} not in {[c.name for c in report.checks]}")


def _shift_result(delta_s: int, gap_before: float) -> ReanchorResult:
    return ReanchorResult(
        delta_seconds=delta_s, gap_before_hours=gap_before, gap_after_hours=0.0,
        anchor_before="x", anchor_after=(datetime.now(timezone.utc)).isoformat(),
        shifts=[IndexShift("zeek-conn", total=100, updated=100, seconds=3.0),
                IndexShift("ot-assets", total=40, skipped_reason="no document carries @timestamp")],
        wall_seconds=3.0,
    )


def test_preflight_gap_under_tolerance_is_noop(config_path):
    now = datetime.now(timezone.utc)
    fake = FakePreflightES(anchor=_anchor_at(now - timedelta(hours=1)), max_ts=now - timedelta(hours=1))
    report = run_preflight(config_path, client=fake, reanchor=True, reanchor_tolerance_hours=2)
    assert report.ok
    chk = _check(report, "corpus_anchor")
    assert chk.passed and "fresh" in chk.detail
    assert fake.calls == []


def test_preflight_stale_with_reanchor_shifts_then_rechecks(config_path):
    now = datetime.now(timezone.utc)
    stale_end = now - timedelta(hours=65)
    fake = FakePreflightES(anchor=_anchor_at(stale_end), max_ts=stale_end,
                           shift_result=_shift_result(65 * 3600, 65.0))
    report = run_preflight(config_path, client=fake, reanchor=True, reanchor_tolerance_hours=2,
                           now_tolerance_hours=48)
    assert fake.calls == [{"tolerance_hours": 2, "dry_run": False}]
    names = [c.name for c in report.checks]
    # Before-record demoted, anchor check passed, fresh window check appended.
    assert names == ["es_reachable", "indices_populated", "window_covers_now_before_reanchor",
                     "corpus_anchor", "window_covers_now"]
    before = _check(report, "window_covers_now_before_reanchor")
    assert before.passed is False and before.critical is False
    anchor = _check(report, "corpus_anchor")
    assert anchor.passed
    assert "delta +234000s (65.00h)" in anchor.detail
    assert "gap before 65.00h, after 0.00h" in anchor.detail
    assert "zeek-conn=100" in anchor.detail and "ot-assets (no document carries @timestamp)" in anchor.detail
    after = _check(report, "window_covers_now")
    assert after.passed and after.critical
    assert report.ok


def test_preflight_stale_with_reanchor_off_fails_with_command(config_path):
    now = datetime.now(timezone.utc)
    stale_end = now - timedelta(hours=10)   # inside the 48h window tolerance, outside ours
    fake = FakePreflightES(anchor=_anchor_at(stale_end), max_ts=stale_end)
    report = run_preflight(config_path, client=fake, reanchor=False, reanchor_tolerance_hours=2)
    assert fake.calls == []
    assert _check(report, "window_covers_now").passed   # 10h < 48h: the old check is blind to this
    chk = _check(report, "corpus_anchor")
    assert chk.passed is False and chk.critical
    assert "STALE" in chk.detail and "python -m blue_bench_eval.reanchor" in chk.detail
    assert report.ok is False


def test_preflight_dry_run_reports_delta_and_fails(config_path):
    now = datetime.now(timezone.utc)
    stale_end = now - timedelta(hours=65)
    res = _shift_result(65 * 3600, 65.0)
    res.dry_run = True
    fake = FakePreflightES(anchor=_anchor_at(stale_end), max_ts=stale_end, shift_result=res)
    report = run_preflight(config_path, client=fake, reanchor=True, reanchor_dry_run=True,
                           reanchor_tolerance_hours=2)
    assert fake.calls == [{"tolerance_hours": 2, "dry_run": True}]
    chk = _check(report, "corpus_anchor")
    assert chk.passed is False and "DRY RUN: would apply +234000s" in chk.detail
    assert "1 indices, 100 docs" in chk.detail
    assert report.ok is False


def test_preflight_no_anchor_doc(config_path):
    now = datetime.now(timezone.utc)
    fake = FakePreflightES(anchor=None, max_ts=now)
    # reanchor off: informational only
    report = run_preflight(config_path, client=fake, reanchor=False)
    chk = _check(report, "corpus_anchor")
    assert chk.passed and chk.critical is False and "--bootstrap-anchor" in chk.detail
    assert report.ok
    # reanchor on: cannot do what was asked -> critical
    report = run_preflight(config_path, client=fake, reanchor=True)
    chk = _check(report, "corpus_anchor")
    assert chk.passed is False and chk.critical and "--bootstrap-anchor" in chk.detail
    assert report.ok is False and fake.calls == []


def test_preflight_reanchor_failure_is_a_clean_failed_check(config_path):
    now = datetime.now(timezone.utc)
    stale_end = now - timedelta(hours=65)
    fake = FakePreflightES(anchor=_anchor_at(stale_end), max_ts=stale_end, raise_on_reanchor="an ingest holds bb-meta/ingest-lock")
    report = run_preflight(config_path, client=fake, reanchor=True, reanchor_tolerance_hours=2)
    chk = _check(report, "corpus_anchor")
    assert chk.passed is False and "re-anchor FAILED: an ingest holds" in chk.detail
    assert report.ok is False


def test_preflight_cli_flags(config_path, monkeypatch, capsys):
    seen = {}

    def fake_run(cfg, **kw):
        seen.update(kw)
        return preflight.PreflightReport(config_path=str(cfg))

    monkeypatch.setattr(preflight, "run_preflight", fake_run)
    assert preflight.main(["--config", str(config_path), "--reanchor", "--dry-run",
                           "--reanchor-tolerance-hours", "3"]) == 0
    assert seen["reanchor"] is True and seen["reanchor_dry_run"] is True
    assert seen["reanchor_tolerance_hours"] == 3.0
    assert preflight.main(["--config", str(config_path), "--no-reanchor"]) == 0
    assert seen["reanchor"] is False


def _anchor_at(end: datetime) -> AnchorDoc:
    return AnchorDoc(
        original_window_start="2026-03-02T05:00:00+00:00",
        original_window_end="2026-03-20T05:00:00+00:00",
        current_window_end=end.isoformat(),
        applied_delta_seconds=0.0,
        anchored_at=end.isoformat(),
    )


# --- live: Painless == _shift_embedded_times ---------------------------------

# One document per shape the corpus actually holds (sampled from the L corpus
# 2026-09-14), plus the raw pre-ingest shapes _parse_iso accepts and the
# unparseable values it leaves alone.
SHAPES: list[dict] = [
    # windows-sysmon (EVTX baseline): TimeCreated ISO + UtcTime ms
    {"@timestamp": "2026-08-24T16:21:56.175887+00:00", "TimeCreated": "2026-08-24T16:21:56.175887+00:00",
     "UtcTime": "2026-08-24 16:21:56.175", "EventID": 1},
    # windows-security (EVTX): TimeCreated only
    {"@timestamp": "2026-08-24T16:19:56.993556+00:00", "TimeCreated": "2026-08-24T16:19:56.993556+00:00"},
    # injected sysmon NDJSON: UtcTime only, whole-second variant
    {"@timestamp": "2026-09-01T22:05:00+00:00", "UtcTime": "2026-09-01 22:05:00.000", "event_id": 1},
    # zeek-* / ot-* protocol: ts epoch string
    {"@timestamp": "2026-09-11T14:35:18.790470+00:00", "ts": "1789137318.790470", "uid": "C1"},
    {"@timestamp": "2026-09-11T16:16:12.409883+00:00", "ts": "1789143372.409883", "func": "read"},
    # ecar-edr: timestamp_ms int
    {"@timestamp": "2026-09-06T14:35:05.731883+00:00", "timestamp_ms": 1788705305732},
    # linux-syslog / ot-hosts: ISO timestamp
    {"@timestamp": "2026-09-11T12:58:56.378503+00:00", "timestamp": "2026-09-11T12:58:56.378503+00:00"},
    # suricata / wazuh: UtcTime
    {"@timestamp": "2026-09-11T14:50:32.409883+00:00", "UtcTime": "2026-09-11 14:50:32.409"},
    # raw pre-ingest shapes _parse_iso normalises
    {"@timestamp": "2026-03-02T10:24:01.1234567Z", "TimeCreated": "2026-03-02T10:24:01.1234567Z",
     "EventTime": "2026-03-02T10:24:01+0000", "timestamp": "2026-03-02 10:24:01.141", "UtcTime": "2026-03-02 10:24:01.141"},
    {"@timestamp": "2026-12-31T23:59:59.999999+05:30", "EventTime": "2026-12-31T23:59:59.5-00:00", "timestamp": "2026-12-31"},
    # month/year roll-over
    {"@timestamp": "2026-02-28T23:30:00+00:00", "UtcTime": "2026-02-28 23:59:59.999", "ts": "1772323199.999999"},
    # values Python leaves untouched
    {"@timestamp": "2026-09-11T16:19:28.5Z", "ts": "-", "timestamp_ms": "", "UtcTime": "garbage",
     "TimeCreated": "", "timestamp": "1789143372.409883", "EventTime": "not a date"},
    {"@timestamp": "2026-09-11T16:19:28+00:00", "ts": 1789143372.409883, "timestamp_ms": "123", "timestamp": 12345},
    # ot-assets-like: no @timestamp at all, nothing to shift
    {"fqdn": "hmi-03.plant.example.invalid", "role": "hmi"},
]


def _python_expected(doc: dict, delta: timedelta, ie) -> dict:
    out = copy.deepcopy(doc)
    ie._shift_embedded_times(out, delta)
    if "@timestamp" in out:
        t = ie._parse_iso(out["@timestamp"])
        out["@timestamp"] = (t + delta).isoformat()
    return out


def _wait_yellow(index: str) -> None:
    httpx.get(f"{ES_URL}/_cluster/health/{index}", params={"wait_for_status": "yellow", "timeout": "30s"}, timeout=40)


@live
@pytest.mark.parametrize("delta", [timedelta(seconds=234_000), timedelta(hours=1, microseconds=123_456)])
def test_live_painless_matches_shift_embedded_times(delta: timedelta):
    ie = _ingest_ef()
    admin = ESAdmin(ES_URL)
    index = f"bb-test-reanchor-{uuid.uuid4().hex[:8]}"
    try:
        httpx.put(f"{ES_URL}/{index}", json=ie._index_mappings(["@timestamp", "ts", "UtcTime"]), timeout=15).raise_for_status()
        _wait_yellow(index)
        lines = []
        for i, doc in enumerate(SHAPES):
            lines.append(json.dumps({"index": {"_index": index, "_id": f"d{i}"}}))
            lines.append(json.dumps(doc))
        r = httpx.post(f"{ES_URL}/_bulk", content="\n".join(lines) + "\n",
                       headers={"Content-Type": "application/x-ndjson"}, params={"refresh": "true"}, timeout=30)
        r.raise_for_status()
        assert not r.json().get("errors"), r.text[:500]

        task = admin.submit_update_by_query(index, script_params(delta))
        st = ra._poll(admin, task, interval=0.5)
        resp = st["response"]
        assert resp["updated"] == len(SHAPES), resp
        assert resp["noops"] == 0 and resp["version_conflicts"] == 0 and resp["failures"] == [], resp
        admin.refresh(index)

        got = httpx.get(f"{ES_URL}/{index}/_search", params={"size": 100}, timeout=15).json()
        by_id = {h["_id"]: h["_source"] for h in got["hits"]["hits"]}
        assert len(by_id) == len(SHAPES)
        for i, doc in enumerate(SHAPES):
            expected = _python_expected(doc, delta, ie)
            assert by_id[f"d{i}"] == expected, f"doc {i}: {json.dumps(by_id[f'd{i}'])} != {json.dumps(expected)}"
    finally:
        httpx.delete(f"{ES_URL}/{index}", timeout=15)


@live
def test_live_second_reanchor_within_tolerance_is_noop():
    """On the real corpus: after a re-anchor the anchor is fresh, and another
    call changes nothing. Tolerance is set generously so this holds however
    long ago the last live re-anchor happened to run."""
    admin = ESAdmin(ES_URL)
    before = admin.read_anchor()
    if before is None:
        pytest.skip("no bb-meta/corpus-anchor on this ES (bootstrap it first)")
    gap = ra.gap_hours(before)
    logs: list[str] = []
    assert reanchor(admin, tolerance_hours=gap + 1, log=logs.append) is None
    assert any("within tolerance" in l for l in logs)
    assert asdict(admin.read_anchor()) == asdict(before)


def test_preflight_fresh_anchor_but_stale_index_names_mixed_corpus(config_path):
    # A crashed re-anchor advanced the anchor (the finished indices moved) but
    # left this index behind. --reanchor would no-op; the check must say re-ingest.
    now = datetime.now(timezone.utc)
    fake = FakePreflightES(anchor=_anchor_at(now - timedelta(minutes=10)), max_ts=now - timedelta(hours=65))
    report = run_preflight(config_path, client=fake, reanchor=True, reanchor_tolerance_hours=2)
    assert fake.calls == []
    chk = _check(report, "corpus_anchor")
    assert chk.passed is False and "mixed" in chk.detail and "re-ingest" in chk.detail
    assert report.ok is False
