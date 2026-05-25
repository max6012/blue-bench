"""Windows EventLog generator tests for `t-it-base` subtask t-08mn.

Cover only-Windows emission, determinism, window bounds, rate
fidelity (4624 + 4625 ratio, 4688), logon/logoff pairing, admin
4672 sibling, logon-type distribution per host class, SubStatus
enum membership, and the 7036 servers-only rule.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.evtx import generate
from blue_bench_generators.it_baseline.topology import build_topology


# --- helpers ---------------------------------------------------------------


# 8-hour weekday daytime window: comfortable spread across the
# 9-17 peak so 4624/4625/4688 rates have enough events for the
# ratio + volume tests to be statistically stable.
_START = datetime(2026, 5, 11, 9, 0, 0)  # Monday 09:00
_END = _START + timedelta(hours=8)


def _build(tier: str = "M", seed: int = 0):
    topo = build_topology(tier)  # type: ignore[arg-type]
    am = build_activity_model(topo)
    events = list(generate(topo, am, _START, _END, seed=seed))
    return topo, am, events


def _windows_host_names(topology) -> set[str]:
    return {h.name for h in topology.hosts if h.os == "windows"}


def _linux_host_names(topology) -> set[str]:
    return {h.name for h in topology.hosts if h.os == "linux"}


# --- tests ----------------------------------------------------------------


def test_only_windows_hosts_emit_events():
    topo, _am, events = _build()
    linux_names = _linux_host_names(topo)
    assert events, "expected non-empty event stream for M tier 8-hour window"
    for ev in events:
        assert ev.get("HostName") not in linux_names, (
            f"event emitted for non-Windows host: {ev}"
        )


def test_envelope_fields_present():
    _topo, _am, events = _build()
    for ev in events:
        assert ev["_log"] == "winevtx"
        assert ev["channel"] in {"Security", "System"}
        assert isinstance(ev["event_id"], int)
        # System channel exclusively for 7036; Security for the rest.
        if ev["event_id"] == 7036:
            assert ev["channel"] == "System"
        else:
            assert ev["channel"] == "Security"


def test_deterministic_with_seed():
    _t1, _a1, e1 = _build(seed=123)
    _t2, _a2, e2 = _build(seed=123)
    assert e1 == e2
    _t3, _a3, e3 = _build(seed=7)
    assert e1 != e3, "different seeds must produce different streams"


def test_no_events_outside_window():
    _topo, _am, events = _build()
    for ev in events:
        ts = datetime.fromisoformat(ev["timestamp"])
        assert _START <= ts < _END, f"event timestamp outside window: {ev}"


def test_4624_volume_matches_logon_attempt_rate():
    topo, am, events = _build()
    by_host_4624: dict[str, int] = {}
    for ev in events:
        if ev["event_id"] == 4624:
            by_host_4624[ev["HostName"]] = (
                by_host_4624.get(ev["HostName"], 0) + 1
            )

    # Expected count = sum_{hour in window} rate(host, "logon_attempt", t).
    # Tolerance: ±60% (driven by the integer floor-and-Bernoulli model and
    # low-rate hosts where one extra event swings the count meaningfully).
    cursor = _START
    expected: dict[str, float] = {}
    while cursor < _END:
        for h in topo.hosts:
            if h.os != "windows":
                continue
            expected[h.name] = expected.get(h.name, 0.0) + am.rate(
                h, "logon_attempt", cursor
            )
        cursor += timedelta(hours=1)

    # Drop tiny-expected hosts (<3 events expected) -- one-event noise
    # dominates; the tolerance check would be vacuous.
    for hname, exp in expected.items():
        if exp < 3.0:
            continue
        actual = by_host_4624.get(hname, 0)
        lo, hi = exp * 0.4, exp * 1.6
        assert lo <= actual <= hi, (
            f"4624 count for {hname}={actual} outside [{lo:.1f}, {hi:.1f}] "
            f"(expected {exp:.1f})"
        )


def test_4625_to_4624_ratio_matches_behavior_model():
    _topo, _am, events = _build(tier="L")  # L for more samples
    n_4624 = sum(1 for e in events if e["event_id"] == 4624)
    n_4625 = sum(1 for e in events if e["event_id"] == 4625)
    assert n_4624 > 100, f"need enough 4624 to compute a ratio (got {n_4624})"

    # Expected ratio is the behavior table's failure/attempt = ~2%
    # uniformly across roles. Test the global aggregate within ±50%.
    ratio = n_4625 / n_4624
    expected = 0.02  # ~ 0.1/5 for workstations; 3/200 for DC; ~similar.
    lo, hi = expected * 0.5, expected * 1.5
    assert lo <= ratio <= hi, (
        f"4625/4624 ratio {ratio:.4f} outside [{lo:.4f}, {hi:.4f}]"
    )


def test_4624_logoff_pairing():
    _topo, _am, events = _build()
    by_id_4624: dict[str, dict] = {}
    by_id_4634: dict[str, dict] = {}
    for ev in events:
        if ev["event_id"] == 4624:
            by_id_4624[ev["TargetLogonId"]] = ev
        elif ev["event_id"] == 4634:
            by_id_4634[ev["TargetLogonId"]] = ev

    # Every 4634 must have a matching 4624.
    for lid, ev in by_id_4634.items():
        assert lid in by_id_4624, (
            f"4634 with TargetLogonId={lid} has no 4624 partner"
        )
        # Matching subject + logon type.
        partner = by_id_4624[lid]
        assert ev["TargetUserName"] == partner["TargetUserName"]
        assert ev["LogonType"] == partner["LogonType"]

    # At least *some* 4624s pair to a 4634 inside the window (8-hour
    # window vs 15min-4h session means most sessions close in-window).
    paired = sum(1 for lid in by_id_4624 if lid in by_id_4634)
    assert paired > 0, "expected at least one 4624 to pair to a 4634 in-window"


def test_admin_logons_emit_4672():
    topo, _am, events = _build()
    admin_users = {u.username for u in topo.users if u.role == "admin"}
    by_id_4624 = {
        e["TargetLogonId"]: e for e in events if e["event_id"] == 4624
    }
    by_id_4672 = {
        e["SubjectLogonId"]: e for e in events if e["event_id"] == 4672
    }
    for lid, ev in by_id_4624.items():
        if ev["TargetUserName"] in admin_users:
            assert lid in by_id_4672, (
                f"admin 4624 (TargetLogonId={lid}, "
                f"user={ev['TargetUserName']}) has no 4672 sibling"
            )


def test_4688_volume_matches_process_creation_rate():
    topo, am, events = _build()
    by_host_4688: dict[str, int] = {}
    for ev in events:
        if ev["event_id"] == 4688:
            by_host_4688[ev["HostName"]] = (
                by_host_4688.get(ev["HostName"], 0) + 1
            )
    cursor = _START
    expected: dict[str, float] = {}
    while cursor < _END:
        for h in topo.hosts:
            if h.os != "windows":
                continue
            expected[h.name] = expected.get(h.name, 0.0) + am.rate(
                h, "process_creation", cursor
            )
        cursor += timedelta(hours=1)
    for hname, exp in expected.items():
        if exp < 20.0:
            continue
        actual = by_host_4688.get(hname, 0)
        lo, hi = exp * 0.6, exp * 1.4
        assert lo <= actual <= hi, (
            f"4688 count for {hname}={actual} outside [{lo:.1f}, {hi:.1f}] "
            f"(expected {exp:.1f})"
        )


def test_logon_types_distribution():
    topo, _am, events = _build(tier="L")
    workstation_names = {
        h.name for h in topo.hosts if h.role in ("workstation", "admin-workstation")
    }
    server_windows_names = {
        h.name
        for h in topo.hosts
        if h.os == "windows" and h.role not in ("workstation", "admin-workstation")
    }

    type_counts_ws: dict[int, int] = {}
    type_counts_srv: dict[int, int] = {}
    for ev in events:
        if ev["event_id"] != 4624:
            continue
        host = ev["HostName"]
        if host in workstation_names:
            type_counts_ws[ev["LogonType"]] = (
                type_counts_ws.get(ev["LogonType"], 0) + 1
            )
        elif host in server_windows_names:
            type_counts_srv[ev["LogonType"]] = (
                type_counts_srv.get(ev["LogonType"], 0) + 1
            )

    if type_counts_ws:
        total_ws = sum(type_counts_ws.values())
        # type 2 dominant on workstations
        assert (
            type_counts_ws.get(2, 0) / total_ws > 0.5
        ), f"type-2 not dominant on workstations: {type_counts_ws}"
    if type_counts_srv:
        total_srv = sum(type_counts_srv.values())
        assert (
            type_counts_srv.get(3, 0) / total_srv > 0.5
        ), f"type-3 not dominant on servers: {type_counts_srv}"


def test_failure_substatus_in_known_set():
    _topo, _am, events = _build()
    allowed = {
        "0xC0000064",
        "0xC000006A",
        "0xC0000234",
        "0xC0000071",
        "0xC0000072",
    }
    seen_any = False
    for ev in events:
        if ev["event_id"] != 4625:
            continue
        seen_any = True
        assert ev["SubStatus"] in allowed, (
            f"unknown SubStatus {ev['SubStatus']}: {ev}"
        )
    assert seen_any, "expected at least one 4625 event in the M-tier window"


def test_service_events_emit_on_servers():
    topo, _am, events = _build()
    workstation_names = {
        h.name for h in topo.hosts if h.role in ("workstation", "admin-workstation")
    }
    server_windows_names = {
        h.name
        for h in topo.hosts
        if h.os == "windows" and h.role not in ("workstation", "admin-workstation")
    }
    saw_on_server = False
    for ev in events:
        if ev["event_id"] != 7036:
            continue
        assert ev["HostName"] not in workstation_names, (
            f"7036 emitted on workstation: {ev}"
        )
        if ev["HostName"] in server_windows_names:
            saw_on_server = True
    assert saw_on_server, (
        "expected at least one 7036 on a Windows server in the window"
    )


def test_volume_responds_to_time_of_day():
    """Daytime weekday hours should produce more 4624s than overnight."""
    topo = build_topology("M")  # type: ignore[arg-type]
    am = build_activity_model(topo)
    # 4-hour daytime slice vs 4-hour overnight slice, same length so
    # the comparison reduces to the time-of-day multiplier.
    day_start = datetime(2026, 5, 11, 10, 0, 0)
    day_end = day_start + timedelta(hours=4)
    night_start = datetime(2026, 5, 11, 2, 0, 0)
    night_end = night_start + timedelta(hours=4)

    day_events = list(generate(topo, am, day_start, day_end, seed=11))
    night_events = list(generate(topo, am, night_start, night_end, seed=11))

    day_4624 = sum(1 for e in day_events if e["event_id"] == 4624)
    night_4624 = sum(1 for e in night_events if e["event_id"] == 4624)
    assert day_4624 > night_4624, (
        f"expected more 4624 events during day ({day_4624}) "
        f"than overnight ({night_4624})"
    )


def test_empty_window_returns_no_events():
    topo = build_topology("S")  # type: ignore[arg-type]
    am = build_activity_model(topo)
    events = list(generate(topo, am, _START, _START, seed=0))
    assert events == []
    events = list(generate(topo, am, _END, _START, seed=0))
    assert events == []
