"""Tests for the OT host log generator (t-ot-host).

Acceptance bar: schema coverage per event family, operator-shift
volume model, anomaly visibility, determinism, host-role discipline
(no embedded-RTOS roles emit), composer-signature compatibility.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators import ot_hosts
from blue_bench_generators.ot_hosts.hosts import (
    AnomalyWindow,
    generate_for_network,
)
from blue_bench_generators.ot_protocols.topology import (
    OTNetwork,
    build_ot_network,
)


# --- shared fixtures -------------------------------------------------------


# Monday 2026-01-05 -- mirrors composer.DEFAULT_START so on-shift /
# off-shift boundaries align across the test suite.
WINDOW_START = datetime(2026, 1, 5, 0, 0, 0)
WINDOW_END_1D = datetime(2026, 1, 6, 0, 0, 0)
WINDOW_END_3D = datetime(2026, 1, 8, 0, 0, 0)


@pytest.fixture(scope="module")
def net_s() -> OTNetwork:
    return build_ot_network(tier="S", seed=0)


@pytest.fixture(scope="module")
def net_m() -> OTNetwork:
    return build_ot_network(tier="M", seed=0)


@pytest.fixture(scope="module")
def events_clean_1d(net_s: OTNetwork) -> list[dict]:
    return list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0))


# --- schema ---------------------------------------------------------------


_COMMON_REQUIRED = {"_log", "timestamp", "uid", "host", "host_role"}

_FAMILY_REQUIRED: dict[str, set[str]] = {
    "hmi_alarm": _COMMON_REQUIRED | {"user", "tag", "severity", "action", "message"},
    "hmi_operator": _COMMON_REQUIRED | {"user", "tag", "action", "old_value", "new_value", "message"},
    "ews_project": _COMMON_REQUIRED | {"user", "action", "project", "target_device", "target_role", "bytes", "message"},
    "historian_audit": _COMMON_REQUIRED | {"user", "tag", "action", "details"},
    "ot_auth": _COMMON_REQUIRED | {"user", "auth_method", "status", "source_ip", "message"},
    "ot_usb": _COMMON_REQUIRED | {"user", "action", "vendor_id", "product_id", "device_label", "message"},
}


def test_every_event_has_known_log_kind(events_clean_1d):
    assert events_clean_1d, "expected non-empty event stream"
    known = set(_FAMILY_REQUIRED.keys())
    seen = {e["_log"] for e in events_clean_1d}
    unknown = seen - known
    assert not unknown, f"unknown _log values: {unknown}"


def test_all_six_families_emit(net_m: OTNetwork):
    """A 3-day M-tier window must exercise every event family.

    Guards against a silent regression where someone zeros a rate
    table entry -- ``test_every_event_has_known_log_kind`` only
    detects *unknown* families, not missing ones.
    """
    events = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_3D, seed=0))
    seen = {e["_log"] for e in events}
    expected = set(_FAMILY_REQUIRED.keys())
    missing = expected - seen
    assert not missing, f"families never emitted across 3-day M-tier corpus: {missing}"


def test_schema_per_family(events_clean_1d):
    by_family: dict[str, list[dict]] = {}
    for e in events_clean_1d:
        by_family.setdefault(e["_log"], []).append(e)
    for family, required in _FAMILY_REQUIRED.items():
        recs = by_family.get(family, [])
        if not recs:
            continue  # rare-family case acceptable in 1d S window
        for r in recs:
            missing = required - set(r.keys())
            assert not missing, f"{family} missing fields {missing}: {r}"


def test_uid_uniqueness(events_clean_1d):
    uids = [e["uid"] for e in events_clean_1d]
    assert len(uids) == len(set(uids)), "uids must be unique across the stream"


def test_uid_shape(events_clean_1d):
    for e in events_clean_1d:
        assert e["uid"].startswith("H"), f"OT-host uid must start with 'H': {e['uid']}"
        assert len(e["uid"]) == 13, f"uid wrong length: {e['uid']}"


# --- host role discipline -------------------------------------------------


def test_no_embedded_roles_emit(events_clean_1d):
    """Controllers / safety controllers / RTUs are embedded RTOS -- no host logs."""
    embedded_roles = {"controller", "safety-controller", "rtu"}
    for e in events_clean_1d:
        assert e["host_role"] not in embedded_roles, (
            f"embedded-RTOS role {e['host_role']!r} must not emit host logs: {e}"
        )


def test_only_logging_roles_emit(events_clean_1d):
    allowed = {"hmi", "engineering-workstation", "historian", "ot-firewall"}
    for e in events_clean_1d:
        assert e["host_role"] in allowed, f"unexpected role: {e}"


def test_hmi_only_families_only_from_hmi(events_clean_1d):
    for e in events_clean_1d:
        if e["_log"] in ("hmi_alarm", "hmi_operator"):
            assert e["host_role"] == "hmi", f"{e['_log']} from non-hmi: {e}"
        if e["_log"] == "ews_project":
            assert e["host_role"] == "engineering-workstation"
        if e["_log"] == "historian_audit":
            assert e["host_role"] == "historian"


# --- window discipline ----------------------------------------------------


def test_no_events_outside_window(events_clean_1d):
    for e in events_clean_1d:
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
        assert WINDOW_START <= ts < WINDOW_END_1D, f"timestamp outside window: {ts}"


def test_events_sorted(events_clean_1d):
    for prev, curr in zip(events_clean_1d, events_clean_1d[1:]):
        assert (prev["timestamp"], prev["_log"], prev["uid"]) <= (
            curr["timestamp"], curr["_log"], curr["uid"]
        )


# --- determinism ----------------------------------------------------------


def test_determinism_same_seed(net_s: OTNetwork):
    a = list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    b = list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    assert a == b


def test_determinism_different_seed_differs(net_s: OTNetwork):
    a = list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    b = list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=42))
    assert a != b, "different seeds should produce different streams"


# --- operator shift model -------------------------------------------------


def _hours_with_family(events: list[dict], family: str) -> set[int]:
    return {int(e["timestamp"][11:13]) for e in events if e["_log"] == family}


def test_off_hours_zero_for_project_family(net_m: OTNetwork):
    """Project events MUST NOT appear outside weekday shift hours."""
    events = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_3D, seed=0))
    for e in events:
        if e["_log"] != "ews_project":
            continue
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
        is_weekday = ts.weekday() <= 4
        on_shift = is_weekday and 7 <= ts.hour < 19
        assert on_shift, f"ews_project outside shift: {e['timestamp']}"


def test_off_hours_zero_for_usb_family(net_m: OTNetwork):
    events = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_3D, seed=0))
    for e in events:
        if e["_log"] != "ot_usb":
            continue
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
        is_weekday = ts.weekday() <= 4
        on_shift = is_weekday and 7 <= ts.hour < 19
        assert on_shift, f"ot_usb outside shift: {e['timestamp']}"


def test_alarm_events_appear_in_off_hours(net_m: OTNetwork):
    """Alarms / historian audits continue (reduced) around the clock."""
    events = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_3D, seed=0))
    has_off_hours_alarm = False
    for e in events:
        if e["_log"] != "hmi_alarm":
            continue
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
        if ts.hour < 7 or ts.hour >= 19 or ts.weekday() > 4:
            has_off_hours_alarm = True
            break
    assert has_off_hours_alarm, "expected at least one alarm outside shift over 3 days"


# --- anomaly overlays -----------------------------------------------------


def test_off_hours_ews_login_anomaly(net_m: OTNetwork):
    # Saturday 03:00 -- definitively off-shift.
    anomaly_start = datetime(2026, 1, 10, 3, 0, 0)
    anomaly_end = datetime(2026, 1, 10, 4, 0, 0)
    window = AnomalyWindow(
        kind="off_hours_ews_login",
        start=anomaly_start,
        end=anomaly_end,
    )
    events = list(generate_for_network(
        net_m, WINDOW_START, datetime(2026, 1, 12, 0, 0, 0),
        seed=0, anomaly_windows=(window,),
    ))
    anomaly_logins = [
        e for e in events
        if e["_log"] == "ot_auth"
        and e["host_role"] == "engineering-workstation"
        and anomaly_start.isoformat(timespec="seconds") <= e["timestamp"][:19] < anomaly_end.isoformat(timespec="seconds")
    ]
    assert len(anomaly_logins) >= 1, "expected EWS login inside anomaly window"


def test_unexpected_project_download_anomaly(net_m: OTNetwork):
    # Pick an HMI from the M-tier topology.
    hmis = [d for d in net_m.devices if d.role == "hmi"]
    assert hmis, "test precondition: M tier should have HMIs"
    target_hmi = hmis[0]
    window = AnomalyWindow(
        kind="unexpected_project_download",
        start=datetime(2026, 1, 5, 10, 0, 0),
        end=datetime(2026, 1, 5, 10, 30, 0),
        target_device=target_hmi.name,
    )
    events = list(generate_for_network(
        net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=(window,),
    ))
    anomalous = [
        e for e in events
        if e["_log"] == "ews_project"
        and e["target_role"] == "hmi"
        and e["target_device"] == target_hmi.name
    ]
    assert anomalous, "expected project download with HMI target"
    # And in the baseline (no anomaly), targets should never be HMI.
    baseline = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_1D, seed=0))
    for e in baseline:
        if e["_log"] == "ews_project":
            assert e["target_role"] != "hmi", (
                f"baseline ews_project should never target HMI: {e}"
            )


def test_historian_tag_deletion_anomaly(net_m: OTNetwork):
    window = AnomalyWindow(
        kind="historian_tag_deletion",
        start=datetime(2026, 1, 5, 14, 0, 0),
        end=datetime(2026, 1, 5, 14, 5, 0),
    )
    events = list(generate_for_network(
        net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=(window,),
    ))
    deletions = [
        e for e in events
        if e["_log"] == "historian_audit" and e["action"] == "point_delete"
    ]
    assert deletions, "expected historian point_delete event"
    # Baseline never emits point_delete.
    baseline = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_1D, seed=0))
    for e in baseline:
        if e["_log"] == "historian_audit":
            assert e["action"] != "point_delete", (
                f"baseline historian_audit should not delete: {e}"
            )


def test_off_hours_login_on_shift_start_raises(net_m: OTNetwork):
    """A weekday-noon start defeats the anomaly's purpose; reject."""
    bad = AnomalyWindow(
        kind="off_hours_ews_login",
        start=datetime(2026, 1, 5, 12, 0, 0),  # Monday noon = on-shift
        end=datetime(2026, 1, 5, 13, 0, 0),
    )
    with pytest.raises(ValueError, match="on-shift"):
        list(generate_for_network(
            net_m, WINDOW_START, WINDOW_END_1D, seed=0, anomaly_windows=(bad,),
        ))


@pytest.mark.parametrize("kind,window_start,window_end", [
    # Window straddles left edge of corpus -- emit would land before start.
    ("historian_tag_deletion",
     datetime(2026, 1, 4, 23, 0, 0),
     datetime(2026, 1, 5, 1, 0, 0)),
    # Window straddles right edge of corpus -- emit would land after end.
    ("historian_tag_deletion",
     datetime(2026, 1, 5, 23, 0, 0),
     datetime(2026, 1, 6, 1, 0, 0)),
    # off_hours_ews_login follow-up at start+2min could spill past end --
    # right-edge case for the 2-minute follow-up. Saturday timestamps so
    # _on_shift is False before the cross-boundary check runs.
    ("off_hours_ews_login",
     datetime(2026, 1, 4, 23, 0, 0),
     datetime(2026, 1, 5, 0, 30, 0)),
    ("unexpected_project_download",
     datetime(2026, 1, 4, 23, 0, 0),
     datetime(2026, 1, 5, 0, 30, 0)),
])
def test_anomaly_partial_overlap_raises(net_m, kind, window_start, window_end):
    """Anomalies that straddle the corpus boundary would emit events
    outside [start, end). Reject loudly rather than corrupt the corpus."""
    bad = AnomalyWindow(kind=kind, start=window_start, end=window_end)
    with pytest.raises(ValueError, match="straddles corpus window"):
        list(generate_for_network(
            net_m, WINDOW_START, WINDOW_END_1D, seed=0, anomaly_windows=(bad,),
        ))


def test_bad_target_device_raises(net_m: OTNetwork):
    """Explicit target_device that names no eligible device is a caller bug."""
    bad = AnomalyWindow(
        kind="historian_tag_deletion",
        start=datetime(2026, 1, 5, 10, 0, 0),
        end=datetime(2026, 1, 5, 10, 5, 0),
        target_device="not-a-real-host",
    )
    with pytest.raises(ValueError, match="not an eligible"):
        list(generate_for_network(
            net_m, WINDOW_START, WINDOW_END_1D, seed=0, anomaly_windows=(bad,),
        ))


def test_unknown_anomaly_kind_raises(net_s: OTNetwork):
    bad = AnomalyWindow(
        kind="bogus_kind",  # type: ignore[arg-type]
        start=WINDOW_START,
        end=WINDOW_END_1D,
    )
    with pytest.raises(ValueError, match="unknown anomaly kind"):
        list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0, anomaly_windows=(bad,)))


def test_anomalies_outside_window_are_skipped(net_s: OTNetwork):
    # Anomaly entirely before the corpus window -- must not emit.
    earlier = AnomalyWindow(
        kind="historian_tag_deletion",
        start=WINDOW_START - timedelta(days=2),
        end=WINDOW_START - timedelta(days=1),
    )
    events = list(generate_for_network(
        net_s, WINDOW_START, WINDOW_END_1D, seed=0, anomaly_windows=(earlier,),
    ))
    deletions = [e for e in events if e.get("action") == "point_delete"]
    assert not deletions


# --- composer signature ---------------------------------------------------


def test_composer_signature(net_s: OTNetwork):
    """``generate(topology, activity_model, start, end, seed)`` must work
    with anything exposing ``.tier`` -- the composer hands us an IT
    ``Topology`` dataclass."""
    class FakeTopo:
        tier = "S"
        seed = 0
    events = list(ot_hosts.generate(FakeTopo(), None, WINDOW_START, WINDOW_END_1D, seed=0))
    assert events, "expected non-empty stream via composer signature"


def test_composer_signature_missing_tier_raises():
    class NoTier:
        pass
    with pytest.raises(TypeError, match="has no ``tier`` attribute"):
        list(ot_hosts.generate(NoTier(), None, WINDOW_START, WINDOW_END_1D, seed=0))


# --- volume sanity --------------------------------------------------------


def test_volume_within_reasonable_bounds(events_clean_1d):
    """S-tier 1 day should emit at least a few dozen and at most a few
    thousand events. Catches accidental rate-table breakage."""
    n = len(events_clean_1d)
    assert 30 <= n <= 5000, f"unexpected S-tier 1d volume: {n}"


def test_m_tier_emits_more_than_s_tier(net_s: OTNetwork, net_m: OTNetwork):
    s_events = list(generate_for_network(net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    m_events = list(generate_for_network(net_m, WINDOW_START, WINDOW_END_1D, seed=0))
    assert len(m_events) > len(s_events)
