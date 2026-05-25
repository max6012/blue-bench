"""Behavioral / activity-model tests for `t-it-base` subtask t-ta82.

Cover rate composition (time-of-day, role buckets, admin overlay,
constant-overnight floor, anomaly windows), determinism, and the
hour-schedule helper.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import (
    EVENT_CLASSES,
    ActivityModel,
    AnomalyWindow,
    build_activity_model,
)
from blue_bench_generators.it_baseline.topology import Host, build_topology


# --- helpers ---------------------------------------------------------------


def _model(tier: str = "M", **kwargs) -> ActivityModel:
    topo = build_topology(tier)  # type: ignore[arg-type]
    return build_activity_model(topo, **kwargs)


def _first_host_with_role(model: ActivityModel, role: str) -> Host:
    for h in model.topology.hosts:
        if h.role == role:
            return h
    raise AssertionError(f"no host with role {role!r} in tier {model.topology.tier}")


# Reference timestamps. Pin to a known Monday so weekday() == 0.
MON_10AM = datetime(2026, 5, 11, 10, 0, 0)  # Monday
MON_1245 = datetime(2026, 5, 11, 12, 45, 0)  # Monday lunch dip
MON_1930 = datetime(2026, 5, 11, 19, 30, 0)  # Monday evening taper
MON_2300 = datetime(2026, 5, 11, 23, 0, 0)  # Monday after-hours admin
SAT_10AM = datetime(2026, 5, 16, 10, 0, 0)  # Saturday
SAT_0300 = datetime(2026, 5, 16, 3, 0, 0)  # Saturday early morning


# --- spec acceptance cases -------------------------------------------------


def test_workday_peak_higher_than_lunch_dip():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    assert m.rate(h, "process_creation", MON_10AM) > m.rate(
        h, "process_creation", MON_1245
    )


def test_workday_higher_than_weekend():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    assert m.rate(h, "process_creation", MON_10AM) > m.rate(
        h, "process_creation", SAT_10AM
    )


def test_admin_workstation_higher_than_workstation():
    m = _model()
    ws = _first_host_with_role(m, "workstation")
    adm = _first_host_with_role(m, "admin-workstation")
    for cls in ("logon_attempt", "process_creation"):
        assert m.rate(adm, cls, MON_10AM) > m.rate(ws, cls, MON_10AM), (
            f"admin-WS should exceed workstation on {cls} at peak"
        )


def test_dc_logon_volume_dominates_workstation():
    m = _model()
    ws = _first_host_with_role(m, "workstation")
    dc = _first_host_with_role(m, "domain-controller")
    # DC's logon volume should be a clear multiple of workstation's.
    assert m.rate(dc, "logon_attempt", MON_10AM) > 5 * m.rate(
        ws, "logon_attempt", MON_10AM
    )


def test_file_server_file_access_dominates_workstation():
    m = _model()
    ws = _first_host_with_role(m, "workstation")
    fs = _first_host_with_role(m, "file-server")
    assert m.rate(fs, "file_access", MON_10AM) > 10 * m.rate(
        ws, "file_access", MON_10AM
    )


def test_service_account_constant_overnight():
    """A service-host role at 03:00 should be within ~20% of its 14:00 rate."""
    m = _model()
    # Use DC (constant-overnight role). dhcp-dns-server also qualifies.
    dc = _first_host_with_role(m, "domain-controller")
    afternoon = m.rate(
        dc, "process_creation", datetime(2026, 5, 11, 14, 0, 0)
    )
    overnight = m.rate(
        dc, "process_creation", datetime(2026, 5, 12, 3, 0, 0)
    )
    ratio = overnight / afternoon
    assert 0.8 <= ratio <= 1.2, (
        f"DC overnight/afternoon ratio {ratio:.3f} not within +/-20%"
    )


def test_after_hours_admin_window_lifts_admin_rates():
    """Admin-WS at 23:00 > admin-WS at 19:30 (after the workday taper)."""
    m = _model()
    adm = _first_host_with_role(m, "admin-workstation")
    rate_2300 = m.rate(adm, "process_creation", MON_2300)
    rate_1930 = m.rate(adm, "process_creation", MON_1930)
    assert rate_2300 > rate_1930, (
        f"admin-WS 23:00 ({rate_2300:.1f}) should exceed 19:30 ({rate_1930:.1f})"
    )


def test_holiday_anomaly_window_suppresses_rates():
    topo = build_topology("M")
    holiday = AnomalyWindow(
        start=datetime(2026, 5, 11, 0, 0, 0),
        end=datetime(2026, 5, 12, 0, 0, 0),
        kind="holiday",
        multiplier=0.05,
    )
    m_normal = build_activity_model(topo)
    m_holiday = build_activity_model(topo, anomaly_windows=(holiday,))
    h = next(h for h in topo.hosts if h.role == "workstation")
    inside = m_holiday.rate(h, "process_creation", MON_10AM)
    outside = m_normal.rate(h, "process_creation", MON_10AM)
    assert inside < outside * 0.2, (
        f"holiday rate {inside:.2f} should be <<< normal rate {outside:.2f}"
    )


def test_deterministic_across_calls():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    a = m.rate(h, "logon_attempt", MON_10AM)
    b = m.rate(h, "logon_attempt", MON_10AM)
    c = m.rate(h, "logon_attempt", MON_10AM)
    assert a == b == c


def test_seed_does_not_affect_rates_for_v1():
    """v1 rates are purely deterministic from topology + time.

    The seed field is reserved for future stochastic overlays. Pin
    this property explicitly so a future contributor who wires RNG
    in cannot do so without breaking the test and confronting the
    determinism contract.
    """
    topo = build_topology("M", seed=0)
    m_seed_0 = build_activity_model(topo, seed=0)
    m_seed_99 = build_activity_model(topo, seed=99)
    h = next(h for h in topo.hosts if h.role == "workstation")
    for cls in EVENT_CLASSES:
        for ts in (MON_10AM, MON_2300, SAT_0300):
            assert m_seed_0.rate(h, cls, ts) == m_seed_99.rate(h, cls, ts), (
                f"seed must not affect v1 rate for {cls} at {ts}"
            )


def test_hour_schedule_window_length():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    start = datetime(2026, 5, 11, 0, 0, 0)
    end = start + timedelta(hours=24)
    sched = m.hour_schedule(h, "process_creation", start, end)
    assert len(sched) == 24
    # Ordered ascending.
    timestamps = [t for t, _ in sched]
    assert timestamps == sorted(timestamps)
    # Each step is exactly 1 hour from the previous.
    for i in range(1, len(timestamps)):
        assert timestamps[i] - timestamps[i - 1] == timedelta(hours=1)


# --- API & contract guards ------------------------------------------------


def test_unknown_event_class_raises():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    with pytest.raises(ValueError):
        m.rate(h, "not-a-real-class", MON_10AM)


def test_unknown_event_class_in_schedule_raises():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    start = datetime(2026, 5, 11, 0, 0, 0)
    end = start + timedelta(hours=2)
    with pytest.raises(ValueError):
        m.hour_schedule(h, "bogus", start, end)


def test_activity_model_is_frozen():
    m = _model()
    with pytest.raises(Exception):
        m.seed = 99  # type: ignore[misc]


def test_anomaly_windows_default_empty_tuple():
    m = _model()
    assert m.anomaly_windows == ()
    assert isinstance(m.anomaly_windows, tuple)


def test_hour_schedule_empty_window():
    m = _model()
    h = _first_host_with_role(m, "workstation")
    start = datetime(2026, 5, 11, 0, 0, 0)
    assert m.hour_schedule(h, "process_creation", start, start) == []
    assert m.hour_schedule(h, "process_creation", start, start - timedelta(hours=1)) == []


def test_every_role_resolves_for_every_event_class():
    """No (role, event_class) pair should error out on lookup."""
    m = _model("L")  # L tier exercises every role
    for h in m.topology.hosts:
        for cls in EVENT_CLASSES:
            r = m.rate(h, cls, MON_10AM)
            assert r >= 0.0, f"negative rate for {h.role} {cls}: {r}"


def test_overnight_is_low_for_workstations():
    """Workstations should drop hard overnight (no admin lift)."""
    m = _model()
    ws = _first_host_with_role(m, "workstation")
    peak = m.rate(ws, "process_creation", MON_10AM)
    overnight = m.rate(ws, "process_creation", datetime(2026, 5, 12, 3, 0, 0))
    assert overnight < 0.3 * peak, (
        f"workstation overnight {overnight:.2f} should be << peak {peak:.2f}"
    )


def test_outage_anomaly_zeros_rates():
    topo = build_topology("M")
    outage = AnomalyWindow(
        start=datetime(2026, 5, 11, 9, 0, 0),
        end=datetime(2026, 5, 11, 11, 0, 0),
        kind="outage",
        multiplier=0.0,
    )
    m = build_activity_model(topo, anomaly_windows=(outage,))
    h = next(h for h in topo.hosts if h.role == "workstation")
    assert m.rate(h, "process_creation", MON_10AM) == 0.0


def test_campaign_anomaly_elevates_rates():
    topo = build_topology("M")
    campaign = AnomalyWindow(
        start=datetime(2026, 5, 11, 9, 0, 0),
        end=datetime(2026, 5, 11, 11, 0, 0),
        kind="campaign",
        multiplier=1.5,
    )
    m_normal = build_activity_model(topo)
    m_campaign = build_activity_model(topo, anomaly_windows=(campaign,))
    h = next(h for h in topo.hosts if h.role == "workstation")
    assert (
        m_campaign.rate(h, "process_creation", MON_10AM)
        > m_normal.rate(h, "process_creation", MON_10AM)
    )


def test_proxy_http_dominates():
    """Proxy is the heaviest http_request host (forwards all WS HTTP)."""
    m = _model("L")
    proxy = _first_host_with_role(m, "proxy-server")
    ws = _first_host_with_role(m, "workstation")
    assert m.rate(proxy, "http_request", MON_10AM) > 10 * m.rate(
        ws, "http_request", MON_10AM
    )
