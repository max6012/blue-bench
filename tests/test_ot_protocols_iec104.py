"""Tests for the IEC-60870-5-104 protocol traffic generator.

Acceptance bar (t-7hw7): per-link IEC-104 traffic is emitted with the
expected Zeek-shaped conn + iec104 records, COT / APDU distributions
look like a clean baseline, anomaly overlays are visible in the
stream, and the generator is deterministic.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

import pytest

from blue_bench_generators.ot_protocols.iec104 import (
    AnomalyWindow,
    generate,
)
from blue_bench_generators.ot_protocols.topology import (
    build_ot_network,
)


# --- fixtures -------------------------------------------------------------


@pytest.fixture
def network():
    return build_ot_network(tier="M", seed=1)


@pytest.fixture
def one_hour_window():
    # Tuesday 10:00-11:00 -- business hours, away from weekend edge cases.
    start = datetime(2025, 6, 3, 10, 0, 0)
    end = start + timedelta(hours=1)
    return start, end


# --- helpers --------------------------------------------------------------


def _iec_links(network):
    return [l for l in network.links if l.protocol == "iec104"]


def _hmi_ips(network):
    return {d.ip for d in network.devices if d.role == "hmi"}


def _controller_ips(network):
    return {
        d.ip
        for d in network.devices
        if d.role in ("controller", "safety-controller")
    }


def _device_by_name(network, name):
    for d in network.devices:
        if d.name == name:
            return d
    return None


# --- schema ---------------------------------------------------------------


def test_conn_record_schema(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=42))
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns, "expected at least one conn record"
    required = {
        "_log",
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "history",
    }
    for c in conns:
        missing = required - set(c.keys())
        assert not missing, f"missing fields {missing} in conn record {c}"
        assert c["proto"] == "tcp"
        assert c["service"] == "iec104"
        assert c["id.resp_p"] == "2404"
        assert c["conn_state"] == "SF"
        assert c["history"] == "ShADadFf"


def test_iec104_record_schema(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=42))
    apdus = [e for e in events if e["_log"] == "iec104"]
    assert apdus, "expected iec104 APDU records"
    required = {
        "_log",
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "apdu_type",
        "asdu_type",
        "cot",
        "asdu_addr",
        "ioa",
        "ioa_count",
    }
    for r in apdus:
        missing = required - set(r.keys())
        assert not missing, f"missing fields {missing} in iec104 record {r}"
        assert r["apdu_type"] in ("I", "S", "U")
        # 5-tuple endpoints are always present.
        assert r["id.resp_p"] == "2404" or r["id.orig_p"] == "2404"


# --- window discipline ----------------------------------------------------


def test_events_inside_window(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=11))
    start_e = start.timestamp()
    end_e = end.timestamp()
    for ev in events:
        ts = float(ev["ts"])
        assert start_e <= ts < end_e, f"event {ev} outside window"


def test_empty_window_emits_nothing(network):
    t0 = datetime(2025, 6, 3, 10, 0, 0)
    events = list(generate(network, t0, t0, seed=0))
    assert events == []


# --- volume sanity --------------------------------------------------------


def test_cyclic_volume_within_tolerance(network, one_hour_window):
    """Clean 1-hour baseline cyclic count ~ links * polling_hz * 3600 ± 15%."""
    start, end = one_hour_window
    links = _iec_links(network)
    poll_hz = links[0].polling_hz
    expected = len(links) * poll_hz * 3600  # 8 * 0.2 * 3600 = 5760
    events = list(generate(network, start, end, seed=99))
    # Count cyclic M_ME with cot in {1, 3} (periodic + spontaneous as part
    # of the cyclic stream, excluding interrogation-driven cot=20).
    cyclic = [
        e
        for e in events
        if e["_log"] == "iec104"
        and e.get("asdu_type") == "M_ME_NA_1"
        and e.get("cot") in ("1", "3")
    ]
    low = expected * 0.85
    high = expected * 1.15
    assert low <= len(cyclic) <= high, (
        f"cyclic count {len(cyclic)} outside [{low}, {high}] (expected ~{expected})"
    )


# --- direction + VLAN containment ----------------------------------------


def test_conn_direction_master_to_controller(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=3))
    hmi_ips = _hmi_ips(network)
    ctrl_ips = _controller_ips(network)
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns
    for c in conns:
        assert c["id.orig_h"] in hmi_ips, f"orig {c['id.orig_h']} not an HMI"
        assert c["id.resp_h"] in ctrl_ips, f"resp {c['id.resp_h']} not a controller"
        assert c["id.resp_p"] == "2404"


def test_no_out_of_vlan_flows(network, one_hour_window):
    """Every IEC-104 5-tuple stays inside ot-supervisory <-> ot-control."""
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=5))
    hmi_ips = _hmi_ips(network)
    ctrl_ips = _controller_ips(network)
    supervisory_ips = {
        d.ip for d in network.devices if d.vlan == "ot-supervisory"
    }
    control_ips = {d.ip for d in network.devices if d.vlan == "ot-control"}
    for ev in events:
        o = ev["id.orig_h"]
        r = ev["id.resp_h"]
        # Each side of the 5-tuple must be a supervisory or control host
        # (HMI / EWS / historian / firewall on supervisory; controller /
        # safety-controller on control). Allow any role within the VLAN
        # because the ack direction has orig = controller.
        assert o in supervisory_ips or o in control_ips, (
            f"orig {o} not in OT supervisory/control VLAN"
        )
        assert r in supervisory_ips or r in control_ips, (
            f"resp {r} not in OT supervisory/control VLAN"
        )
        # The pair must straddle the boundary -- one supervisory, one
        # control. Same-VLAN flows would mean we're emitting outside the
        # iec104 link semantics.
        crosses = (
            (o in supervisory_ips and r in control_ips)
            or (o in control_ips and r in supervisory_ips)
        )
        assert crosses, f"flow {o}->{r} does not cross supervisory<->control"


# --- COT + APDU distribution ---------------------------------------------


def test_cot_distribution_periodic_dominates(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=8))
    i_records = [e for e in events if e["_log"] == "iec104" and e["apdu_type"] == "I"]
    cot_counts = Counter(e.get("cot") for e in i_records)
    total = sum(cot_counts.values())
    assert total > 0
    cot1_share = cot_counts.get("1", 0) / total
    assert cot1_share > 0.6, f"cot=1 share {cot1_share:.3f} should dominate (>0.6)"
    # cot=6 (activation) and cot=7 (activation-confirmation) appear in
    # pairs from interrogation + operator commands.
    assert cot_counts.get("6", 0) > 0
    assert cot_counts.get("7", 0) > 0
    # cot=3 (spontaneous) appears in the cyclic stream.
    assert cot_counts.get("3", 0) > 0
    # Some cot=20 (interrogated-by-station) data reports.
    assert cot_counts.get("20", 0) > 0


def test_apdu_type_distribution(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=4))
    apdu_counts = Counter(
        e["apdu_type"] for e in events if e["_log"] == "iec104"
    )
    total = sum(apdu_counts.values())
    assert total > 0
    assert apdu_counts["I"] / total > 0.5, "I-APDUs should dominate"
    assert apdu_counts["S"] > 0, "S-APDU keep-alives expected"
    # U-APDUs only at link-start: one STARTDT_act + one STARTDT_con per
    # link in the first emitted hour.
    iec_links = _iec_links(network)
    assert apdu_counts["U"] == 2 * len(iec_links), (
        f"expected exactly 2 U-APDUs per link (act+con); got {apdu_counts['U']}"
    )


# --- conn + iec104 pairing -----------------------------------------------


def test_one_conn_per_link_per_hour(network, one_hour_window):
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=6))
    conns = [e for e in events if e["_log"] == "conn"]
    iec_links = _iec_links(network)
    assert len(conns) == len(iec_links), (
        f"expected one conn per link per hour ({len(iec_links)}); got {len(conns)}"
    )
    # Each conn UID is unique.
    uids = [c["uid"] for c in conns]
    assert len(set(uids)) == len(uids)


def test_iec104_uid_well_formed(network, one_hour_window):
    """Every iec104 record carries a Zeek-style UID with the conn prefix."""
    start, end = one_hour_window
    events = list(generate(network, start, end, seed=2))
    for e in events:
        assert e["uid"].startswith("C")
        assert len(e["uid"]) >= 13


# --- determinism ---------------------------------------------------------


def test_deterministic_same_inputs(network, one_hour_window):
    start, end = one_hour_window
    a = list(generate(network, start, end, seed=123))
    b = list(generate(network, start, end, seed=123))
    assert a == b


def test_different_seed_changes_content_not_volume(network, one_hour_window):
    start, end = one_hour_window
    a = list(generate(network, start, end, seed=1))
    b = list(generate(network, start, end, seed=2))
    # Same total count of records -- cyclic + interrogation + op commands
    # + keep-alives are all rate-driven and seed-invariant in count.
    assert len(a) == len(b)
    # But individual records differ (UIDs / source ports / IOA pick / etc).
    a_uids = sorted(e["uid"] for e in a)
    b_uids = sorted(e["uid"] for e in b)
    assert a_uids != b_uids, "different seeds should produce different UIDs"


# --- anomaly visibility ---------------------------------------------------


def test_stopdt_off_hours_emits_u_apdu_outside_business_hours(network):
    # Saturday 02:00 -- off hours.
    start = datetime(2025, 6, 7, 2, 0, 0)
    end = start + timedelta(hours=1)
    windows = (
        AnomalyWindow(
            kind="stopdt_off_hours",
            start=start,
            end=end,
            target_device=None,
        ),
    )
    events = list(generate(network, start, end, seed=10, anomaly_windows=windows))
    # The clean baseline emits exactly 2 U-APDUs per link (link startup).
    # Anomaly adds at least one additional U-APDU per matching link.
    iec_links = _iec_links(network)
    u_count = sum(
        1 for e in events if e["_log"] == "iec104" and e["apdu_type"] == "U"
    )
    # >= startup-pair-count + 1 anomaly STOPDT per link.
    assert u_count >= 2 * len(iec_links) + len(iec_links)


def test_unknown_station_interrogation_emits_from_non_hmi_source(network):
    start = datetime(2025, 6, 3, 10, 0, 0)
    end = start + timedelta(hours=1)
    # Target one specific controller.
    link0 = _iec_links(network)[0]
    target_name = link0.slave
    windows = (
        AnomalyWindow(
            kind="unknown_station_interrogation",
            start=start,
            end=end,
            target_device=target_name,
        ),
    )
    events = list(generate(network, start, end, seed=14, anomaly_windows=windows))
    hmi_ips = _hmi_ips(network)
    target_ip = _device_by_name(network, target_name).ip
    unknown_cics = [
        e
        for e in events
        if e["_log"] == "iec104"
        and e.get("asdu_type") == "C_IC_NA_1"
        and e.get("cot") == "6"
        and e["id.resp_h"] == target_ip
        and e["id.orig_h"] not in hmi_ips
    ]
    assert unknown_cics, "expected at least one C_IC_NA_1 from a non-HMI source"
    # Source IP should be a supervisory-VLAN address that no device holds.
    used_ips = {d.ip for d in network.devices}
    for ev in unknown_cics:
        assert ev["id.orig_h"].startswith("10.40.0."), (
            f"unknown-station src {ev['id.orig_h']} should be on supervisory VLAN"
        )
        assert ev["id.orig_h"] not in used_ips, (
            "unknown-station src IP should not be a real device"
        )


def test_implausible_ioa_write_emits_high_ioa_setpoint(network):
    start = datetime(2025, 6, 3, 10, 0, 0)
    end = start + timedelta(hours=1)
    link0 = _iec_links(network)[0]
    windows = (
        AnomalyWindow(
            kind="implausible_ioa_write",
            start=start,
            end=end,
            target_device=link0.slave,
        ),
    )
    events = list(generate(network, start, end, seed=21, anomaly_windows=windows))
    high_writes = [
        e
        for e in events
        if e["_log"] == "iec104"
        and e.get("asdu_type") == "C_SE_NA_1"
        and e.get("ioa", "").isdigit()
        and int(e["ioa"]) > 1_000_000
    ]
    assert high_writes, "expected at least one C_SE_NA_1 with implausibly high IOA"
