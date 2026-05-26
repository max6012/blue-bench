"""Tests for the Modbus/TCP heavy-telemetry generator.

Acceptance bar for t-cagl: schema coverage, polling-rate, anomaly
visibility, determinism, no out-of-VLAN flows, no RTU<->RTU traffic,
and conn<->modbus uid pairing.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.ot_protocols.modbus import (
    AnomalyWindow,
    generate,
)
from blue_bench_generators.ot_protocols.topology import (
    OTNetwork,
    build_ot_network,
)


# --- shared fixtures -------------------------------------------------------


WINDOW_START = datetime(2026, 6, 1, 0, 0, 0)
WINDOW_END_1H = datetime(2026, 6, 1, 1, 0, 0)


@pytest.fixture(scope="module")
def net_s() -> OTNetwork:
    return build_ot_network(tier="S", seed=0)


@pytest.fixture(scope="module")
def events_clean_1h(net_s: OTNetwork) -> list[dict]:
    return list(generate(net_s, WINDOW_START, WINDOW_END_1H, seed=0))


# --- schema ---------------------------------------------------------------


_CONN_REQUIRED = {
    "_log", "ts", "uid",
    "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "orig_bytes", "resp_bytes",
    "conn_state", "history",
}
_MODBUS_REQUIRED = {
    "_log", "ts", "uid",
    "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "func", "unit_id", "address", "quantity", "exception",
}


def test_schema_conn_records_have_required_fields(events_clean_1h):
    conn_records = [e for e in events_clean_1h if e["_log"] == "conn"]
    assert conn_records, "expected at least one conn record"
    for r in conn_records:
        missing = _CONN_REQUIRED - set(r.keys())
        assert not missing, f"conn record missing fields {missing}: {r}"
        assert r["service"] == "modbus"
        assert r["proto"] == "tcp"
        assert r["id.resp_p"] == "502"


def test_schema_modbus_records_have_required_fields(events_clean_1h):
    modbus_records = [e for e in events_clean_1h if e["_log"] == "modbus"]
    assert modbus_records, "expected at least one modbus record"
    valid_funcs = {"3", "4", "6", "16", "8", "43"}
    for r in modbus_records:
        missing = _MODBUS_REQUIRED - set(r.keys())
        assert not missing, f"modbus record missing fields {missing}: {r}"
        assert r["func"] in valid_funcs, f"unexpected func {r['func']}"
        unit = int(r["unit_id"])
        assert 1 <= unit <= 247, f"unit_id {unit} out of range 1..247"


# --- window discipline ----------------------------------------------------


def test_no_events_outside_window(events_clean_1h):
    start_epoch = WINDOW_START.timestamp()
    end_epoch = WINDOW_END_1H.timestamp()
    for r in events_clean_1h:
        t = float(r["ts"])
        assert start_epoch <= t < end_epoch, (
            f"event ts={t} outside [{start_epoch}, {end_epoch}): {r}"
        )


def test_empty_window_emits_nothing(net_s):
    events = list(generate(net_s, WINDOW_START, WINDOW_START, seed=0))
    assert events == []


# --- polling rate ---------------------------------------------------------


def test_polling_rate_within_tolerance(net_s, events_clean_1h):
    modbus_links = [l for l in net_s.links if l.protocol == "modbus"]
    expected = len(modbus_links) * 3600
    actual = sum(1 for e in events_clean_1h if e["_log"] == "modbus")
    # +/- 5%. The deterministic walk should land squarely at the
    # expected count, but allow slack for off-by-one in partial-hour
    # bucketing on future tier additions.
    lo = int(expected * 0.95)
    hi = int(expected * 1.05)
    assert lo <= actual <= hi, (
        f"expected ~{expected} modbus records (+/- 5%), got {actual}"
    )


# --- direction / VLAN invariants ------------------------------------------


def test_direction_invariant_clean_baseline(net_s, events_clean_1h):
    """In a clean baseline every flow's orig_h is the canonical master."""
    devices_by_name = {d.name: d for d in net_s.devices}
    canonical_pairs: set[tuple[str, str]] = set()
    for link in net_s.links:
        if link.protocol != "modbus":
            continue
        m = devices_by_name[link.master]
        s = devices_by_name[link.slave]
        canonical_pairs.add((m.ip, s.ip))
    for r in events_clean_1h:
        pair = (r["id.orig_h"], r["id.resp_h"])
        assert pair in canonical_pairs, (
            f"flow {pair} is not a canonical modbus master->slave pair"
        )
        assert r["id.resp_p"] == "502"


def test_no_rtu_to_rtu_flows(net_s, events_clean_1h):
    by_ip = {d.ip: d for d in net_s.devices}
    for r in events_clean_1h:
        src = by_ip.get(r["id.orig_h"])
        dst = by_ip.get(r["id.resp_h"])
        assert src is not None and dst is not None, (
            f"event references an unknown IP: {r}"
        )
        assert not (src.role == "rtu" and dst.role == "rtu"), (
            f"RTU->RTU flow not allowed: {src.name}->{dst.name}"
        )


def test_no_out_of_vlan_flows(net_s, events_clean_1h):
    """Every modbus flow must cross ot-control <-> ot-field."""
    allowed = {("ot-control", "ot-field")}
    by_ip = {d.ip: d for d in net_s.devices}
    for r in events_clean_1h:
        src = by_ip[r["id.orig_h"]]
        dst = by_ip[r["id.resp_h"]]
        assert (src.vlan, dst.vlan) in allowed, (
            f"flow {src.name}({src.vlan}) -> {dst.name}({dst.vlan}) "
            "outside the ot-control <-> ot-field conduit"
        )


# --- determinism ----------------------------------------------------------


def test_determinism_same_seed_identical(net_s):
    a = list(generate(net_s, WINDOW_START, WINDOW_END_1H, seed=42))
    b = list(generate(net_s, WINDOW_START, WINDOW_END_1H, seed=42))
    assert a == b


def test_determinism_different_seed_same_volume(net_s):
    a = list(generate(net_s, WINDOW_START, WINDOW_END_1H, seed=0))
    b = list(generate(net_s, WINDOW_START, WINDOW_END_1H, seed=1))
    assert len(a) == len(b), "different seeds must preserve event volume"
    assert a != b, "different seeds must produce different events"


# --- conn / modbus pairing -------------------------------------------------


def test_one_conn_record_per_link_per_hour(net_s, events_clean_1h):
    n_links = sum(1 for l in net_s.links if l.protocol == "modbus")
    n_conns = sum(1 for e in events_clean_1h if e["_log"] == "conn")
    assert n_conns == n_links, (
        f"expected one conn record per modbus link per hour "
        f"({n_links} links, 1h window); got {n_conns} conn records"
    )


def test_every_modbus_uid_pairs_with_one_conn_uid(events_clean_1h):
    conn_uids = [e["uid"] for e in events_clean_1h if e["_log"] == "conn"]
    assert len(conn_uids) == len(set(conn_uids)), "conn uids must be unique"
    conn_uid_set = set(conn_uids)
    modbus_uids = {e["uid"] for e in events_clean_1h if e["_log"] == "modbus"}
    assert modbus_uids, "expected at least one modbus uid"
    missing = modbus_uids - conn_uid_set
    assert not missing, (
        f"modbus records reference uids with no matching conn record: {missing}"
    )


# --- anomaly visibility ---------------------------------------------------


def test_out_of_cycle_write_anomaly_shifts_write_fraction(net_s):
    """FC=6/16 fraction inside the anomaly window must exceed 5x baseline."""
    modbus_links = [l for l in net_s.links if l.protocol == "modbus"]
    assert modbus_links, "topology has no modbus links"
    target_slave = modbus_links[0].slave
    anomaly = AnomalyWindow(
        kind="out_of_cycle_write",
        start=datetime(2026, 6, 1, 0, 10, 0),
        end=datetime(2026, 6, 1, 0, 50, 0),
        target_device=target_slave,
    )
    events = list(generate(
        net_s, WINDOW_START, WINDOW_END_1H, seed=0,
        anomaly_windows=(anomaly,),
    ))
    # Baseline write fraction for the same target slave with NO anomaly.
    clean_events = list(generate(
        net_s, WINDOW_START, WINDOW_END_1H, seed=0,
    ))
    devices_by_name = {d.name: d for d in net_s.devices}
    target_ip = devices_by_name[target_slave].ip

    def write_fraction(records, in_window):
        if in_window:
            t_lo = anomaly.start.timestamp()
            t_hi = anomaly.end.timestamp()
        else:
            t_lo = float("-inf")
            t_hi = float("inf")
        scoped = [
            r for r in records
            if r["_log"] == "modbus"
            and r["id.resp_h"] == target_ip
            and t_lo <= float(r["ts"]) < t_hi
        ]
        if not scoped:
            return 0.0
        writes = sum(1 for r in scoped if r["func"] in ("6", "16"))
        return writes / len(scoped)

    baseline_frac = write_fraction(clean_events, in_window=True)
    anomaly_frac = write_fraction(events, in_window=True)
    assert anomaly_frac > 5.0 * baseline_frac, (
        f"anomaly write fraction {anomaly_frac:.3f} should exceed "
        f"5x baseline {baseline_frac:.3f}"
    )


def test_safety_register_read_anomaly_marks_records(net_s):
    """safety_register_read emits reads >=0xFA00 from a non-canonical source."""
    modbus_links = [l for l in net_s.links if l.protocol == "modbus"]
    target_slave = modbus_links[0].slave
    canonical_master = modbus_links[0].master
    devices_by_name = {d.name: d for d in net_s.devices}
    canonical_master_ip = devices_by_name[canonical_master].ip
    target_ip = devices_by_name[target_slave].ip

    anomaly = AnomalyWindow(
        kind="safety_register_read",
        start=datetime(2026, 6, 1, 0, 10, 0),
        end=datetime(2026, 6, 1, 0, 30, 0),
        target_device=target_slave,
    )
    events = list(generate(
        net_s, WINDOW_START, WINDOW_END_1H, seed=0,
        anomaly_windows=(anomaly,),
    ))
    safety_reads = [
        r for r in events
        if r["_log"] == "modbus"
        and r["id.resp_h"] == target_ip
        and int(r["address"]) >= 0xFA00
    ]
    assert safety_reads, "expected at least one safety-band read"
    for r in safety_reads:
        assert r["id.orig_h"] != canonical_master_ip, (
            "safety-band read should originate from a non-canonical source"
        )
        assert r["exception"] != "-", (
            "safety-band reads against a non-existent register should set exception"
        )


def test_safety_register_read_anomaly_preserves_vlan_rule(net_s):
    """The rogue source still sits on ot-control (cross-VLAN rule holds)."""
    modbus_links = [l for l in net_s.links if l.protocol == "modbus"]
    target_slave = modbus_links[0].slave
    anomaly = AnomalyWindow(
        kind="safety_register_read",
        start=datetime(2026, 6, 1, 0, 10, 0),
        end=datetime(2026, 6, 1, 0, 30, 0),
        target_device=target_slave,
    )
    events = list(generate(
        net_s, WINDOW_START, WINDOW_END_1H, seed=0,
        anomaly_windows=(anomaly,),
    ))
    by_ip = {d.ip: d for d in net_s.devices}
    allowed = {("ot-control", "ot-field")}
    for r in events:
        src = by_ip[r["id.orig_h"]]
        dst = by_ip[r["id.resp_h"]]
        assert (src.vlan, dst.vlan) in allowed, (
            f"safety-anomaly broke cross-VLAN rule: {src.name}->{dst.name}"
        )
