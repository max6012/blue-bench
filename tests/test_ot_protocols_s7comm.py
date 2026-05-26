"""Tests for the S7Comm telemetry generator.

Covers schema, function-code semantics, baseline distribution discipline,
business-hours weighting, maintenance-window behaviour, direction +
vendor + VLAN containment, determinism, and download-block anomaly
visibility.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

import pytest

from blue_bench_generators.ot_protocols.s7comm import (
    AnomalyWindow,
    generate,
)
from blue_bench_generators.ot_protocols.topology import (
    PROTOCOL_PORTS,
    build_ot_network,
)


# --- fixtures --------------------------------------------------------------


def _network(tier="M", seed=0):
    return build_ot_network(tier=tier, seed=seed)


def _first_tuesday(year, month):
    d = datetime(year, month, 1)
    return d + timedelta(days=(1 - d.weekday()) % 7)


# Pick a 7-day window starting on a Monday that contains the first
# Tuesday of the month. 2026-05-04 is a Monday, first Tue is 2026-05-05.
WEEK_START = datetime(2026, 5, 4)  # Monday
WEEK_END = WEEK_START + timedelta(days=7)


# --- schema ----------------------------------------------------------------


def test_conn_schema_fields_present():
    net = _network()
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns, "no conn records emitted"
    required = {
        "_log", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
        "id.resp_p", "proto", "service", "orig_bytes", "resp_bytes",
        "conn_state", "history",
    }
    for c in conns:
        assert required.issubset(c.keys()), f"missing keys in conn record: {c}"
        assert c["proto"] == "tcp"
        assert c["service"] == "s7comm"
        assert c["conn_state"] == "SF"
        assert c["history"] == "ShADadFf"
        assert int(c["id.resp_p"]) == PROTOCOL_PORTS["s7comm"] == 102


def test_s7comm_schema_fields_present():
    net = _network()
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    s7s = [e for e in events if e["_log"] == "s7comm"]
    assert s7s, "no s7comm records emitted"
    required = {
        "_log", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
        "id.resp_p", "rosctr", "function", "pdu_ref", "item_count",
    }
    for s in s7s:
        assert required.issubset(s.keys()), f"missing keys in s7comm record: {s}"
        assert s["rosctr"] in ("job", "ack_data", "userdata")
        assert isinstance(s["pdu_ref"], int)
        assert isinstance(s["item_count"], int)


def test_ts_string_format():
    net = _network()
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    assert events
    for e in events:
        # Six-decimal epoch seconds; floats parse cleanly.
        assert "." in e["ts"]
        assert float(e["ts"]) > 0


# --- window discipline -----------------------------------------------------


def test_all_events_lie_inside_requested_window():
    net = _network()
    start = WEEK_START + timedelta(hours=10)
    end = WEEK_START + timedelta(hours=14)
    events = list(generate(net, start, end))
    assert events
    s, e = start.timestamp(), end.timestamp()
    for ev in events:
        ts = float(ev["ts"])
        assert s <= ts < e, f"event at {ts} outside [{s}, {e})"


def test_end_before_start_emits_nothing():
    net = _network()
    events = list(generate(net, WEEK_END, WEEK_START))
    assert events == []


# --- business-hours weighting ---------------------------------------------


def test_business_hours_dominate_record_volume():
    """A clean 7-day window: >80% of records inside Mon-Fri 09:00-17:00."""
    net = _network()
    events = list(generate(net, WEEK_START, WEEK_END))
    assert events
    # Both the generator and this test convert naive datetimes via
    # ``.timestamp()`` (Python interprets naive as local) and recover
    # via the inverse arithmetic below. Using explicit
    # ``(dt - WEEK_START).total_seconds()`` arithmetic keeps the test
    # TZ-independent: we never compare wall-clock semantics across the
    # boundary, only relative offsets from a known anchor.
    week_start_epoch = WEEK_START.timestamp()
    in_bh = 0
    total = 0
    for ev in events:
        total += 1
        offset_s = float(ev["ts"]) - week_start_epoch
        day_of_week = int(offset_s // 86400) % 7
        sec_of_day = offset_s - (offset_s // 86400) * 86400
        hour_of_day = int(sec_of_day // 3600)
        if day_of_week < 5 and 9 <= hour_of_day < 17:
            in_bh += 1
    ratio = in_bh / total
    assert ratio > 0.80, f"business-hours ratio {ratio:.3f} not > 0.80"


# --- function-code distribution -------------------------------------------


def test_read_var_dominates_in_clean_baseline():
    """Clean window: read_var dominates (>0.9 of s7comm PDUs)."""
    net = _network()
    # Use a single weekday so business-hours session traffic dominates,
    # but exclude the first-Tuesday maintenance window to keep the
    # signal clean.
    start = datetime(2026, 5, 4, 9, 0, 0)  # Monday 09:00
    end = datetime(2026, 5, 4, 17, 0, 0)  # Monday 17:00
    events = list(generate(net, start, end))
    s7s = [e for e in events if e["_log"] == "s7comm"]
    assert s7s
    funcs = Counter(e["function"] for e in s7s)
    total = sum(funcs.values())
    assert funcs["read_var"] / total > 0.9
    # write_var ~1% (allow a wide band -- it's a Bernoulli draw).
    assert 0.001 < funcs.get("write_var", 0) / total < 0.05
    # No PG-only PDU types outside maintenance on a Monday.
    assert funcs.get("download_block", 0) == 0
    assert funcs.get("upload_block", 0) == 0
    assert funcs.get("plc_stop", 0) == 0
    assert funcs.get("plc_control", 0) == 0


# --- maintenance-window discipline ----------------------------------------


def test_read_szl_appears_during_maintenance_window():
    """First-Tuesday 14:00-16:00 produces read_szl records."""
    net = _network()
    # First Tuesday of May 2026 is 2026-05-05.
    tue = _first_tuesday(2026, 5)
    mstart = tue.replace(hour=14)
    mend = tue.replace(hour=16)
    events = list(generate(net, mstart, mend))
    s7s = [e for e in events if e["_log"] == "s7comm"]
    funcs = Counter(e["function"] for e in s7s)
    assert funcs.get("read_szl", 0) > 0, (
        f"no read_szl records in maintenance window: {funcs}"
    )


def test_read_szl_is_rare_outside_maintenance_window():
    """A weekday morning that doesn't overlap maintenance should not
    produce read_szl records in the baseline."""
    net = _network()
    # Monday 09:00-12:00 -- no first-Tuesday overlap.
    start = datetime(2026, 5, 4, 9, 0, 0)
    end = datetime(2026, 5, 4, 12, 0, 0)
    events = list(generate(net, start, end))
    s7s = [e for e in events if e["_log"] == "s7comm"]
    funcs = Counter(e["function"] for e in s7s)
    assert funcs.get("read_szl", 0) == 0


# --- direction + vendor + VLAN containment --------------------------------


def test_baseline_flows_are_ews_to_vendor_a_controller():
    net = _network()
    by_name = {d.name: d for d in net.devices}
    by_ip = {d.ip: d for d in net.devices}
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    assert events
    for ev in events:
        src = by_ip.get(ev["id.orig_h"])
        dst = by_ip.get(ev["id.resp_h"])
        assert src is not None and dst is not None
        assert src.role == "engineering-workstation"
        assert dst.role in ("controller", "safety-controller")
        assert dst.vendor == "vendor-a"
        assert int(ev["id.resp_p"]) == PROTOCOL_PORTS["s7comm"]
    _ = by_name


def test_flows_stay_inside_ot_supervisory_and_ot_control_vlans():
    net = _network()
    by_ip = {d.ip: d for d in net.devices}
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    for ev in events:
        src = by_ip[ev["id.orig_h"]]
        dst = by_ip[ev["id.resp_h"]]
        assert src.vlan == "ot-supervisory"
        assert dst.vlan == "ot-control"


# --- determinism ----------------------------------------------------------


def test_same_inputs_yield_identical_output():
    net = _network()
    a = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1), seed=7))
    b = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1), seed=7))
    assert a == b


def test_different_seed_changes_content_but_keeps_similar_volume():
    net = _network()
    a = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1), seed=1))
    b = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1), seed=2))
    assert a != b
    # Volumes within 10% of each other.
    ratio = len(a) / len(b)
    assert 0.9 <= ratio <= 1.1, f"volume ratio {ratio:.3f} not in [0.9, 1.1]"


# --- conn / s7comm uid pairing --------------------------------------------


def test_every_s7comm_pdu_shares_uid_with_a_conn():
    net = _network()
    events = list(generate(net, WEEK_START, WEEK_START + timedelta(days=1)))
    conn_uids = {e["uid"] for e in events if e["_log"] == "conn"}
    s7_uids = {e["uid"] for e in events if e["_log"] == "s7comm"}
    # Every s7comm PDU's uid must appear in the conn-uid set (the
    # session's conn record).
    missing = s7_uids - conn_uids
    assert not missing, f"s7comm PDUs with no parent conn uid: {missing}"


# --- anomaly visibility ----------------------------------------------------


def test_download_block_off_hours_anomaly_visible():
    """download_block_off_hours emits a userdata/download_block PDU
    inside the anomaly window AND outside the maintenance window."""
    net = _network()
    # Saturday afternoon -- off-hours, not maintenance.
    anomaly = AnomalyWindow(
        kind="download_block_off_hours",
        start=datetime(2026, 5, 9, 14, 0, 0),  # Saturday
        end=datetime(2026, 5, 9, 14, 30, 0),
    )
    events = list(
        generate(
            net,
            datetime(2026, 5, 9, 0, 0, 0),
            datetime(2026, 5, 10, 0, 0, 0),
            anomaly_windows=(anomaly,),
        )
    )
    hits = [
        e
        for e in events
        if e["_log"] == "s7comm"
        and e["rosctr"] == "userdata"
        and e["function"] == "download_block"
    ]
    assert hits, "no download_block userdata PDU emitted"
    # All hits inside the anomaly window. Saturday is not the first
    # Tuesday of the month, so this also exercises the "outside
    # maintenance" property -- but the test asserts that explicitly via
    # offset arithmetic rather than wall-clock attributes so it holds
    # in any CI timezone.
    a_start = anomaly.start.timestamp()
    a_end = anomaly.end.timestamp()
    for h in hits:
        assert a_start <= float(h["ts"]) < a_end


def test_download_block_distinguishable_from_baseline_read_var():
    """The anomaly PDU shape (userdata + download_block) does not occur
    in a baseline weekday."""
    net = _network()
    # Baseline Monday window, no anomalies.
    events = list(
        generate(
            net,
            datetime(2026, 5, 4, 9, 0, 0),
            datetime(2026, 5, 4, 17, 0, 0),
        )
    )
    bad = [
        e
        for e in events
        if e["_log"] == "s7comm"
        and e["rosctr"] == "userdata"
        and e["function"] == "download_block"
    ]
    assert bad == []
