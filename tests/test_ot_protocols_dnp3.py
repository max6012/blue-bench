"""Tests for the DNP3 protocol event generator.

Cover: schema per ``_log`` value, window discipline, per-link volume,
direction invariant, no out-of-VLAN flows, IIN field shape,
function-code distribution, determinism, anomaly visibility, and
conn-dnp3 uid pairing.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta

import pytest

from blue_bench_generators.ot_protocols.dnp3 import (
    AnomalyWindow,
    DNP3_PORT,
    generate,
)
from blue_bench_generators.ot_protocols.topology import (
    OT_VLAN_SPECS,
    build_ot_network,
)


T0 = datetime(2026, 5, 26, 9, 0, 0)
T1 = T0 + timedelta(hours=1)


# --- helpers --------------------------------------------------------------


def _by_log(events):
    out: dict[str, list[dict]] = {}
    for ev in events:
        out.setdefault(ev["_log"], []).append(ev)
    return out


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def _vlan_for_ip(ip: str) -> str | None:
    for name, _vid, cidr, _gw in OT_VLAN_SPECS:
        if _ip_in_subnet(ip, cidr):
            return name
    return None


def _device_by_ip(network, ip: str):
    for d in network.devices:
        if d.ip == ip:
            return d
    return None


# --- schema ---------------------------------------------------------------


def test_schema_conn_records():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=1))
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns, "expected at least one conn record"
    required = {
        "_log", "ts", "uid",
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "orig_bytes", "resp_bytes",
        "conn_state", "history",
    }
    for c in conns:
        assert required.issubset(c.keys())
        assert c["proto"] == "tcp"
        assert c["service"] == "dnp3"
        assert c["conn_state"] == "SF"
        assert c["history"] == "ShADadFf"
        # All numeric-looking fields are stringified.
        for k in ("id.orig_p", "id.resp_p", "orig_bytes", "resp_bytes"):
            assert isinstance(c[k], str)
        # ts is float-as-string with microsecond precision.
        assert re.match(r"^\d+\.\d{6}$", c["ts"])


def test_schema_dnp3_records():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=1))
    dnp3s = [e for e in events if e["_log"] == "dnp3"]
    assert dnp3s, "expected at least one dnp3 record"
    required = {
        "_log", "ts", "uid",
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "fc_request", "fc_reply", "iin",
    }
    for d in dnp3s:
        assert required.issubset(d.keys())
        assert d["fc_reply"] in ("RESPONSE", "UNSOLICITED_RESPONSE")
        assert re.match(r"^\d+\.\d{6}$", d["ts"])


# --- window discipline ----------------------------------------------------


def test_no_events_outside_window():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=0))
    start_e = T0.timestamp()
    end_e = T1.timestamp()
    for ev in events:
        t = float(ev["ts"])
        assert start_e <= t < end_e, f"ts {t} outside [{start_e}, {end_e})"


def test_empty_window_yields_nothing():
    net = build_ot_network("M")
    assert list(generate(net, T0, T0, seed=0)) == []
    assert list(generate(net, T1, T0, seed=0)) == []


# --- volume ---------------------------------------------------------------


@pytest.mark.parametrize("tier", ["S", "M"])
def test_dnp3_record_count_tracks_polling_hz(tier):
    net = build_ot_network(tier)
    events = list(generate(net, T0, T1, seed=3))
    dnp3s = [e for e in events if e["_log"] == "dnp3"]

    expected = 0.0
    for link in net.links:
        if link.protocol == "dnp3":
            expected += link.polling_hz * 3600.0
    assert expected > 0
    # Allow +/- 10%.
    lo, hi = expected * 0.9, expected * 1.1
    assert lo <= len(dnp3s) <= hi, (
        f"expected ~{expected} dnp3 records, got {len(dnp3s)} "
        f"(allowed [{lo}, {hi}])"
    )


def test_one_conn_per_link_per_hour():
    net = build_ot_network("S")
    events = list(generate(net, T0, T1, seed=0))
    conns = [e for e in events if e["_log"] == "conn"]
    dnp3_link_count = sum(1 for l in net.links if l.protocol == "dnp3")
    # Every DNP3 link has at least one transaction per hour at S tier
    # (lowest polling_hz is 0.05 -> 180 transactions/hour), so there is
    # exactly one conn record per link.
    assert len(conns) == dnp3_link_count


# --- direction & VLAN invariants -----------------------------------------


def test_direction_invariant_hmi_historian():
    net = build_ot_network("M")
    devices = {d.name: d for d in net.devices}
    masters = {l.master for l in net.links if l.protocol == "dnp3"}
    hmi_or_hist_ips = {
        devices[m].ip
        for m in masters
        if devices[m].role in ("hmi", "historian")
    }
    events = list(generate(net, T0, T1, seed=0))
    saw_supervisory = False
    for ev in events:
        # Only check flows where the orig is an HMI or historian.
        if ev["id.orig_h"] not in hmi_or_hist_ips:
            continue
        saw_supervisory = True
        assert ev["id.resp_p"] == str(DNP3_PORT)
        # Resp must be a controller / safety-controller (ot-control).
        resp_device = _device_by_ip(net, ev["id.resp_h"])
        assert resp_device is not None
        assert resp_device.role in ("controller", "safety-controller")
    assert saw_supervisory, "expected at least one supervisory-side flow"


def test_no_out_of_vlan_flows():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=0))
    # Every flow must connect supervisory <-> control OR control <-> field.
    allowed = {
        frozenset({"ot-supervisory", "ot-control"}),
        frozenset({"ot-control", "ot-field"}),
    }
    for ev in events:
        ov = _vlan_for_ip(ev["id.orig_h"])
        rv = _vlan_for_ip(ev["id.resp_h"])
        assert ov is not None and rv is not None
        assert frozenset({ov, rv}) in allowed, (
            f"flow {ev['id.orig_h']} ({ov}) -> {ev['id.resp_h']} ({rv}) "
            f"crosses a forbidden VLAN boundary"
        )


# --- IIN shape ------------------------------------------------------------


def test_iin_field_shape():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=0))
    pat = re.compile(r"^0x[0-9a-f]{4}$")
    dnp3s = [e for e in events if e["_log"] == "dnp3"]
    assert dnp3s
    for d in dnp3s:
        assert pat.match(d["iin"]), f"bad iin: {d['iin']!r}"


# --- function code distribution ------------------------------------------


def test_read_dominates_in_clean_window():
    net = build_ot_network("M")
    events = list(generate(net, T0, T1, seed=0))
    dnp3s = [e for e in events if e["_log"] == "dnp3"]
    assert dnp3s
    total = len(dnp3s)
    reads = sum(1 for d in dnp3s if d["fc_request"] == "READ")
    frac = reads / total
    assert frac > 0.7, f"READ fraction {frac:.3f} should dominate clean window"


# --- determinism ---------------------------------------------------------


def test_same_seed_same_stream():
    net = build_ot_network("S")
    a = list(generate(net, T0, T1, seed=42))
    b = list(generate(net, T0, T1, seed=42))
    assert a == b


def test_different_seed_changes_content_not_per_link_volume():
    net = build_ot_network("S")
    a = list(generate(net, T0, T1, seed=1))
    b = list(generate(net, T0, T1, seed=2))
    assert a != b
    a_dnp3 = [e for e in a if e["_log"] == "dnp3"]
    b_dnp3 = [e for e in b if e["_log"] == "dnp3"]
    # Per-link volume is determined solely by polling_hz; seed only
    # changes per-record content.
    assert len(a_dnp3) == len(b_dnp3)


# --- conn-dnp3 uid pairing -----------------------------------------------


def test_every_dnp3_uid_pairs_with_conn_uid():
    net = build_ot_network("S")
    events = list(generate(net, T0, T1, seed=0))
    conn_uids = {e["uid"] for e in events if e["_log"] == "conn"}
    dnp3_uids = {e["uid"] for e in events if e["_log"] == "dnp3"}
    assert dnp3_uids, "expected at least one dnp3 record"
    # Every dnp3 transaction's uid was issued by a conn record.
    assert dnp3_uids <= conn_uids


# --- anomaly visibility --------------------------------------------------


def test_cold_restart_anomaly_emits_restart_records():
    net = build_ot_network("M")
    # Pick a controller to target.
    controller = next(d for d in net.devices if d.role == "controller")
    window = AnomalyWindow(
        kind="cold_restart",
        start=T0,
        end=T1,
        target_device=controller.name,
    )
    events = list(
        generate(net, T0, T1, seed=0, anomaly_windows=(window,))
    )
    restarts = [
        e for e in events
        if e["_log"] == "dnp3"
        and e["fc_request"] in ("COLD_RESTART", "WARM_RESTART")
    ]
    assert restarts, "expected at least one COLD_RESTART/WARM_RESTART record"
    # Records must target the chosen controller.
    for r in restarts:
        assert r["id.resp_h"] == controller.ip


def test_iin_device_restart_anomaly_sets_bit():
    net = build_ot_network("M")
    controller = next(d for d in net.devices if d.role == "controller")
    window = AnomalyWindow(
        kind="iin_device_restart",
        start=T0,
        end=T1,
        target_device=controller.name,
    )
    events = list(
        generate(net, T0, T1, seed=0, anomaly_windows=(window,))
    )
    # Any dnp3 record whose responder is the controller and whose
    # request is READ must carry the device-restart bit set.
    restart_reads = [
        e for e in events
        if e["_log"] == "dnp3"
        and e["id.resp_h"] == controller.ip
        and e["fc_request"] == "READ"
    ]
    assert restart_reads
    for r in restart_reads:
        # 0x0080 = device restart bit.
        assert int(r["iin"], 16) & 0x0080, f"missing restart bit in {r['iin']}"


def test_unsolicited_response_anomaly_from_non_enrolled_pair():
    net = build_ot_network("M")
    # Build the canonical enrolment map.
    enrolment: dict[str, set[str]] = {}
    for l in net.links:
        if l.protocol == "dnp3":
            enrolment.setdefault(l.slave, set()).add(l.master)

    window = AnomalyWindow(
        kind="unsolicited_response",
        start=T0,
        end=T1,
        target_device=None,
    )
    events = list(
        generate(net, T0, T1, seed=0, anomaly_windows=(window,))
    )
    unsols = [
        e for e in events
        if e["_log"] == "dnp3"
        and e["fc_request"] == "UNSOLICITED_MESSAGE"
    ]
    assert unsols, "expected at least one UNSOLICITED_MESSAGE record"
    for u in unsols:
        assert u["fc_reply"] == "UNSOLICITED_RESPONSE"
        # Real DNP3 unsolicited responses originate at the OUTSTATION
        # and target the master, so id.orig_h must be the outstation IP
        # and id.resp_h the master IP. The (master, outstation) pair
        # must also be non-enrolled.
        outstation_dev = _device_by_ip(net, u["id.orig_h"])
        master_dev = _device_by_ip(net, u["id.resp_h"])
        assert outstation_dev is not None and master_dev is not None
        assert outstation_dev.role in ("controller", "safety-controller"), (
            f"unsolicited id.orig_h={u['id.orig_h']} role={outstation_dev.role}, "
            f"expected outstation"
        )
        assert master_dev.role in ("hmi", "historian", "engineering-workstation"), (
            f"unsolicited id.resp_h={u['id.resp_h']} role={master_dev.role}, "
            f"expected supervisory-VLAN master"
        )
        assert master_dev.name not in enrolment.get(outstation_dev.name, set())
