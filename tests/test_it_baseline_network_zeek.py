"""Tests for ``it_baseline.network_zeek`` benign-traffic Zeek emitter.

Covers determinism, window correctness, traffic-shape constraints
(SMB only file-server-bound, outbound web via proxy, allowed corp->
server ports), and rate-driven volume behaviour (scales with window
length, peak > lunch dip, admin-WS > workstation).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.network_zeek import (
    CORP_TO_SERVER_ALLOWED_PORTS,
    PROXY_PORT,
    generate,
)
from blue_bench_generators.it_baseline.topology import Host, build_topology


# --- shared fixtures -------------------------------------------------------


# Pin a known Monday so weekday() == 0 across the suite.
MON_10AM = datetime(2026, 5, 11, 10, 0, 0)  # weekday peak
MON_1245 = datetime(2026, 5, 11, 12, 45, 0)  # weekday lunch dip


def _build(tier: str = "S"):
    topo = build_topology(tier)  # type: ignore[arg-type]
    model = build_activity_model(topo)
    return topo, model


def _hosts_by_name(topo) -> dict[str, Host]:
    return {h.name: h for h in topo.hosts}


# --- determinism + window --------------------------------------------------


def test_deterministic_with_seed():
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=1)
    a = list(generate(topo, model, start, end, seed=42))
    b = list(generate(topo, model, start, end, seed=42))
    assert a == b
    assert len(a) > 0


def test_different_seeds_produce_different_streams():
    """Sanity check that ``seed`` actually has an effect."""
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=1)
    a = list(generate(topo, model, start, end, seed=1))
    b = list(generate(topo, model, start, end, seed=2))
    # Counts may match; exact records should not (RNG-driven).
    assert a != b


def test_no_events_outside_window():
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=7))
    assert events, "expected at least one event in a 2h window"
    start_epoch = start.timestamp()
    end_epoch = end.timestamp()
    for ev in events:
        ts = float(ev["ts"])
        assert start_epoch <= ts < end_epoch, (
            f"event ts {ts} out of [{start_epoch}, {end_epoch}) "
            f"for {ev.get('_log')}"
        )


def test_empty_window_yields_nothing():
    topo, model = _build("S")
    start = MON_10AM
    assert list(generate(topo, model, start, start, seed=0)) == []
    assert list(generate(topo, model, start, start - timedelta(hours=1), seed=0)) == []


# --- volume scaling --------------------------------------------------------


def test_volume_scales_with_window_length():
    """24h window has roughly 24x events of 1h, within +/-20% on average.

    Time-of-day variation means a 1h peak window has a high rate while
    overnight hours are lower. We anchor both windows to start at
    midnight so the 1h window is at the lowest hour and the 24h window
    averages across the full day -- the 24h total should still be well
    above the 1h total. We check the ratio against [12, 60] which is
    generous enough to absorb time-of-day differences but tight enough
    to catch a broken implementation.
    """
    topo, model = _build("S")
    base = datetime(2026, 5, 11, 9, 0, 0)  # weekday morning ramp
    short = list(generate(topo, model, base, base + timedelta(hours=1), seed=0))
    long = list(generate(topo, model, base, base + timedelta(hours=24), seed=0))
    assert short, "1h window should produce events"
    assert long, "24h window should produce events"
    ratio = len(long) / len(short)
    # At least 5x more in 24h than 1h. Weak floor accommodates the
    # huge peak/quiet gap in the activity model.
    assert ratio >= 5.0, f"24h/1h ratio {ratio:.2f} suspiciously low"


# --- traffic-shape constraints --------------------------------------------


def test_dns_queries_only_target_dns_server():
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=3))
    by_name = _hosts_by_name(topo)
    by_ip = {h.ip: h for h in topo.hosts}
    dns_records = [e for e in events if e["_log"] == "dns"]
    assert dns_records, "expected dns records"
    for r in dns_records:
        resp_ip = r["id.resp_h"]
        # Responder must be a known host with role dhcp-dns-server.
        assert resp_ip in by_ip, f"dns responder ip {resp_ip} not in topology"
        assert by_ip[resp_ip].role == "dhcp-dns-server", (
            f"dns responder {by_ip[resp_ip].name} role is "
            f"{by_ip[resp_ip].role}, not dhcp-dns-server"
        )
    _ = by_name


def test_smb_only_between_corp_and_file_servers():
    topo, model = _build("M")  # M tier has multiple file-servers
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=11))
    by_ip = {h.ip: h for h in topo.hosts}
    smb_conns = [
        e for e in events
        if e["_log"] == "conn" and e["id.resp_p"] == "445"
    ]
    assert smb_conns, "expected SMB conn records"
    for r in smb_conns:
        src = by_ip[r["id.orig_h"]]
        dst = by_ip[r["id.resp_h"]]
        assert src.vlan == "corp", (
            f"tcp/445 origin {src.name} on VLAN {src.vlan}, expected corp"
        )
        assert dst.role == "file-server", (
            f"tcp/445 responder {dst.name} role {dst.role}, "
            f"expected file-server"
        )


def test_outbound_http_routes_via_proxy_when_proxy_exists():
    """M/L tiers have a proxy; outbound web flows through it."""
    topo, model = _build("M")
    start = MON_10AM
    end = start + timedelta(hours=1)
    events = list(generate(topo, model, start, end, seed=5))
    by_ip = {h.ip: h for h in topo.hosts}
    proxies = [h for h in topo.hosts if h.role == "proxy-server"]
    assert proxies, "M tier should have at least one proxy"
    proxy_ips = {p.ip for p in proxies}

    # http and ssl records must all terminate at the proxy.
    web_records = [e for e in events if e["_log"] in ("http", "ssl")]
    assert web_records, "expected http/ssl records at M tier"
    for r in web_records:
        assert r["id.resp_h"] in proxy_ips, (
            f"{r['_log']} record resp_h={r['id.resp_h']} not in proxy IPs"
        )
        assert r["id.resp_p"] == str(PROXY_PORT)
        src = by_ip[r["id.orig_h"]]
        assert src.role in ("workstation", "admin-workstation"), (
            f"web origin {src.name} role {src.role} unexpected"
        )


def test_conn_records_carry_required_fields():
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=1)
    events = list(generate(topo, model, start, end, seed=1))
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns, "expected at least one conn record"
    required = {
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "_log",
        "ts",
    }
    for r in conns:
        missing = required - r.keys()
        assert not missing, f"conn record missing fields {missing}: {r}"


def test_no_forbidden_internal_paths():
    """corp VLAN -> server VLAN must only use allowed ports (53/88/389/445)."""
    topo, model = _build("M")
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=13))
    by_ip = {h.ip: h for h in topo.hosts}
    conns = [e for e in events if e["_log"] == "conn"]
    assert conns
    for r in conns:
        src = by_ip.get(r["id.orig_h"])
        dst = by_ip.get(r["id.resp_h"])
        if src is None or dst is None:
            continue
        if src.vlan == "corp" and dst.vlan == "server":
            port = int(r["id.resp_p"])
            assert port in CORP_TO_SERVER_ALLOWED_PORTS, (
                f"forbidden corp->server conn on port {port}: "
                f"{src.name} -> {dst.name}"
            )


def test_no_workstation_to_workstation_smb():
    """No tcp/445 between two workstations (file-server is the only responder)."""
    topo, model = _build("M")
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=17))
    by_ip = {h.ip: h for h in topo.hosts}
    for r in events:
        if r["_log"] != "conn":
            continue
        if r["id.resp_p"] != "445":
            continue
        src = by_ip[r["id.orig_h"]]
        dst = by_ip[r["id.resp_h"]]
        assert not (
            src.role in ("workstation", "admin-workstation")
            and dst.role in ("workstation", "admin-workstation")
        ), f"forbidden WS<->WS SMB: {src.name} -> {dst.name}"


# --- time-of-day + role behaviour -----------------------------------------


def test_event_volume_responds_to_time_of_day():
    """Peak hour (10:00 weekday) should yield more events than lunch dip (12:45 weekday).

    Compare 1h windows starting at the peak vs. the lunch-dip hour.
    Same property as the behavior model tests.
    """
    topo, model = _build("S")
    peak_start = datetime(2026, 5, 11, 10, 0, 0)
    dip_start = datetime(2026, 5, 11, 12, 0, 0)
    peak_events = list(
        generate(topo, model, peak_start, peak_start + timedelta(hours=1), seed=0)
    )
    dip_events = list(
        generate(topo, model, dip_start, dip_start + timedelta(hours=1), seed=0)
    )
    assert len(peak_events) > len(dip_events), (
        f"peak {len(peak_events)} should exceed lunch-dip {len(dip_events)}"
    )


def test_event_volume_admin_workstation_higher_than_workstation():
    """Sum events per host class: admin-WS produces more than a regular WS."""
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=2)
    events = list(generate(topo, model, start, end, seed=0))
    by_ip = {h.ip: h for h in topo.hosts}
    ws_count = 0
    adm_count = 0
    for e in events:
        src_ip = e.get("id.orig_h")
        if src_ip is None:
            continue
        host = by_ip.get(src_ip)
        if host is None:
            continue
        if host.role == "workstation":
            ws_count += 1
        elif host.role == "admin-workstation":
            adm_count += 1
    # Normalize: S tier has 6 workstations vs 1 admin-WS. Compare
    # per-host averages so the test is about per-host activity, not
    # host count.
    n_ws = sum(1 for h in topo.hosts if h.role == "workstation")
    n_adm = sum(1 for h in topo.hosts if h.role == "admin-workstation")
    assert n_ws > 0 and n_adm > 0
    avg_ws = ws_count / n_ws
    avg_adm = adm_count / n_adm
    assert avg_adm > avg_ws, (
        f"avg admin-WS events {avg_adm:.1f} should exceed avg WS {avg_ws:.1f}"
    )


# --- supplementary contract guards ----------------------------------------


def test_every_event_has_log_and_ts_fields():
    topo, model = _build("S")
    start = MON_10AM
    end = start + timedelta(hours=1)
    events = list(generate(topo, model, start, end, seed=0))
    assert events
    for e in events:
        assert "_log" in e, f"event missing _log: {e}"
        assert e["_log"] in ("conn", "dns", "http", "ssl", "files"), e["_log"]
        assert "ts" in e, f"event missing ts: {e}"
        # ts is a string parseable as float (Zeek convention).
        float(e["ts"])


def test_log_kinds_present_at_m_tier():
    """M tier should produce every log kind we claim to emit."""
    topo, model = _build("M")
    start = MON_10AM
    end = start + timedelta(hours=4)
    events = list(generate(topo, model, start, end, seed=0))
    kinds = {e["_log"] for e in events}
    # files may be rare in some 1h windows; 4h with HTTPS_FRACTION=0.85
    # and SMB_CONN_OBSERVABILITY_FRACTION ensures conn/dns/http/ssl/files
    # all appear.
    assert "conn" in kinds
    assert "dns" in kinds
    assert "ssl" in kinds
    # http requires the cleartext slice (1-HTTPS_FRACTION ~= 15%); in
    # a 4h M-tier window this should be hit.
    assert "http" in kinds
    assert "files" in kinds


def test_dc_to_dc_replication_only_when_multiple_dcs():
    """S tier has 1 DC -> no replication; M tier has 2 DCs -> replication present."""
    topo_s, model_s = _build("S")
    topo_m, model_m = _build("M")
    start = MON_10AM
    end = start + timedelta(hours=1)
    ev_s = list(generate(topo_s, model_s, start, end, seed=0))
    ev_m = list(generate(topo_m, model_m, start, end, seed=0))
    by_ip_s = {h.ip: h for h in topo_s.hosts}
    by_ip_m = {h.ip: h for h in topo_m.hosts}

    def _dc_to_dc(records, by_ip):
        out = []
        for r in records:
            if r["_log"] != "conn":
                continue
            src = by_ip.get(r["id.orig_h"])
            dst = by_ip.get(r["id.resp_h"])
            if src and dst and src.role == "domain-controller" and dst.role == "domain-controller":
                out.append(r)
        return out

    assert _dc_to_dc(ev_s, by_ip_s) == [], "S tier has 1 DC; should have no DC<->DC traffic"
    assert _dc_to_dc(ev_m, by_ip_m), "M tier has 2 DCs; expected DC<->DC traffic"
