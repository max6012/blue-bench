"""Tests for the shared-service log generator (``t-7938``).

Covers DNS / DHCP / SMB / proxy server-side logs. The fixture is the M
tier topology, which carries all four service endpoint roles. A
secondary S-tier check confirms tier-conditional skipping of proxy and
SMB stays correct.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.services import generate
from blue_bench_generators.it_baseline.topology import build_topology


# --- fixtures --------------------------------------------------------------


WINDOW_START = datetime(2026, 5, 11, 0, 0, 0)  # Monday 00:00
WINDOW_END = datetime(2026, 5, 13, 0, 0, 0)  # Wednesday 00:00 -- 2 full days


def _m_setup():
    topo = build_topology("M")
    model = build_activity_model(topo)
    return topo, model


def _s_setup():
    topo = build_topology("S")
    model = build_activity_model(topo)
    return topo, model


def _all_events(topo, model, start=WINDOW_START, end=WINDOW_END, seed: int = 0):
    return list(generate(topo, model, start, end, seed=seed))


# --- 1. determinism -------------------------------------------------------


def test_deterministic_with_seed():
    topo, model = _m_setup()
    a = _all_events(topo, model, seed=42)
    b = _all_events(topo, model, seed=42)
    assert a == b
    # And a different seed produces a different stream.
    c = _all_events(topo, model, seed=7)
    assert a != c


# --- 2. window boundaries -------------------------------------------------


def test_no_events_outside_window():
    topo, model = _m_setup()
    events = _all_events(topo, model)
    for ev in events:
        ts = datetime.fromisoformat(ev["timestamp"])
        assert WINDOW_START <= ts < WINDOW_END, ev


# --- 3. DNS server vantage is the dhcp-dns-server role -------------------


def test_dns_server_host_is_dhcp_dns_role():
    topo, model = _m_setup()
    dns_role_fqdns = {h.fqdn for h in topo.hosts if h.role == "dhcp-dns-server"}
    assert dns_role_fqdns, "fixture must have at least one dhcp-dns-server"
    events = [ev for ev in _all_events(topo, model) if ev["_log"] == "dns_server"]
    assert events, "expected at least one dns_server event in M tier window"
    for ev in events:
        assert ev["server_host"] in dns_role_fqdns


# --- 4. DHCP RENEW volume ~ N_ws per 24h ---------------------------------


def test_dhcp_renew_volume_matches_workstation_count_per_day():
    topo, model = _m_setup()
    workstations = [
        h for h in topo.hosts if h.role in ("workstation", "admin-workstation")
    ]
    n_ws = len(workstations)
    days = (WINDOW_END - WINDOW_START).days
    events = [
        ev
        for ev in _all_events(topo, model)
        if ev["_log"] == "dhcp_server" and ev["event_type"] == "RENEW"
    ]
    # 1 RENEW per workstation per 24h window. Allow +/-1 per workstation
    # for boundary-of-window edge cases (none expected here because the
    # window is day-aligned, but keep some tolerance).
    expected = n_ws * days
    assert abs(len(events) - expected) <= n_ws, (len(events), expected, n_ws, days)


# --- 5. SMB conditional on file-server -----------------------------------


def test_smb_only_emits_when_file_servers_present():
    topo_m, model_m = _m_setup()
    smb_m = [ev for ev in _all_events(topo_m, model_m) if ev["_log"] == "smb_server"]
    assert smb_m, "M tier has file-servers -> SMB events expected"

    # Now exercise a topology with NO file-server. The S tier has 1
    # file-server; construct a synthetic topology by filtering hosts.
    # Easiest path: drop file-servers from S tier hosts and rebuild a
    # Topology dataclass instance.
    topo_s, _ = _s_setup()
    from dataclasses import replace

    no_fs_hosts = tuple(h for h in topo_s.hosts if h.role != "file-server")
    no_fs_services = tuple(
        s for s in topo_s.services if s.name != "smb"
    )
    no_fs_topo = replace(topo_s, hosts=no_fs_hosts, services=no_fs_services)
    no_fs_model = build_activity_model(no_fs_topo)
    smb_none = [
        ev
        for ev in generate(no_fs_topo, no_fs_model, WINDOW_START, WINDOW_END)
        if ev["_log"] == "smb_server"
    ]
    assert smb_none == []


# --- 6. Proxy conditional on proxy-server --------------------------------


def test_proxy_only_emits_when_proxy_server_present():
    # S tier has no proxy-server.
    topo_s, model_s = _s_setup()
    proxy_s = [
        ev for ev in _all_events(topo_s, model_s) if ev["_log"] == "proxy_access"
    ]
    assert proxy_s == [], "S tier has no proxy-server -> zero proxy_access events"

    topo_m, model_m = _m_setup()
    proxy_m = [
        ev for ev in _all_events(topo_m, model_m) if ev["_log"] == "proxy_access"
    ]
    assert proxy_m, "M tier has a proxy-server -> proxy_access events expected"


# --- 7. SMB session lifecycle ordering -----------------------------------


def test_smb_session_setup_then_tree_connect_then_disconnect_order():
    topo, model = _m_setup()
    events = [ev for ev in _all_events(topo, model) if ev["_log"] == "smb_server"]
    by_session: dict[int, list[dict]] = defaultdict(list)
    for ev in events:
        by_session[ev["session_id"]].append(ev)
    # Per-session_id, setup precedes every tree_connect precedes every
    # tree_disconnect (paired) precedes session_logoff.
    for sid, bucket in by_session.items():
        bucket_sorted = sorted(
            bucket, key=lambda ev: datetime.fromisoformat(ev["timestamp"])
        )
        # Ordered event-type sequence.
        types = [ev["event_type"] for ev in bucket_sorted]
        # First event must be session_setup.
        assert types[0] == "session_setup", (sid, types)
        # Last event (if logoff present) must be session_logoff.
        if "session_logoff" in types:
            assert types[-1] == "session_logoff", (sid, types)
        # Every tree_disconnect must come AFTER at least one tree_connect.
        seen_tc = 0
        for t in types:
            if t == "tree_connect":
                seen_tc += 1
            elif t == "tree_disconnect":
                assert seen_tc > 0, (sid, types)


# --- 8. DNS client_ips are real topology host IPs ------------------------


def test_dns_client_ips_match_topology_hosts():
    topo, model = _m_setup()
    host_ips = {h.ip for h in topo.hosts}
    events = [ev for ev in _all_events(topo, model) if ev["_log"] == "dns_server"]
    assert events
    for ev in events:
        assert ev["client_ip"] in host_ips, ev


# --- 9. DHCP MAC stability per client hostname ---------------------------


def test_dhcp_macs_unique_per_client_hostname():
    topo, model = _m_setup()
    events = [ev for ev in _all_events(topo, model) if ev["_log"] == "dhcp_server"]
    # hostname -> set(macs). All sets must be size 1.
    host_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_hosts: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        host_to_macs[ev["client_hostname"]].add(ev["client_mac"])
        mac_to_hosts[ev["client_mac"]].add(ev["client_hostname"])
    for host, macs in host_to_macs.items():
        assert len(macs) == 1, (host, macs)
    # And different hosts have different MACs (no collisions).
    for mac, hosts in mac_to_hosts.items():
        assert len(hosts) == 1, (mac, hosts)


# --- 10. Proxy URL pool is vendor-neutral --------------------------------


def test_proxy_urls_from_vendor_neutral_pool():
    topo, model = _m_setup()
    events = [ev for ev in _all_events(topo, model) if ev["_log"] == "proxy_access"]
    assert events
    for ev in events:
        url = ev["url"]
        # Every proxy URL must reference a host ending in .example.invalid.
        # Strip the scheme/port to extract the host.
        if url.startswith("http://"):
            after = url[len("http://"):]
            host = after.split("/", 1)[0]
        else:
            # CONNECT form: host:port
            host = url.rsplit(":", 1)[0]
        assert host.endswith(".example.invalid"), ev


# --- 11. Volume responds to time of day ----------------------------------


def test_volume_responds_to_time_of_day():
    """DNS volume should be much higher during the workday peak hour
    than during deep overnight, because workstation rates collapse
    overnight (server floor still applies to the small number of
    servers, but workstations dominate the total)."""
    topo, model = _m_setup()
    # Single-day window: Monday.
    day_start = datetime(2026, 5, 11, 0, 0, 0)
    day_end = day_start + timedelta(days=1)
    events = [
        ev
        for ev in generate(topo, model, day_start, day_end, seed=0)
        if ev["_log"] == "dns_server"
    ]
    hour_counts: dict[int, int] = defaultdict(int)
    for ev in events:
        hour_counts[datetime.fromisoformat(ev["timestamp"]).hour] += 1
    # Morning peak hour (10:00) vs deep overnight (02:00 -- weekday
    # early-morning multiplier 0.1).
    peak_count = hour_counts.get(10, 0)
    quiet_count = hour_counts.get(2, 0)
    assert peak_count > quiet_count, (peak_count, quiet_count, dict(hour_counts))
