"""Tests for ``blue_bench_generators.it_baseline.identity`` (task t-v9km).

Covers DC-only emission, deterministic ordering, time-of-day response,
TGT-before-TGS per-user invariants, SPN -> topology.services anchoring,
status-code domain, IP integrity, and the LDAP business-hours gate.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import (
    build_activity_model,
)
from blue_bench_generators.it_baseline.identity import generate
from blue_bench_generators.it_baseline.topology import (
    ADForest,
    Host,
    Service,
    Topology,
    User,
    VLAN,
    build_topology,
)


# --- fixtures -------------------------------------------------------------


# Pin to a known Monday so weekday() == 0 and business-hours rules apply.
MON_09_00 = datetime(2026, 5, 11, 9, 0, 0)
MON_10_00 = datetime(2026, 5, 11, 10, 0, 0)
MON_03_00 = datetime(2026, 5, 11, 3, 0, 0)
MON_NEXT_DAY = datetime(2026, 5, 12, 9, 0, 0)


def _small_topology() -> Topology:
    """Single-DC, single-workstation toy topology -- minimal but valid.

    Built by hand (rather than via ``build_topology``) so the tests don't
    re-validate the larger builder. Keeps host/user counts low and lets
    us assert exactly which IPs and SPNs should appear.
    """
    forest = ADForest(
        name="corp.example.invalid",
        root_domain="corp.example.invalid",
        ous=("Workstations", "Servers"),
    )
    vlans = (
        VLAN(name="corp", vlan_id=10, subnet="10.10.0.0/24", gateway_ip="10.10.0.1"),
        VLAN(name="server", vlan_id=20, subnet="10.20.0.0/24", gateway_ip="10.20.0.1"),
    )
    hosts = (
        Host(
            name="wkst-01",
            fqdn="wkst-01.corp.example.invalid",
            os="windows",
            role="workstation",
            vlan="corp",
            ip="10.10.0.10",
            ou="Workstations",
        ),
        Host(
            name="wkst-adm-01",
            fqdn="wkst-adm-01.corp.example.invalid",
            os="windows",
            role="admin-workstation",
            vlan="corp",
            ip="10.10.0.11",
            ou="Workstations",
        ),
        Host(
            name="srv-files-01",
            fqdn="srv-files-01.corp.example.invalid",
            os="windows",
            role="file-server",
            vlan="server",
            ip="10.20.0.10",
            ou="Servers",
        ),
        Host(
            name="dc-01",
            fqdn="dc-01.corp.example.invalid",
            os="windows",
            role="domain-controller",
            vlan="server",
            ip="10.20.0.11",
            ou="Servers",
        ),
    )
    users = (
        User(
            username="emma.chen",
            display_name="Emma Chen",
            role="user",
            primary_host="wkst-01",
            department="engineering",
        ),
        User(
            username="david.patel.adm",
            display_name="David Patel (Admin)",
            role="admin",
            primary_host="wkst-adm-01",
            department="operations",
        ),
        User(
            username="svc-smb-01",
            display_name="Service Account: smb (1)",
            role="service",
            primary_host="srv-files-01",
            department="operations",
        ),
    )
    services = (
        Service(name="smb", endpoint_hosts=("srv-files-01",), port=445),
        Service(name="ad-dc", endpoint_hosts=("dc-01",), port=389),
    )
    return Topology(
        tier="S",
        seed=0,
        forest=forest,
        vlans=vlans,
        hosts=hosts,
        users=users,
        services=services,
    )


def _topology_without_dc() -> Topology:
    """Topology with the DC stripped -- generate() must skip silently."""
    topo = _small_topology()
    new_hosts = tuple(h for h in topo.hosts if h.role != "domain-controller")
    return replace(topo, hosts=new_hosts)


# --- tests ----------------------------------------------------------------


def test_only_dc_hosts_emit_events():
    topo = _small_topology()
    model = build_activity_model(topo)
    dc_fqdns = {h.fqdn for h in topo.hosts if h.role == "domain-controller"}
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=2), seed=1)
    )
    assert events, "expected at least one identity event"
    for ev in events:
        assert ev["host"] in dc_fqdns, (
            f"non-DC host emitted identity event: {ev['host']}"
        )


def test_skips_silently_when_no_dc():
    topo = _topology_without_dc()
    model = build_activity_model(topo)
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=4), seed=1)
    )
    assert events == []


def test_deterministic_with_seed():
    topo = _small_topology()
    model = build_activity_model(topo)
    a = list(generate(topo, model, MON_09_00, MON_NEXT_DAY, seed=7))
    b = list(generate(topo, model, MON_09_00, MON_NEXT_DAY, seed=7))
    assert a == b
    c = list(generate(topo, model, MON_09_00, MON_NEXT_DAY, seed=8))
    # Different seed produces a different sequence (overwhelmingly likely
    # but not strictly guaranteed by determinism alone; the toy topology
    # is large enough that collisions don't occur for seeds 7 vs 8).
    assert c != a


def test_no_events_outside_window():
    topo = _small_topology()
    model = build_activity_model(topo)
    start = MON_09_00
    end = MON_09_00 + timedelta(hours=3)
    events = list(generate(topo, model, start, end, seed=1))
    for ev in events:
        ts = datetime.fromisoformat(ev["timestamp"])
        assert start <= ts < end, f"event at {ts} outside [{start}, {end})"


def test_4768_volume_matches_logon_attempt_rate_aggregated_across_hosts():
    """The DC's 4768 volume must equal the SUM of per-workstation logon
    rates -- not the DC's own logon_attempt rate.
    """
    # Use the real M-tier topology so we have multiple workstations.
    topo = build_topology("M")
    model = build_activity_model(topo)
    start = MON_09_00
    end = MON_09_00 + timedelta(hours=4)

    events = list(generate(topo, model, start, end, seed=11))
    tgt_count = sum(1 for e in events if e["event_id"] == 4768)

    # Expected = sum over (user, hour) of rate(user.primary_host,
    # "logon_attempt", hour). Iterate the same way the generator does.
    expected = 0.0
    cursor = start
    while cursor < end:
        for user in topo.users:
            primary = next(
                (h for h in topo.hosts if h.name == user.primary_host), None
            )
            if primary is None:
                continue
            expected += model.rate(primary, "logon_attempt", cursor)
        cursor = cursor + timedelta(hours=1)

    # ±25% tolerance for Bernoulli rounding noise on fractional rates.
    assert expected > 0
    ratio = tgt_count / expected
    assert 0.75 <= ratio <= 1.25, (
        f"TGT count {tgt_count} should be ~ aggregated logon-attempt rate "
        f"{expected:.0f} (ratio={ratio:.2f})"
    )

    # Sanity: this should be much larger than the DC's own logon_attempt
    # rate alone, demonstrating we're not using the DC rate as the source.
    dc = next(h for h in topo.hosts if h.role == "domain-controller")
    dc_only = sum(
        model.rate(dc, "logon_attempt", MON_09_00 + timedelta(hours=i))
        for i in range(4)
    )
    assert tgt_count > dc_only, (
        "TGT count should exceed DC's own logon_attempt rate (we should be "
        "summing per-user, not querying the DC)"
    )


def test_4771_to_4768_ratio_matches_behavior():
    topo = build_topology("M")
    model = build_activity_model(topo)
    start = MON_09_00
    end = MON_09_00 + timedelta(hours=8)
    events = list(generate(topo, model, start, end, seed=3))
    tgt = sum(1 for e in events if e["event_id"] == 4768)
    fail = sum(1 for e in events if e["event_id"] == 4771)
    assert tgt > 0

    # Aggregate the configured ratio across the same window.
    expected_attempt = 0.0
    expected_failure = 0.0
    cursor = start
    while cursor < end:
        for user in topo.users:
            primary = next(
                (h for h in topo.hosts if h.name == user.primary_host), None
            )
            if primary is None:
                continue
            expected_attempt += model.rate(primary, "logon_attempt", cursor)
            expected_failure += model.rate(primary, "logon_failure", cursor)
        cursor = cursor + timedelta(hours=1)

    expected_ratio = expected_failure / expected_attempt
    observed_ratio = fail / tgt
    # ±50% tolerance per spec.
    assert expected_ratio * 0.5 <= observed_ratio <= expected_ratio * 1.5, (
        f"observed 4771/4768 ratio {observed_ratio:.4f} should be within ±50% "
        f"of configured {expected_ratio:.4f}"
    )


def test_tgt_before_tgs_for_same_user():
    topo = build_topology("M")
    model = build_activity_model(topo)
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=6), seed=5)
    )
    first_tgt: dict[str, datetime] = {}
    first_tgs: dict[str, datetime] = {}
    for ev in events:
        ts = datetime.fromisoformat(ev["timestamp"])
        u = ev.get("TargetUserName")
        if not u:
            continue
        if ev["event_id"] == 4768 and u not in first_tgt:
            first_tgt[u] = ts
        if ev["event_id"] == 4769 and u not in first_tgs:
            first_tgs[u] = ts
    # For each user with both event types, TGT first must precede or
    # equal TGS first.
    checked = 0
    for u, tgs_ts in first_tgs.items():
        if u in first_tgt:
            assert first_tgt[u] <= tgs_ts, (
                f"user {u}: first TGT {first_tgt[u]} after first TGS {tgs_ts}"
            )
            checked += 1
    assert checked > 0, "no users had both TGT and TGS events to check"


def test_tgs_service_names_match_topology_services():
    topo = build_topology("M")
    model = build_activity_model(topo)
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=4), seed=2)
    )
    # Build the set of legal SPNs from topology.services. SPN class map
    # is in identity._SPN_CLASS; reflect the same mapping here so the
    # test stays decoupled from the production map (and catches drift).
    spn_class = {
        "smb": "cifs",
        "ad-dc": "ldap",
        "dns": "DNS",
        "proxy": "HTTP",
        "siem": "HOST",
        "dhcp": "HOST",
    }
    host_fqdn = {h.name: h.fqdn for h in topo.hosts}
    legal_spns: set[str] = set()
    for svc in topo.services:
        cls = spn_class.get(svc.name)
        if cls is None:
            continue
        for ep in svc.endpoint_hosts:
            fqdn = host_fqdn[ep]
            legal_spns.add(f"{cls}/{fqdn}")
    tgs_events = [e for e in events if e["event_id"] == 4769]
    assert tgs_events, "expected at least one 4769 event"
    for ev in tgs_events:
        assert ev["ServiceName"] in legal_spns, (
            f"TGS ServiceName {ev['ServiceName']!r} not in legal SPNs "
            f"(must reference a real topology.services endpoint)"
        )


def test_status_codes_in_known_set():
    topo = build_topology("M")
    model = build_activity_model(topo)
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=12), seed=9)
    )
    kerberos_ok = {"0x0", "0x6", "0x12", "0x18", "0x25"}
    ntlm_ok = {
        "0x0", "0xC000006A", "0xC0000064", "0xC0000234", "0xC0000071"
    }
    for ev in events:
        if ev["event_id"] in (4768, 4769, 4771):
            assert ev["Status"] in kerberos_ok, (
                f"unexpected Kerberos status {ev['Status']!r} on event "
                f"{ev['event_id']}"
            )
        elif ev["event_id"] == 4776:
            assert ev["Status"] in ntlm_ok, (
                f"unexpected NTLM status {ev['Status']!r}"
            )


def test_ip_addresses_match_topology_hosts():
    topo = build_topology("M")
    model = build_activity_model(topo)
    real_ips = {h.ip for h in topo.hosts}
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=3), seed=4)
    )
    assert events
    for ev in events:
        ip = ev.get("IpAddress") or ev.get("ClientIp")
        assert ip is not None, f"event lacks IP field: {ev}"
        assert ip in real_ips, (
            f"event IP {ip} not in topology host IPs"
        )


def test_volume_responds_to_time_of_day():
    topo = build_topology("M")
    model = build_activity_model(topo)
    # Two 1-hour windows on the same weekday: 10:00 (peak) vs 02:00
    # (overnight). Workstation rate at peak >> overnight.
    peak_window = (datetime(2026, 5, 11, 10, 0), datetime(2026, 5, 11, 11, 0))
    night_window = (datetime(2026, 5, 12, 2, 0), datetime(2026, 5, 12, 3, 0))
    peak = list(generate(topo, model, *peak_window, seed=12))
    night = list(generate(topo, model, *night_window, seed=12))
    peak_tgt = sum(1 for e in peak if e["event_id"] == 4768)
    night_tgt = sum(1 for e in night if e["event_id"] == 4768)
    assert peak_tgt > night_tgt, (
        f"peak-hour TGT count {peak_tgt} should exceed overnight {night_tgt}"
    )


def test_ldap_queries_emit_on_business_hours_only_for_workstation_users():
    """Regular (workstation) users must not generate LDAP queries
    outside Mon-Fri 08:00-18:00. Admin / service users may.
    """
    topo = build_topology("M")
    model = build_activity_model(topo)
    # 03:00 on a weekday -- outside business hours, but admins/services
    # can still issue LDAP queries.
    start = datetime(2026, 5, 12, 3, 0)
    end = datetime(2026, 5, 12, 4, 0)
    events = list(generate(topo, model, start, end, seed=15))
    ldap_events = [e for e in events if e["event_id"] == 1644]
    # Categorise by user.
    user_role = {u.username: u.role for u in topo.users}
    for ev in ldap_events:
        u = ev["BindUserName"]
        role = user_role.get(u)
        assert role in ("admin", "service"), (
            f"workstation/regular user {u} (role={role}) issued LDAP query "
            f"outside business hours"
        )


def test_every_event_has_required_envelope_fields():
    topo = _small_topology()
    model = build_activity_model(topo)
    events = list(
        generate(topo, model, MON_09_00, MON_09_00 + timedelta(hours=2), seed=1)
    )
    assert events
    valid_channels = {"Security", "Directory Service"}
    for ev in events:
        assert ev.get("_log") == "winevtx"
        assert isinstance(ev.get("event_id"), int)
        assert ev.get("channel") in valid_channels
        assert "host" in ev
        assert "timestamp" in ev
        # ISO timestamp parses.
        datetime.fromisoformat(ev["timestamp"])


def test_empty_window_yields_nothing():
    topo = _small_topology()
    model = build_activity_model(topo)
    assert list(generate(topo, model, MON_09_00, MON_09_00, seed=1)) == []
    assert (
        list(generate(topo, model, MON_09_00, MON_09_00 - timedelta(hours=1), seed=1))
        == []
    )
