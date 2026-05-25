"""Topology contract tests for `t-it-base` subtask t-l4il.

Cover deterministic build, tier population, IPAM coherence, user/host
references, OU membership, and a tripwire against accidental
exercise-vocabulary leakage.
"""

from __future__ import annotations

import ipaddress

import pytest

from blue_bench_generators.it_baseline.topology import (
    FORBIDDEN_TERM_DENYLIST,
    Host,
    Topology,
    User,
    build_topology,
)


TIERS = ("S", "M", "L")


# --- determinism ---


def test_build_topology_deterministic():
    for tier in TIERS:
        a = build_topology(tier, seed=42)
        b = build_topology(tier, seed=42)
        assert a == b
        # Tuples mean equality is structural; verify it's actually frozen.
        with pytest.raises(Exception):
            a.hosts[0].name = "mutated"  # type: ignore[misc]


# --- tier counts ---


def test_tier_host_counts():
    # Targets from the t-it-base decomposition spec (within +-2 tolerance).
    expected = {"S": 11, "M": 27, "L": 41}
    for tier, n in expected.items():
        topo = build_topology(tier)
        assert abs(len(topo.hosts) - n) <= 2, (
            f"tier {tier}: expected ~{n} hosts, got {len(topo.hosts)}"
        )


def test_l_tier_meets_40_host_target():
    # The headline number from the resolved 2026-05-25 decision.
    topo = build_topology("L")
    assert len(topo.hosts) >= 40


# --- IPAM coherence ---


def test_no_ip_collisions():
    for tier in TIERS:
        topo = build_topology(tier)
        ips = [h.ip for h in topo.hosts]
        assert len(ips) == len(set(ips)), f"tier {tier} has duplicate IPs"


def test_every_host_ip_in_declared_subnet():
    for tier in TIERS:
        topo = build_topology(tier)
        vlan_subnets = {v.name: ipaddress.ip_network(v.subnet) for v in topo.vlans}
        for h in topo.hosts:
            net = vlan_subnets[h.vlan]
            assert ipaddress.ip_address(h.ip) in net, (
                f"{h.name} ip {h.ip} not in vlan {h.vlan} subnet {net}"
            )


def test_no_host_lands_on_gateway_or_network_address():
    for tier in TIERS:
        topo = build_topology(tier)
        gateways = {v.gateway_ip for v in topo.vlans}
        for h in topo.hosts:
            net = ipaddress.ip_network(
                next(v.subnet for v in topo.vlans if v.name == h.vlan)
            )
            assert h.ip not in gateways
            assert ipaddress.ip_address(h.ip) != net.network_address
            assert ipaddress.ip_address(h.ip) != net.broadcast_address


# --- user / host references ---


def test_every_user_primary_host_exists():
    for tier in TIERS:
        topo = build_topology(tier)
        host_names = {h.name for h in topo.hosts}
        for u in topo.users:
            assert u.primary_host in host_names, (
                f"user {u.username} references unknown host {u.primary_host}"
            )


def test_admin_users_have_admin_workstations():
    for tier in TIERS:
        topo = build_topology(tier)
        by_name: dict[str, Host] = {h.name: h for h in topo.hosts}
        admins = [u for u in topo.users if u.role == "admin"]
        assert admins, f"tier {tier}: no admin users"
        for u in admins:
            host = by_name[u.primary_host]
            assert host.role == "admin-workstation", (
                f"admin user {u.username} primary_host {host.name} has role "
                f"{host.role!r}, expected 'admin-workstation'"
            )


def test_service_users_have_server_hosts():
    for tier in TIERS:
        topo = build_topology(tier)
        by_name: dict[str, Host] = {h.name: h for h in topo.hosts}
        service_users = [u for u in topo.users if u.role == "service"]
        # At every tier we have at least DNS + DHCP + AD-DC services.
        assert len(service_users) >= 3, (
            f"tier {tier}: only {len(service_users)} service users"
        )
        for u in service_users:
            host = by_name[u.primary_host]
            assert host.role not in ("workstation", "admin-workstation"), (
                f"service user {u.username} placed on user-class host {host.name}"
            )


def test_service_endpoint_hosts_exist():
    for tier in TIERS:
        topo = build_topology(tier)
        host_names = {h.name for h in topo.hosts}
        for svc in topo.services:
            assert svc.endpoint_hosts, f"service {svc.name} has zero endpoints"
            for h in svc.endpoint_hosts:
                assert h in host_names, (
                    f"service {svc.name} references unknown host {h}"
                )


# --- redundancy / availability ---


def test_dc_count_per_tier():
    # S: 1 DC acceptable. M and L: at least 2 (redundancy).
    assert _hosts_by_role(build_topology("S"), "domain-controller") >= 1
    assert _hosts_by_role(build_topology("M"), "domain-controller") >= 2
    assert _hosts_by_role(build_topology("L"), "domain-controller") >= 2


# --- OU membership ---


def test_ou_membership_consistent():
    for tier in TIERS:
        topo = build_topology(tier)
        for h in topo.hosts:
            if h.role in ("workstation", "admin-workstation"):
                assert h.ou == "Workstations", (
                    f"{h.name} role={h.role} expected ou=Workstations, got {h.ou}"
                )
            else:
                assert h.ou == "Servers", (
                    f"{h.name} role={h.role} expected ou=Servers, got {h.ou}"
                )


# --- vocabulary guard ---


def test_no_forbidden_terms_in_names():
    """Tripwire against scenario-vocabulary leaks into committed topology.

    The pre-commit forbidden-terms hook is the primary defence; this is a
    cheap additional guard so a future contributor extending the name
    pools sees a test failure immediately.
    """
    for tier in TIERS:
        topo = build_topology(tier)
        all_strings: list[str] = []
        all_strings.extend(h.name for h in topo.hosts)
        all_strings.extend(h.fqdn for h in topo.hosts)
        all_strings.extend(u.username for u in topo.users)
        all_strings.extend(u.display_name for u in topo.users)
        all_strings.extend(s.name for s in topo.services)
        haystack = " ".join(s.lower() for s in all_strings)
        for term in FORBIDDEN_TERM_DENYLIST:
            assert term not in haystack, (
                f"forbidden term {term!r} appears in tier {tier} topology"
            )


# --- type shape sanity ---


def test_topology_collections_are_tuples():
    topo = build_topology("S")
    assert isinstance(topo.hosts, tuple)
    assert isinstance(topo.users, tuple)
    assert isinstance(topo.services, tuple)
    assert isinstance(topo.vlans, tuple)
    assert isinstance(topo.forest.ous, tuple)


def test_unknown_tier_raises():
    with pytest.raises(ValueError):
        build_topology("XL")  # type: ignore[arg-type]


# --- seed varies users, not hosts (added after code-review feedback) ---


def test_seed_changes_user_names_but_not_hosts():
    a = build_topology("M", seed=0)
    b = build_topology("M", seed=7)
    # Hosts/IPs/services are seed-invariant.
    assert a.hosts == b.hosts
    assert a.services == b.services
    assert a.vlans == b.vlans
    # User names vary (at least one regular user has a different username).
    a_regular = sorted(u.username for u in a.users if u.role == "user")
    b_regular = sorted(u.username for u in b.users if u.role == "user")
    assert a_regular != b_regular, "seed change did not vary regular usernames"


# --- helpers ---


def _hosts_by_role(topo: Topology, role: str) -> int:
    return sum(1 for h in topo.hosts if h.role == role)
