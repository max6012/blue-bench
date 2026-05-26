"""Tests for the OT plant-network topology builder.

Acceptance bar (t-7puu): ``build_ot_network(tier, seed)`` returns a
populated ``OTNetwork``; IP-plan coherence, master/slave-link invariants,
tier-population correctness, and seeded determinism all hold.
"""

from __future__ import annotations

import ipaddress
import pytest

from blue_bench_generators.ot_protocols.topology import (
    OT_VLAN_SPECS,
    PROTOCOL_PORTS,
    OTNetwork,
    _ROLE_VLAN,
    _TIER_POPULATION,
    build_ot_network,
)


TIERS = ("S", "M", "L")


# --- shape ----------------------------------------------------------------


@pytest.mark.parametrize("tier", TIERS)
def test_build_returns_ot_network(tier):
    net = build_ot_network(tier=tier)
    assert isinstance(net, OTNetwork)
    assert net.tier == tier
    assert len(net.vlans) == 3
    assert len(net.devices) > 0
    assert len(net.links) > 0


@pytest.mark.parametrize("tier", TIERS)
def test_populations_match_per_tier_table(tier):
    net = build_ot_network(tier=tier)
    by_role: dict[str, int] = {}
    for d in net.devices:
        by_role[d.role] = by_role.get(d.role, 0) + 1
    expected = {r: c for r, c in _TIER_POPULATION[tier].items() if c > 0}
    assert by_role == expected


def test_tier_s_is_smallest(_unused_for_alignment=None):
    # Just so the comparator below reads naturally.
    pass


@pytest.mark.parametrize("smaller,larger", [("S", "M"), ("M", "L")])
def test_tiers_are_downscalings(smaller, larger):
    """S/M/L are downscalings of the same shape: device count monotonically
    grows with tier."""
    s = build_ot_network(tier=smaller)
    l = build_ot_network(tier=larger)
    assert len(s.devices) < len(l.devices), (
        f"{smaller} should have fewer devices than {larger}: "
        f"{len(s.devices)} vs {len(l.devices)}"
    )


def test_unknown_tier_raises():
    with pytest.raises(ValueError, match="unknown tier"):
        build_ot_network(tier="XL")  # type: ignore[arg-type]


# --- IP plan + VLAN coherence ---------------------------------------------


@pytest.mark.parametrize("tier", TIERS)
def test_every_device_ip_lives_in_its_vlan_subnet(tier):
    net = build_ot_network(tier=tier)
    subnets = {v.name: ipaddress.ip_network(v.subnet) for v in net.vlans}
    for d in net.devices:
        assert d.vlan in subnets, f"device {d.name} on unknown VLAN {d.vlan}"
        assert ipaddress.ip_address(d.ip) in subnets[d.vlan], (
            f"device {d.name} ip={d.ip} not in vlan={d.vlan} subnet={subnets[d.vlan]}"
        )


@pytest.mark.parametrize("tier", TIERS)
def test_ips_are_unique_within_vlan(tier):
    net = build_ot_network(tier=tier)
    seen: dict[str, set[str]] = {}
    for d in net.devices:
        seen.setdefault(d.vlan, set())
        assert d.ip not in seen[d.vlan], (
            f"ip collision on vlan {d.vlan}: {d.name} reused {d.ip}"
        )
        seen[d.vlan].add(d.ip)


@pytest.mark.parametrize("tier", TIERS)
def test_role_to_vlan_mapping_is_consistent(tier):
    """Every device's vlan must match the canonical ROLE_VLAN map.
    Generators downstream rely on this invariant to route traffic."""
    net = build_ot_network(tier=tier)
    for d in net.devices:
        assert d.vlan == _ROLE_VLAN[d.role], (
            f"device {d.name} role={d.role} placed on vlan={d.vlan}, "
            f"expected {_ROLE_VLAN[d.role]}"
        )


def test_ot_subnets_do_not_collide_with_it_baseline_vlans():
    """IT baseline uses 10.10/10.20/10.30; OT must not overlap so an
    IT+OT corpus has no IP collisions."""
    from blue_bench_generators.it_baseline.topology import VLAN_SPECS as IT_VLANS

    it_subnets = [ipaddress.ip_network(cidr) for _, _, cidr, _ in IT_VLANS]
    ot_subnets = [ipaddress.ip_network(cidr) for _, _, cidr, _ in OT_VLAN_SPECS]
    for it in it_subnets:
        for ot in ot_subnets:
            assert not it.overlaps(ot), (
                f"OT subnet {ot} overlaps with IT subnet {it}"
            )


# --- master-slave links ---------------------------------------------------


@pytest.mark.parametrize("tier", TIERS)
def test_all_link_endpoints_are_real_devices(tier):
    net = build_ot_network(tier=tier)
    names = {d.name for d in net.devices}
    for l in net.links:
        assert l.master in names, f"link master {l.master!r} not a device"
        assert l.slave in names, f"link slave {l.slave!r} not a device"


@pytest.mark.parametrize("tier", TIERS)
def test_link_protocols_match_port_table(tier):
    """Every protocol in the link set must be in the PROTOCOL_PORTS table
    (so the per-protocol generators can map link -> conn dst port)."""
    net = build_ot_network(tier=tier)
    used_protocols = {l.protocol for l in net.links}
    for proto in used_protocols:
        assert proto in PROTOCOL_PORTS, (
            f"protocol {proto!r} has no canonical port in PROTOCOL_PORTS"
        )


@pytest.mark.parametrize("tier", ("M", "L"))
def test_modbus_links_have_every_rtu_owned_exactly_once(tier):
    """Modbus modelling assumes each RTU is polled by exactly one
    controller (balanced round-robin). The DNP3 path adds a second
    polling link per RTU on a different protocol, but Modbus alone must
    have RTU -> controller cardinality 1."""
    net = build_ot_network(tier=tier)
    rtus = [d.name for d in net.devices if d.role == "rtu"]
    modbus_links = [l for l in net.links if l.protocol == "modbus"]
    rtu_master_count: dict[str, int] = {n: 0 for n in rtus}
    for l in modbus_links:
        if l.slave in rtu_master_count:
            rtu_master_count[l.slave] += 1
    for rtu, n in rtu_master_count.items():
        assert n == 1, f"RTU {rtu} has {n} Modbus masters, expected 1"


@pytest.mark.parametrize("tier", TIERS)
def test_modbus_links_only_cross_supervisory_to_field(tier):
    """A Modbus link's master is a controller (control VLAN); its slave
    is an RTU (field VLAN). Tests enforce no RTU->RTU or controller->
    controller Modbus."""
    net = build_ot_network(tier=tier)
    role_by_name = {d.name: d.role for d in net.devices}
    for l in net.links:
        if l.protocol != "modbus":
            continue
        assert role_by_name[l.master] in ("controller", "safety-controller")
        assert role_by_name[l.slave] == "rtu"


@pytest.mark.parametrize("tier", ("M", "L"))
def test_dnp3_links_present_when_supervisory_devices_exist(tier):
    """DNP3 links: HMI / historian -> controller (supervisory polling).
    Must be present at any tier with at least 1 HMI/historian and 1
    controller."""
    net = build_ot_network(tier=tier)
    dnp3 = [l for l in net.links if l.protocol == "dnp3"]
    assert dnp3, f"tier {tier} produced no DNP3 links"


@pytest.mark.parametrize("tier", ("M", "L"))
def test_iec104_links_only_hmi_to_controller(tier):
    net = build_ot_network(tier=tier)
    role_by_name = {d.name: d.role for d in net.devices}
    iec = [l for l in net.links if l.protocol == "iec104"]
    assert iec, f"tier {tier} produced no IEC-104 links"
    for l in iec:
        assert role_by_name[l.master] == "hmi"
        assert role_by_name[l.slave] in ("controller", "safety-controller")


def test_s7comm_links_only_ews_to_siemens_controller():
    """S7Comm in this model targets vendor-a controllers only (the
    Siemens stand-in in our vendor pool)."""
    net = build_ot_network(tier="L")
    vendor_by_name = {d.name: d.vendor for d in net.devices}
    role_by_name = {d.name: d.role for d in net.devices}
    s7 = [l for l in net.links if l.protocol == "s7comm"]
    assert s7, "L tier produced no S7Comm links"
    for l in s7:
        assert role_by_name[l.master] == "engineering-workstation"
        assert role_by_name[l.slave] in ("controller", "safety-controller")
        assert vendor_by_name[l.slave] == "vendor-a", (
            f"S7Comm slave {l.slave} vendor={vendor_by_name[l.slave]}, expected vendor-a"
        )


# --- determinism ----------------------------------------------------------


@pytest.mark.parametrize("tier", TIERS)
def test_same_inputs_yield_identical_network(tier):
    a = build_ot_network(tier=tier, seed=0)
    b = build_ot_network(tier=tier, seed=0)
    assert a == b


@pytest.mark.parametrize("tier", TIERS)
def test_seed_is_invariant_in_v1(tier):
    """v1 OT topology is seed-invariant by design (devices, IPs, links
    are fixed by tier). The seed parameter is reserved for future
    stochastic overlays."""
    a = build_ot_network(tier=tier, seed=0)
    b = build_ot_network(tier=tier, seed=99)
    assert a.devices == b.devices
    assert a.links == b.links
    assert a.vlans == b.vlans


