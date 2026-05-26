"""Cohesive plant-network topology for the OT protocol generators.

Contract every downstream OT generator (``modbus``, ``dnp3``, ``iec104``,
``s7comm``) consumes. Pure data -- no event emission, no I/O.

Tier knob (``S``, ``M``, ``L``) drives device populations. S/M/L are
downscalings of the SAME plant-network shape -- scale (device count, time
window) is the only variable across tiers, not topology semantics.

Determinism: ``build_ot_network(tier, seed)`` is a pure function of its
inputs. Same ``(tier, seed)`` always returns an identical ``OTNetwork``.

Vendor-neutral terminology only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

log = logging.getLogger(__name__)


# --- constants: VLANs, role layout, protocol mapping ----------------------


# Three-tier plant-network segmentation per IEC 62443 zone-and-conduit
# practice. All RFC1918 inside 10.0.0.0/8. Subnets are deliberately above
# the IT-baseline VLAN range (10.10/10.20/10.30) so an IT+OT corpus has
# no IP collisions.
OT_VLAN_SPECS: tuple[tuple[str, int, str, str], ...] = (
    # supervisory: HMI consoles, historians, engineering workstations.
    ("ot-supervisory", 40, "10.40.0.0/24", "10.40.0.1"),
    # control: PLCs and DCS controllers.
    ("ot-control", 41, "10.41.0.0/24", "10.41.0.1"),
    # field: RTUs and field devices.
    ("ot-field", 42, "10.42.0.0/24", "10.42.0.1"),
)


_ROLE_VLAN: dict[str, str] = {
    "hmi": "ot-supervisory",
    "historian": "ot-supervisory",
    "engineering-workstation": "ot-supervisory",
    "ot-firewall": "ot-supervisory",
    "controller": "ot-control",
    "safety-controller": "ot-control",
    "rtu": "ot-field",
}


# OS by role. Operator-facing supervisory hosts run Windows
# (HMI/EWS) or Linux (historian); controllers and RTUs run vendor RTOS
# which we mark as "embedded" since they are not Windows/Linux for the
# IT-style logging purposes.
_ROLE_OS: dict[str, Literal["windows", "linux", "embedded"]] = {
    "hmi": "windows",
    "historian": "linux",
    "engineering-workstation": "windows",
    "ot-firewall": "linux",
    "controller": "embedded",
    "safety-controller": "embedded",
    "rtu": "embedded",
}


# Sequential per-role host prefix. Deterministic; no random suffixes.
_ROLE_HOST_PREFIX: dict[str, str] = {
    "hmi": "hmi",
    "historian": "histor",
    "engineering-workstation": "ews",
    "ot-firewall": "ot-fw",
    "controller": "plc",
    "safety-controller": "safety",
    "rtu": "rtu",
}


# Vendor pool. Deterministic round-robin per role -- each controller and
# each RTU gets a vendor stamp so the per-protocol generators can pick
# protocol-appropriate links (e.g. S7Comm targets only "siemens"-flavour
# controllers; DNP3 outstations are any vendor; Modbus is universal).
# Vendor-neutral by IEC convention: "vendor-a" / "vendor-b" rather than
# real company names. The per-protocol generators document which vendor
# their protocol targets.
_VENDOR_POOL: tuple[str, ...] = ("vendor-a", "vendor-b", "vendor-c", "vendor-d")


# Per-tier device populations. Roles with count 0 in a tier are skipped.
_TIER_POPULATION: dict[str, dict[str, int]] = {
    "S": {
        "hmi": 1,
        "historian": 1,
        "engineering-workstation": 1,
        "ot-firewall": 0,
        "controller": 2,
        "safety-controller": 0,
        "rtu": 3,
    },
    "M": {
        "hmi": 2,
        "historian": 1,
        "engineering-workstation": 2,
        "ot-firewall": 1,
        "controller": 4,
        "safety-controller": 0,
        "rtu": 10,
    },
    "L": {
        "hmi": 4,
        "historian": 2,
        "engineering-workstation": 4,
        "ot-firewall": 1,
        "controller": 8,
        "safety-controller": 1,
        "rtu": 20,
    },
}


# --- protocol-to-port mapping (canonical OT ports) ------------------------


# Standard IANA / vendor-default ports per protocol. Generators reference
# these so downstream conn.log records carry the right ``id.resp_p``.
PROTOCOL_PORTS: dict[str, int] = {
    "modbus": 502,    # Modbus/TCP
    "dnp3": 20000,    # DNP3 over TCP
    "iec104": 2404,   # IEC-60870-5-104
    "s7comm": 102,    # ISO-on-TCP / S7Comm
}


# --- dataclasses ----------------------------------------------------------


@dataclass(frozen=True)
class OTVlan:
    name: str
    vlan_id: int
    subnet: str
    gateway_ip: str


@dataclass(frozen=True)
class Device:
    name: str
    fqdn: str
    os: Literal["windows", "linux", "embedded"]
    role: str
    vlan: str
    ip: str
    # Vendor stamp -- used by per-protocol generators to pick links.
    # Supervisory devices (HMI/EWS/historian/firewall) carry the empty
    # string; only field-side (controller/safety-controller/rtu) carries
    # a vendor label.
    vendor: str


@dataclass(frozen=True)
class MasterSlaveLink:
    """A directional protocol-bound link between two devices.

    ``master`` -> ``slave`` direction is the polling direction. For
    Modbus that's controller->RTU. For DNP3 that's HMI/historian->
    outstation (controller or RTU). For IEC-104 that's controlling-
    station->controlled-station. For S7Comm that's HMI/EWS->controller.
    """

    master: str
    slave: str
    protocol: Literal["modbus", "dnp3", "iec104", "s7comm"]
    # Nominal cycle in hertz (reads per second). 0.0 marks event-driven /
    # non-cyclic links (e.g. S7Comm engineering sessions).
    polling_hz: float


@dataclass(frozen=True)
class OTNetwork:
    tier: Literal["S", "M", "L"]
    seed: int
    vlans: tuple[OTVlan, ...]
    devices: tuple[Device, ...]
    links: tuple[MasterSlaveLink, ...]


# --- builder helpers ------------------------------------------------------


def _vlan_prefixes() -> dict[str, str]:
    """Return the /24 dotted-quad prefix for each VLAN.

    e.g. "10.40.0.0/24" -> "10.40.0". Allocator code appends ``.{octet}``
    to produce well-formed host IPs.
    """
    prefixes: dict[str, str] = {}
    for name, _vid, cidr, _gw in OT_VLAN_SPECS:
        network_only = cidr.split("/", 1)[0]  # "10.40.0.0"
        prefixes[name] = network_only.rsplit(".", 1)[0]  # "10.40.0"
    return prefixes


def _make_devices(tier: Literal["S", "M", "L"]) -> tuple[Device, ...]:
    """Deterministic device list. Naming is sequential per-role.

    Hosts in each VLAN start at .10 (reserving .1 for the gateway and
    .2-.9 for future infrastructure). Vendor stamps cycle through
    ``_VENDOR_POOL`` for controller/RTU roles so each protocol generator
    can pick a vendor-appropriate subset of links.
    """
    population = _TIER_POPULATION[tier]
    next_ip_octet: dict[str, int] = {name: 10 for name, _, _, _ in OT_VLAN_SPECS}
    prefixes = _vlan_prefixes()

    devices: list[Device] = []
    # Sorted role iteration -> deterministic regardless of dict order.
    for role in sorted(population.keys()):
        count = population[role]
        if count <= 0:
            continue
        prefix = _ROLE_HOST_PREFIX[role]
        vlan = _ROLE_VLAN[role]
        os_choice = _ROLE_OS[role]
        for i in range(1, count + 1):
            name = f"{prefix}-{i:02d}"
            fqdn = f"{name}.plant.example.invalid"
            octet = next_ip_octet[vlan]
            ip = f"{prefixes[vlan]}.{octet}"
            next_ip_octet[vlan] = octet + 1
            # Vendor stamp only for field-side roles.
            if role in ("controller", "safety-controller", "rtu"):
                vendor = _VENDOR_POOL[(i - 1) % len(_VENDOR_POOL)]
            else:
                vendor = ""
            devices.append(
                Device(
                    name=name,
                    fqdn=fqdn,
                    os=os_choice,
                    role=role,
                    vlan=vlan,
                    ip=ip,
                    vendor=vendor,
                )
            )
    return tuple(devices)


def _by_role(devices: tuple[Device, ...]) -> dict[str, list[Device]]:
    out: dict[str, list[Device]] = {}
    for d in devices:
        out.setdefault(d.role, []).append(d)
    return out


def _make_links(devices: tuple[Device, ...]) -> tuple[MasterSlaveLink, ...]:
    """Build the master-slave link set for all four protocols.

    Modbus: each controller polls a deterministic slice of RTUs at 1 Hz.
        RTUs are distributed across controllers in a balanced
        round-robin so every RTU is owned by exactly one controller and
        controllers carry roughly equal RTU counts.
    DNP3: each HMI polls every controller at 0.1 Hz (integrity poll
        cadence). Historian additionally pulls from every controller at
        0.05 Hz. Field-side: each controller polls its RTUs at 0.5 Hz
        DNP3 class-1 event polls (representing the controller-as-
        DNP3-master role in mixed deployments).
    IEC-104: each HMI on supervisory VLAN cyclic-reads from every
        controller at 0.2 Hz. (No RTU-side IEC-104 in v1.)
    S7Comm: each engineering-workstation has an event-driven session
        with every Siemens-vendor controller (vendor-a in our pool by
        convention). polling_hz=0.0 marks event-driven.

    All links are deterministic given the device list -- no RNG.
    """
    by_role = _by_role(devices)
    rtus = by_role.get("rtu", [])
    controllers = by_role.get("controller", []) + by_role.get("safety-controller", [])
    hmis = by_role.get("hmi", [])
    historians = by_role.get("historian", [])
    ewss = by_role.get("engineering-workstation", [])

    links: list[MasterSlaveLink] = []

    # Modbus: controller -> RTU, balanced round-robin assignment.
    for i, rtu in enumerate(rtus):
        if not controllers:
            break
        master = controllers[i % len(controllers)]
        links.append(
            MasterSlaveLink(
                master=master.name, slave=rtu.name, protocol="modbus",
                polling_hz=1.0,
            )
        )

    # DNP3: HMI integrity polls + historian aggregation + controller->RTU
    # event polls.
    for hmi in hmis:
        for c in controllers:
            links.append(
                MasterSlaveLink(
                    master=hmi.name, slave=c.name, protocol="dnp3",
                    polling_hz=0.1,
                )
            )
    for h in historians:
        for c in controllers:
            links.append(
                MasterSlaveLink(
                    master=h.name, slave=c.name, protocol="dnp3",
                    polling_hz=0.05,
                )
            )
    for i, rtu in enumerate(rtus):
        if not controllers:
            break
        master = controllers[i % len(controllers)]
        links.append(
            MasterSlaveLink(
                master=master.name, slave=rtu.name, protocol="dnp3",
                polling_hz=0.5,
            )
        )

    # IEC-104: HMI cyclic-read from every controller. No RTU-side in v1.
    for hmi in hmis:
        for c in controllers:
            links.append(
                MasterSlaveLink(
                    master=hmi.name, slave=c.name, protocol="iec104",
                    polling_hz=0.2,
                )
            )

    # S7Comm: engineering workstation -> Siemens-flavour controller
    # (vendor-a). Event-driven (polling_hz=0.0).
    siemens_controllers = [c for c in controllers if c.vendor == "vendor-a"]
    for ews in ewss:
        for c in siemens_controllers:
            links.append(
                MasterSlaveLink(
                    master=ews.name, slave=c.name, protocol="s7comm",
                    polling_hz=0.0,
                )
            )

    return tuple(links)


# --- public builder -------------------------------------------------------


def build_ot_network(
    tier: Literal["S", "M", "L"], seed: int = 0
) -> OTNetwork:
    """Deterministic OT plant-network builder.

    Args:
        tier: corpus tier -- "S", "M", or "L". Drives device population
            from a fixed per-tier table.
        seed: reserved for future stochastic overlays. v1 builds are
            seed-INVARIANT (devices, IPs, VLANs, master-slave links are
            entirely determined by ``tier``); the parameter is present
            for API symmetry with ``it_baseline.build_topology`` and so
            downstream callers can pass ``seed`` uniformly.

    Returns:
        ``OTNetwork`` dataclass (frozen, hashable, tuple-only collections).
    """
    if tier not in _TIER_POPULATION:
        raise ValueError(
            f"unknown tier {tier!r}; expected one of {sorted(_TIER_POPULATION)}"
        )

    vlans = tuple(
        OTVlan(name=name, vlan_id=vid, subnet=cidr, gateway_ip=gw)
        for name, vid, cidr, gw in OT_VLAN_SPECS
    )
    devices = _make_devices(tier)
    links = _make_links(devices)

    log.info(
        "built OT network: tier=%s devices=%d links=%d (modbus=%d dnp3=%d iec104=%d s7comm=%d)",
        tier,
        len(devices),
        len(links),
        sum(1 for l in links if l.protocol == "modbus"),
        sum(1 for l in links if l.protocol == "dnp3"),
        sum(1 for l in links if l.protocol == "iec104"),
        sum(1 for l in links if l.protocol == "s7comm"),
    )

    return OTNetwork(
        tier=tier,
        seed=seed,
        vlans=vlans,
        devices=devices,
        links=links,
    )
