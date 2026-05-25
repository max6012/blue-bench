"""Cohesive enterprise topology model for the IT baseline generator.

This is the contract every downstream telemetry generator in ``t-it-base``
consumes: ``behavior`` (activity model), ``network_zeek``, ``suricata_noise``,
``sysmon``, ``evtx``, ``linux_logs``, ``identity``, ``services``, and the
composer. It is pure data -- no event emission, no I/O, no log generation.

Three tier knobs (``S``, ``M``, ``L``) drive the host/user populations.
S/M/L are downscalings of the SAME topology model -- scale (host count,
time window) is the only variable across tiers, not topology semantics.

Determinism: ``build_topology(tier, seed)`` is a pure function of its
inputs. Same ``(tier, seed)`` always returns an identical ``Topology``.

Vendor-neutral terminology only -- no exercise vocabulary, no scenario
names, no published-TTX vocabulary anywhere in this module's name pools
or role enums.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

log = logging.getLogger(__name__)


# --- constants: AD forest, VLANs, name pools ---


AD_FOREST_NAME = "corp.example.invalid"
AD_ROOT_DOMAIN = "corp.example.invalid"
AD_OUS: tuple[str, ...] = (
    "Workstations",
    "Servers",
    "Service-Accounts",
    "Admins",
)

# Three-VLAN segmentation: corp (workstations + admin-WS), server (back-end),
# dmz (proxy / jump-host / internet-facing). All RFC1918 inside 10.0.0.0/8.
VLAN_SPECS: tuple[tuple[str, int, str, str], ...] = (
    ("corp", 10, "10.10.0.0/24", "10.10.0.1"),
    ("server", 20, "10.20.0.0/24", "10.20.0.1"),
    ("dmz", 30, "10.30.0.0/24", "10.30.0.1"),
)

# Role -> VLAN routing. Workstations land on corp; servers on server;
# proxy + jump-host on dmz.
_ROLE_VLAN: dict[str, str] = {
    "workstation": "corp",
    "admin-workstation": "corp",
    "file-server": "server",
    "database-server": "server",
    "web-server": "server",
    "mail-server": "server",
    "domain-controller": "server",
    "dhcp-dns-server": "server",
    "siem-server": "server",
    "jump-host": "dmz",
    "proxy-server": "dmz",
}

# Role -> OU mapping.
_ROLE_OU: dict[str, str] = {
    "workstation": "Workstations",
    "admin-workstation": "Workstations",
    "file-server": "Servers",
    "database-server": "Servers",
    "web-server": "Servers",
    "mail-server": "Servers",
    "domain-controller": "Servers",
    "dhcp-dns-server": "Servers",
    "siem-server": "Servers",
    "jump-host": "Servers",
    "proxy-server": "Servers",
}

# OS by role. Workstations and Windows-flavor servers are windows; the
# proxy/jump-host/SIEM are typically Linux in enterprises.
_ROLE_OS: dict[str, Literal["windows", "linux"]] = {
    "workstation": "windows",
    "admin-workstation": "windows",
    "file-server": "windows",
    "database-server": "windows",
    "web-server": "linux",
    "mail-server": "linux",
    "domain-controller": "windows",
    "dhcp-dns-server": "linux",
    "siem-server": "linux",
    "jump-host": "linux",
    "proxy-server": "linux",
}

# Vendor-neutral first / last name pools. Ordinary, multi-cultural,
# avoid anything that could read as a scenario codeword.
_FIRST_NAMES: tuple[str, ...] = (
    "david", "emma", "lucas", "aisha", "marcus", "priya", "tomas", "noor",
    "ethan", "maya", "hassan", "lina", "carlos", "sara", "liam", "anya",
    "jordan", "hana", "felix", "zara", "mateo", "nia", "owen", "tara",
    "rohan", "iris", "bjorn", "lila", "khaled", "sofia",
)

_LAST_NAMES: tuple[str, ...] = (
    "anderson", "chen", "patel", "muller", "okafor", "rodriguez",
    "yamamoto", "singh", "thompson", "kowalski", "nakamura", "schmidt",
    "hassan", "larsen", "tran", "martinez", "ivanov", "khan", "walker",
    "roberts", "ferreira", "cohen", "suzuki", "reyes", "fischer", "bauer",
    "petrov", "jansen", "wagner", "smith",
)

_DEPARTMENTS: tuple[str, ...] = (
    "engineering",
    "finance",
    "operations",
    "sales",
    "hr",
)

# Distribution weights for regular-user departments (must sum to 1.0).
_DEPARTMENT_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("engineering", 0.50),
    ("finance", 0.20),
    ("operations", 0.15),
    ("sales", 0.10),
    ("hr", 0.05),
)

# Guard against accidental vocabulary leaks. The hosts/users/services
# generator never emits these strings; tests assert it. Keep small and
# focused -- the pre-commit forbidden-terms hook is the primary defence,
# and that hook's authoritative pattern list lives in
# ``.githooks/forbidden-terms.local`` (intentionally out-of-band). The
# entries below are a small set of generic exercise-coded terms that the
# pattern file would also catch; this in-code tripwire just shortens the
# feedback loop for an in-process generator change.
FORBIDDEN_TERM_DENYLIST: tuple[str, ...] = (
    "redteam",
    "blueteam",
    "tabletop",
    "northstar",
)


# --- dataclasses ---


@dataclass(frozen=True)
class ADForest:
    name: str
    root_domain: str
    ous: tuple[str, ...]


@dataclass(frozen=True)
class VLAN:
    name: str
    vlan_id: int
    subnet: str
    gateway_ip: str


@dataclass(frozen=True)
class Host:
    name: str
    fqdn: str
    os: Literal["windows", "linux"]
    role: str
    vlan: str
    ip: str
    ou: str


@dataclass(frozen=True)
class User:
    username: str
    display_name: str
    role: Literal["user", "admin", "service"]
    primary_host: str
    department: str


@dataclass(frozen=True)
class Service:
    name: str
    endpoint_hosts: tuple[str, ...]
    port: int


@dataclass(frozen=True)
class Topology:
    tier: Literal["S", "M", "L"]
    seed: int
    forest: ADForest
    vlans: tuple[VLAN, ...]
    hosts: tuple[Host, ...]
    users: tuple[User, ...]
    services: tuple[Service, ...]


# --- per-tier population spec ---


# Maps role -> count per tier. Deliberately frozen here (not parameterised)
# so all callers see the same topology shape at each tier.
_TIER_POPULATION: dict[str, dict[str, int]] = {
    "S": {
        "workstation": 6,
        "admin-workstation": 1,
        "file-server": 1,
        "database-server": 0,
        "web-server": 1,
        "mail-server": 0,
        "domain-controller": 1,
        "jump-host": 0,
        "proxy-server": 0,
        "siem-server": 0,
        "dhcp-dns-server": 1,
    },
    "M": {
        "workstation": 16,
        "admin-workstation": 2,
        "file-server": 2,
        "database-server": 1,
        "web-server": 1,
        "mail-server": 1,
        "domain-controller": 2,
        "jump-host": 0,
        "proxy-server": 1,
        "siem-server": 0,
        "dhcp-dns-server": 1,
    },
    "L": {
        "workstation": 22,
        "admin-workstation": 4,
        "file-server": 3,
        "database-server": 2,
        "web-server": 2,
        "mail-server": 2,
        "domain-controller": 2,
        "jump-host": 1,
        "proxy-server": 1,
        "siem-server": 1,
        "dhcp-dns-server": 1,
    },
}


# Per-tier regular-user counts (additional admins + service users are
# derived from host count, not specified here).
_TIER_REGULAR_USERS: dict[str, int] = {"S": 10, "M": 30, "L": 50}


# Naming pattern per role -- short, deterministic, no random suffixes.
_ROLE_HOST_PREFIX: dict[str, str] = {
    "workstation": "wkst",
    "admin-workstation": "wkst-adm",
    "file-server": "srv-files",
    "database-server": "srv-db",
    "web-server": "srv-web",
    "mail-server": "srv-mail",
    "domain-controller": "dc",
    "jump-host": "jump",
    "proxy-server": "proxy",
    "siem-server": "siem",
    "dhcp-dns-server": "ns",
}


# Services and the role of their endpoint hosts.
_SERVICE_SPECS: tuple[tuple[str, str, int], ...] = (
    ("dns", "dhcp-dns-server", 53),
    ("dhcp", "dhcp-dns-server", 67),
    ("ad-dc", "domain-controller", 389),
    ("smb", "file-server", 445),
    ("proxy", "proxy-server", 3128),
    ("siem", "siem-server", 514),
)


# --- builder ---


def _make_hosts(tier: Literal["S", "M", "L"]) -> tuple[Host, ...]:
    """Deterministic host list. Naming is sequential per-role."""
    population = _TIER_POPULATION[tier]
    # IP allocation cursors per VLAN. Reserve .1 for the gateway and .2
    # for a placeholder broadcast-ish address; start hosts at .10.
    next_ip_octet: dict[str, int] = {"corp": 10, "server": 10, "dmz": 10}
    # For each VLAN, derive the /24 prefix as the first three octets.
    # e.g. "10.10.0.0/24" -> "10.10.0", so f"{prefix}.{octet}" produces
    # a well-formed dotted-quad host IP.
    vlan_subnet_prefix: dict[str, str] = {}
    for name, _vid, cidr, _gw in VLAN_SPECS:
        network_only = cidr.split("/", 1)[0]  # "10.10.0.0"
        vlan_subnet_prefix[name] = network_only.rsplit(".", 1)[0]  # "10.10.0"

    hosts: list[Host] = []
    # Sorted role iteration -> deterministic regardless of dict order
    # (CPython 3.7+ preserves insertion, but explicit sort survives
    # accidental reorders).
    for role in sorted(population.keys()):
        count = population[role]
        if count <= 0:
            continue
        prefix = _ROLE_HOST_PREFIX[role]
        vlan = _ROLE_VLAN[role]
        prefix_octets = vlan_subnet_prefix[vlan]
        ou = _ROLE_OU[role]
        os_choice: Literal["windows", "linux"] = _ROLE_OS[role]
        for i in range(1, count + 1):
            name = f"{prefix}-{i:02d}"
            fqdn = f"{name}.{AD_FOREST_NAME}"
            octet = next_ip_octet[vlan]
            ip = f"{prefix_octets}.{octet}"
            next_ip_octet[vlan] = octet + 1
            hosts.append(
                Host(
                    name=name,
                    fqdn=fqdn,
                    os=os_choice,
                    role=role,
                    vlan=vlan,
                    ip=ip,
                    ou=ou,
                )
            )
    return tuple(hosts)


def _name_at(index: int) -> tuple[str, str]:
    """Pick (first, last) deterministically from the pools.

    Uses 2D indexing (first cycles, last advances every full first cycle)
    so the pair space is ``|first| * |last| = 900`` unique combinations
    before wrap-around -- comfortably above any tier's user count.
    """
    first = _FIRST_NAMES[index % len(_FIRST_NAMES)]
    last = _LAST_NAMES[(index // len(_FIRST_NAMES)) % len(_LAST_NAMES)]
    return first, last


def _dept_for(index: int) -> str:
    """Weighted-deterministic department assignment.

    Uses cumulative weights against ``index % 20`` so the distribution
    converges to the declared weights without an RNG call.
    """
    bucket = index % 20  # 0..19 -> 5% resolution
    cumulative = 0
    for dept, weight in _DEPARTMENT_WEIGHTS:
        cumulative += round(weight * 20)
        if bucket < cumulative:
            return dept
    return _DEPARTMENT_WEIGHTS[-1][0]


def _make_users(tier: Literal["S", "M", "L"], hosts: tuple[Host, ...]) -> tuple[User, ...]:
    workstations = [h for h in hosts if h.role == "workstation"]
    admin_workstations = [h for h in hosts if h.role == "admin-workstation"]
    servers = [h for h in hosts if h.role not in ("workstation", "admin-workstation")]

    users: list[User] = []

    # Regular users: round-robin onto workstations.
    regular_count = _TIER_REGULAR_USERS[tier]
    if not workstations:
        raise ValueError(f"tier {tier} has no workstations -- cannot place regular users")
    for i in range(regular_count):
        first, last = _name_at(i)
        username = f"{first}.{last}"
        display_name = f"{first.capitalize()} {last.capitalize()}"
        host = workstations[i % len(workstations)]
        users.append(
            User(
                username=username,
                display_name=display_name,
                role="user",
                primary_host=host.name,
                department=_dept_for(i),
            )
        )

    # Admin users: one per admin-workstation, names from a different
    # slice of the pool so they don't collide with regular users.
    admin_offset = len(_FIRST_NAMES) // 2
    for j, host in enumerate(admin_workstations):
        first, last = _name_at(admin_offset + j)
        username = f"{first}.{last}.adm"
        display_name = f"{first.capitalize()} {last.capitalize()} (Admin)"
        users.append(
            User(
                username=username,
                display_name=display_name,
                role="admin",
                primary_host=host.name,
                department="operations",
            )
        )

    # Service users: one per service-endpoint server. Use svc-<service>-<n>
    # naming. Primary host is the first endpoint of the service.
    service_assignments = _service_assignments(hosts)
    for svc_name, endpoint_hosts, _port in service_assignments:
        for n, host_name in enumerate(endpoint_hosts, start=1):
            username = f"svc-{svc_name}-{n:02d}"
            display_name = f"Service Account: {svc_name} ({n})"
            users.append(
                User(
                    username=username,
                    display_name=display_name,
                    role="service",
                    primary_host=host_name,
                    department="operations",
                )
            )

    # Sanity guard against name collisions.
    seen: set[str] = set()
    for u in users:
        if u.username in seen:
            raise ValueError(f"username collision: {u.username}")
        seen.add(u.username)
    _ = servers  # name kept for future tests; not currently used here
    return tuple(users)


def _service_assignments(
    hosts: tuple[Host, ...],
) -> tuple[tuple[str, tuple[str, ...], int], ...]:
    """Map services to their endpoint host names.

    Skips services whose endpoint role has zero hosts in this tier
    (e.g. proxy and siem at S tier).
    """
    by_role: dict[str, list[str]] = {}
    for h in hosts:
        by_role.setdefault(h.role, []).append(h.name)

    out: list[tuple[str, tuple[str, ...], int]] = []
    for svc_name, role, port in _SERVICE_SPECS:
        endpoint_hosts = tuple(by_role.get(role, ()))
        if not endpoint_hosts:
            continue
        out.append((svc_name, endpoint_hosts, port))
    return tuple(out)


def _make_services(hosts: tuple[Host, ...]) -> tuple[Service, ...]:
    return tuple(
        Service(name=svc_name, endpoint_hosts=endpoints, port=port)
        for svc_name, endpoints, port in _service_assignments(hosts)
    )


def build_topology(
    tier: Literal["S", "M", "L"], seed: int = 0
) -> Topology:
    """Deterministic topology builder.

    Args:
        tier: corpus tier -- "S", "M", or "L".
        seed: integer seed reserved for future stochastic variations; the
            current implementation does not use it (population, naming,
            and IP allocation are all index-driven). Accepted and
            recorded on the Topology so future tier changes can vary
            shape without breaking the call contract.

    Returns:
        Topology dataclass (frozen, hashable, tuple-only collections).
    """
    if tier not in _TIER_POPULATION:
        raise ValueError(f"unknown tier {tier!r}; expected one of {sorted(_TIER_POPULATION)}")

    forest = ADForest(
        name=AD_FOREST_NAME, root_domain=AD_ROOT_DOMAIN, ous=AD_OUS
    )
    vlans = tuple(
        VLAN(name=name, vlan_id=vid, subnet=cidr, gateway_ip=gw)
        for name, vid, cidr, gw in VLAN_SPECS
    )
    hosts = _make_hosts(tier)
    users = _make_users(tier, hosts)
    services = _make_services(hosts)

    log.info(
        "built topology: tier=%s hosts=%d users=%d services=%d",
        tier,
        len(hosts),
        len(users),
        len(services),
    )

    return Topology(
        tier=tier,
        seed=seed,
        forest=forest,
        vlans=vlans,
        hosts=hosts,
        users=users,
        services=services,
    )
