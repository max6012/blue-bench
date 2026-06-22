"""Build a ``Topology``-shaped object from an EvidenceForge scenario YAML.

The OT generators (``ot_protocols``, ``ot_hosts``) and the IT/OT bridge were
written against ``it_baseline.topology.Topology``. They read a narrow slice of
it: ``.tier`` / ``.seed`` everywhere, plus — for the bridge — ``.hosts`` (each
with ``.role`` / ``.fqdn`` / ``.ip``) and ``.users`` (each with ``.username``).

EvidenceForge owns IT host identity now, and the scenario YAML is the source of
truth EF itself reads. This shim parses that same file into the slice the
generators need, mapping EF's ``type`` / ``roles`` vocabulary onto the role
strings the bridge selects on (``workstation`` / ``file-server`` /
``database-server`` / ``domain-controller`` / ...). Feeding the shim to the
unchanged generators makes their IT-side references match the EF corpus by
construction — same file, same hosts, same IPs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from blue_bench_generators.it_baseline.topology import Host, User


@dataclass(frozen=True)
class ScenarioTopology:
    """The slice of ``Topology`` the OT/bridge generators actually read."""

    tier: Literal["S", "M", "L"]
    seed: int
    hosts: tuple[Host, ...]
    users: tuple[User, ...]


# EF system type / role vocabulary -> the role strings the bridge selects on
# (it_baseline.it_ot_bridge.bridge reads h.role == "workstation",
# "admin-workstation", "file-server", "database-server", "jump-host").
def _bridge_role(system: dict) -> str:
    sys_type = str(system.get("type", "")).lower()
    roles = [str(r).lower().replace("_", "-") for r in (system.get("roles") or [])]
    if sys_type == "workstation":
        return "workstation"
    if sys_type == "domain_controller" or "domain-controller" in roles:
        return "domain-controller"
    if "file-server" in roles:
        return "file-server"
    if "database" in roles or "database-server" in roles:
        return "database-server"
    if "web-server" in roles:
        return "web-server"
    if "jump-host" in roles or "jump-server" in roles:
        return "jump-host"
    return sys_type or "server"


def _os_kind(system: dict) -> Literal["windows", "linux"]:
    return "windows" if "windows" in str(system.get("os", "")).lower() else "linux"


def shim_from_scenario(
    scenario_path: str | Path,
    *,
    tier: Literal["S", "M", "L"],
    seed: int = 0,
) -> ScenarioTopology:
    """Parse an EF scenario YAML into a generator-ready ``ScenarioTopology``.

    Args:
        scenario_path: path to the EF scenario YAML.
        tier: corpus tier (drives OT network size via ``build_ot_network``).
        seed: OT/bridge seed — share it across ``ot_protocols`` / ``ot_hosts``
            and the bridge so the bridge's internal OT endpoints match the
            standalone OT telemetry.
    """
    doc = yaml.safe_load(Path(scenario_path).read_text(encoding="utf-8"))
    env = doc.get("environment", {})
    domain = str(env.get("domain", "")).strip()

    hosts: list[Host] = []
    for sysd in env.get("systems", []) or []:
        name = str(sysd["hostname"])
        fqdn = f"{name}.{domain}" if domain and "." not in name else name
        hosts.append(Host(
            name=name,
            fqdn=fqdn,
            os=_os_kind(sysd),
            role=_bridge_role(sysd),
            vlan=str(sysd.get("segment", sysd.get("vlan", ""))),
            ip=str(sysd.get("ip", "")),
            ou=str(sysd.get("type", "")),
        ))

    users: list[User] = []
    for usr in env.get("users", []) or []:
        groups = [str(g).lower() for g in (usr.get("groups") or [])]
        role = "admin" if any("admin" in g for g in groups) else "user"
        users.append(User(
            username=str(usr["username"]),
            display_name=str(usr.get("full_name", usr.get("username", ""))),
            role=role,
            primary_host=str(usr.get("primary_system", "")),
            department="",
        ))

    return ScenarioTopology(tier=tier, seed=seed, hosts=tuple(hosts), users=tuple(users))
