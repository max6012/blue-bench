"""Unit tests for the EF-scenario -> Topology shim (blue_bench_generators/merge).

Locks the role mapping the IT/OT bridge selects on, jump-host detection, and
FQDN/IP construction from an EF scenario YAML. No generators or ES needed.
"""

from __future__ import annotations

from pathlib import Path

from blue_bench_generators.merge.scenario_topology import shim_from_scenario

SCENARIO = (
    Path(__file__).resolve().parents[1]
    / "scenarios" / "heavy-telemetry" / "bb-benign-s.yaml"
)


def _by_role(shim):
    out: dict[str, list] = {}
    for h in shim.hosts:
        out.setdefault(h.role, []).append(h)
    return out


def test_shim_maps_ef_types_to_bridge_roles():
    shim = shim_from_scenario(SCENARIO, tier="S", seed=0)
    roles = _by_role(shim)
    # the roles the it_ot_bridge selects on must be present and correctly mapped
    assert len(roles["workstation"]) == 6
    assert "domain-controller" in roles          # type: domain_controller
    assert "file-server" in roles                # roles: [file_server] -> hyphen
    assert "database-server" in roles            # roles: [database]
    assert "web-server" in roles                 # roles: [web_server]


def test_shim_detects_jump_host_and_builds_fqdn_ip():
    shim = shim_from_scenario(SCENARIO, tier="S", seed=0)
    jump = [h for h in shim.hosts if h.role == "jump-host"]
    assert len(jump) == 1
    h = jump[0]
    assert h.fqdn == "jump-ot-01.corp.example.invalid"   # hostname + domain
    assert h.ip == "10.30.0.10"
    assert h.os == "windows"                              # "Windows Server 2022"


def test_shim_carries_tier_seed_and_users():
    shim = shim_from_scenario(SCENARIO, tier="S", seed=7)
    assert shim.tier == "S" and shim.seed == 7
    usernames = {u.username for u in shim.users}
    assert "corp-admin" in usernames
    # group containing "admin" -> admin role
    admin = next(u for u in shim.users if u.username == "corp-admin")
    assert admin.role == "admin"


def test_every_host_has_ip_and_fqdn():
    shim = shim_from_scenario(SCENARIO, tier="S", seed=0)
    assert shim.hosts
    for h in shim.hosts:
        assert h.ip and h.fqdn.endswith(".corp.example.invalid")
