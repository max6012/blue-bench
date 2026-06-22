"""Bridge-coherence gate for a merged corpus (EF-P4c).

The IT/OT bridge references IT-side hosts (a workstation, the file/db server,
the jump host). Every such reference must resolve to a host that actually
exists in the corpus — otherwise the bridge points at a ghost and an analyst
(or model) can never corroborate the session against host telemetry.

This gate loads the merged corpus's bridge NDJSON, collects every IT-side
endpoint reference (corp IPs and ``*.corp.example.invalid`` FQDNs), and checks
them against the real corpus host set (the EvidenceForge per-host data dirs
plus the scenario's declared IPs). Any reference that is not a real corpus host
is an orphan and fails the gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from blue_bench_generators.merge.scenario_topology import shim_from_scenario

# Corp (IT) address space — OT/plant ranges (10.40.x, plant.example.invalid)
# are bridge *destinations* and are not expected to be IT corpus hosts.
_CORP_IP_PREFIXES = ("10.10.", "10.20.", "10.30.")
_CORP_FQDN_SUFFIX = ".corp.example.invalid"
_IT_REF_FIELDS = ("src_ip", "dst_ip", "id.orig_h", "id.resp_h",
                  "host", "hostname", "Computer", "source_ip")


@dataclass
class CoherenceResult:
    bridge_events: int
    it_refs: set[str] = field(default_factory=set)
    orphans: set[str] = field(default_factory=set)
    corpus_hosts: int = 0

    @property
    def ok(self) -> bool:
        return not self.orphans

    @property
    def vacuous(self) -> bool:
        return not self.it_refs


def _corpus_host_identity(ef_dir: Path, scenario_path: str | Path, tier: str) -> set[str]:
    """Real corpus IT identities: EF per-host data dirs (FQDNs) + scenario IPs/FQDNs."""
    ids: set[str] = set()
    data = ef_dir / "data"
    if data.is_dir():
        ids.update(p.name for p in data.iterdir() if p.is_dir())
    shim = shim_from_scenario(scenario_path, tier=tier, seed=0)
    for h in shim.hosts:
        ids.add(h.fqdn)
        ids.add(h.ip)
    return ids


def check_bridge_coherence(
    ef_dir: str | Path, scenario_path: str | Path, *, tier: str
) -> CoherenceResult:
    """Gate: every IT-side bridge endpoint resolves to a real corpus host."""
    ef_dir = Path(ef_dir)
    hosts = _corpus_host_identity(ef_dir, scenario_path, tier)
    res = CoherenceResult(bridge_events=0, corpus_hosts=len(hosts))

    bridge_dir = ef_dir / "bridge"
    if not bridge_dir.is_dir():
        return res
    for f in sorted(bridge_dir.glob("*.ndjson")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            res.bridge_events += 1
            for k in _IT_REF_FIELDS:
                v = ev.get(k)
                if not isinstance(v, str) or not v:
                    continue
                is_corp = v.startswith(_CORP_IP_PREFIXES) or v.endswith(_CORP_FQDN_SUFFIX)
                if is_corp:
                    res.it_refs.add(v)
                    if v not in hosts:
                        res.orphans.add(v)
    return res
