"""IT enterprise baseline generator.

Builds a cohesive synthetic enterprise topology (AD forest, VLANs/IPAM, host
inventory, user inventory, service inventory) and the seven per-source
telemetry streams that consume it (Zeek, Suricata, Sysmon, EVTX, Linux,
identity, services), plus a tier-driven composer that emits a complete
corpus to disk.

Vendor-neutral terminology throughout. Same ``(tier, seed)`` ALWAYS
produces an identical corpus.

Sub-modules:
    topology  -- dataclasses + ``build_topology(tier, seed)`` builder.
    behavior  -- activity model driving per-source event rates.
    network_zeek, suricata_noise, sysmon, evtx, linux_logs, identity, services
              -- the seven per-source generators.
    composer  -- ``build_corpus(tier, output_dir, seed)`` + tier scaling.
"""

from blue_bench_generators.it_baseline.composer import (
    DEFAULT_START,
    TIER_DURATION_DAYS,
    build_corpus,
)
from blue_bench_generators.it_baseline.topology import (
    ADForest,
    Host,
    Service,
    Topology,
    User,
    VLAN,
    build_topology,
)

__all__ = [
    "ADForest",
    "DEFAULT_START",
    "Host",
    "Service",
    "TIER_DURATION_DAYS",
    "Topology",
    "User",
    "VLAN",
    "build_corpus",
    "build_topology",
]
