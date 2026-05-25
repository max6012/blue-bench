"""IT enterprise baseline generator.

Builds a cohesive synthetic enterprise topology (AD forest, VLANs/IPAM, host
inventory, user inventory, service inventory) that downstream telemetry
generators consume. NO event emission lives in this package's topology module
-- it is pure data + a deterministic builder.

Vendor-neutral terminology throughout; no exercise vocabulary. Same
``(tier, seed)`` ALWAYS produces an identical ``Topology``.

Sub-modules:
    topology  -- dataclasses + ``build_topology(tier, seed)`` builder.
"""

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
    "Host",
    "Service",
    "Topology",
    "User",
    "VLAN",
    "build_topology",
]
