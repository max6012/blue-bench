"""Corpus merger: compose an EvidenceForge IT baseline with Blue-Bench OT +
IT/OT-bridge telemetry into one tiered corpus (EF-P4).

EvidenceForge generates the benign IT telemetry; the OT protocol/host
generators and the IT/OT bridge stay Blue-Bench's. The merger drives those
generators over the EF scenario's own time window and host inventory, so the
OT side and the bridge reference the same hosts EF actually emitted — no
parallel topology, no IP collisions.

The bridge between the two worlds is ``scenario_topology``: it builds a
``Topology``-shaped object straight from the EF scenario YAML (the shared
source of truth for IT host identity) and feeds it to the unchanged OT/bridge
generators.
"""
