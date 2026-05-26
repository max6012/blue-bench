"""OT protocol generator suite.

Cohesive plant-network topology + per-protocol telemetry generators for
Modbus/TCP, DNP3, IEC-104, and Siemens S7Comm. Mirrors the structure of
``it_baseline``: a pure-data topology module that the four per-protocol
generators consume, plus a composer-friendly ``generate()`` entry point
that fans out across the four protocols.

Vendor-neutral terminology throughout. Same ``(tier, seed)`` always
produces an identical ``OTNetwork``.

Sub-modules:
    topology  -- dataclasses + ``build_ot_network(tier, seed)`` builder.
    modbus    -- Modbus/TCP generator.
    dnp3      -- DNP3 generator.
    iec104    -- IEC-60870-5-104 generator.
    s7comm    -- Siemens S7Comm / S7CommPlus generator.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from blue_bench_generators.ot_protocols import dnp3, iec104, modbus, s7comm
from blue_bench_generators.ot_protocols.topology import (
    Device,
    MasterSlaveLink,
    OTNetwork,
    OTVlan,
    build_ot_network,
)

__all__ = [
    "Device",
    "MasterSlaveLink",
    "OTNetwork",
    "OTVlan",
    "build_ot_network",
    "dnp3",
    "generate",
    "iec104",
    "modbus",
    "s7comm",
]


def generate(
    topology,
    activity_model,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Composer-friendly entry point.

    Signature matches the per-source generators in ``it_baseline`` so the
    composer can dispatch uniformly. The OT side builds its own
    ``OTNetwork`` from the IT topology's ``tier`` / ``seed`` and ignores
    ``activity_model`` -- OT protocols are clock-driven from the
    master-slave-link cadence, not IT activity rates.

    Yields events from all four per-protocol generators in series
    (Modbus, DNP3, IEC-104, S7Comm). Each event carries a ``_log``
    discriminator that the composer's Zeek-TSV writer routes into the
    appropriate per-protocol ``.log`` file under ``<output>/ot/``.
    """
    network = build_ot_network(tier=topology.tier, seed=topology.seed)
    yield from modbus.generate(network, start, end, seed=seed)
    yield from dnp3.generate(network, start, end, seed=seed)
    yield from iec104.generate(network, start, end, seed=seed)
    yield from s7comm.generate(network, start, end, seed=seed)
