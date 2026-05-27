"""OT host log generator.

Application-level event-log telemetry for the OT-side non-embedded hosts:
HMI consoles, engineering workstations, historians, and the OT firewall.
PLCs / safety controllers / RTUs run vendor RTOS and emit no host logs
here -- their behaviour is captured by the wire-protocol generators
(``modbus``, ``dnp3``, ``iec104``, ``s7comm``).

Six event families share a flat JSONL stream, routed into per-family
files by the composer's ``jsonl_by_log`` writer:

``hmi_alarm``         alarm raised / acknowledged / cleared at HMI
``hmi_operator``      operator setpoint change / tag value write at HMI
``ews_project``       engineering project upload/download at EWS
``historian_audit``   historian point create / modify / retention / delete
``ot_auth``           interactive login at any non-embedded OT host
``ot_usb``            USB device inserted / removed at HMI or EWS

Vendor-neutral schema. Real HMI / historian audit logs are wildly
vendor-specific (Rockwell FactoryTalk, Wonderware InTouch, Siemens
WinCC, Ignition, OSIsoft PI, etc); we adopt an abstract operator-event
schema that any plant operator who has read DOE/CISA ICS post-mortems
will recognise as the canonical actions: alarm-ack, setpoint, project
download, point edit, shared-account login.

Operator-shift model
--------------------

OT operator stations are dense on weekday day shift (07:00-19:00 UTC)
and sparse otherwise. The model is internal to this module -- the
composer's ``ActivityModel`` is for IT user behaviour and is ignored
here, mirroring the ``ot_protocols`` package's treatment.

Anomaly overlays
----------------

Three anomaly kinds layered via ``AnomalyWindow`` (default empty tuple):

* ``off_hours_ews_login``       -- EWS interactive login outside shift
* ``unexpected_project_download`` -- project download to HMI (not controller)
* ``historian_tag_deletion``    -- historian point deletion event

Determinism contract
--------------------

``generate(topology, activity_model, start, end, seed, anomaly_windows)``
is a pure function of its inputs. Per-(host, hour) RNG seeded via
``blake2b(f"{seed}|{host}|{hour_epoch}", digest_size=8)`` so adding or
removing a host cannot reshuffle events on other hosts. The
``activity_model`` argument is accepted for composer-signature
uniformity and ignored.

Composer signature: ``generate(topology, activity_model, start, end,
seed)``. The ``topology`` argument must expose ``.tier`` (and optionally
``.seed``) -- we build our own ``OTNetwork`` from that, identical to the
``ot_protocols`` package.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from blue_bench_generators.ot_hosts.hosts import (
    AnomalyKind,
    AnomalyWindow,
    generate_for_network,
)
from blue_bench_generators.ot_protocols.topology import build_ot_network

__all__ = [
    "AnomalyKind",
    "AnomalyWindow",
    "generate",
    "generate_for_network",
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
    ``OTNetwork`` from ``topology.tier`` (and ``topology.seed`` if
    present), and ignores ``activity_model`` -- operator-shift behaviour
    is modelled internally.
    """
    tier = getattr(topology, "tier", None)
    if tier is None:
        raise TypeError(
            f"ot_hosts.generate: topology object {type(topology).__name__!r} "
            f"has no ``tier`` attribute; expected an IT ``Topology`` dataclass "
            f"or any object exposing ``.tier`` ∈ {{'S','M','L'}}"
        )
    topo_seed = getattr(topology, "seed", seed)
    network = build_ot_network(tier=tier, seed=topo_seed)
    yield from generate_for_network(network, start, end, seed=seed)
