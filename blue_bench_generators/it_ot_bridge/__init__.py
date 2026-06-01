"""IT/OT bridge event generator.

Emits matched-pair telemetry at the legitimate IT-OT seam so a given
session (a user pivoting from corp to OT, a BI tool reading the
historian, a periodic config backup) leaves correlated records on both
sides of the boundary -- IT-side network/host logs AND OT-side host
logs -- tied together by a shared ``bridge_session_uid``.

Three normal session kinds and three anomalous session kinds:

Normal:
    jump_to_ews            Corp user -> jump-host (SSH) -> EWS (RDP). Lands
                           in linux/auth.log on jump-host, zeek conn on
                           both legs, ot_hosts/ot_auth on EWS.
    historian_bi_read      Corp BI host -> historian (HTTPS). Lands in
                           zeek conn on both sides (IT-side zeek sees the
                           outbound; OT-side ot/conn.log sees the inbound
                           with bridge_session_uid).
    ews_config_backup      EWS -> corp file share. Lands in ot/conn.log
                           outbound + IT-side zeek conn inbound.

Anomalous (via AnomalyWindow tuple, never in baseline):
    jump_host_bypass            Corp -> EWS direct, NO jump-host auth.
    unexpected_corp_to_ot       Corp workstation -> OT controller directly.
    historian_external_replication  Historian -> RFC5737 external dst.

Cross-source emission contract
------------------------------

Unlike the other generators, the bridge fans out events across multiple
existing source streams. Each event carries a ``_source`` discriminator
naming the destination source directory (``linux``, ``zeek``, ``ot``,
``ot_hosts``). The composer strips ``_source`` before handing the event
to the appropriate writer, so downstream consumers see only the natural
schema of each stream.

Matched-pair correlation: every event from a session carries
``bridge_session_uid`` (``B`` + 12 hex). For zeek conn records this is
an additional column alongside the standard ``uid``; the bridge does
NOT overload ``uid`` (which is per-connection in real Zeek).

Carve-out for ``linux/auth.log``
--------------------------------

The composer's syslog text writer drops every dict key except the
formatted message, so ``bridge_session_uid`` as a dict field does not
survive serialisation for the auth.log stream. The bridge appends
``session=<bridge_session_uid>`` to the SSH ``Accepted publickey``
message so cross-stream consumers can still correlate via the raw
auth.log text. The SSH key fingerprint in the same message is
deterministically derived from ``bridge_session_uid`` using the same
43-char alphabet as the natural sshd record, so bridge auth records
are length-indistinguishable from natural ones (no "short fingerprint"
detection shortcut).

Determinism: per-session blake2b-derived RNG seeded from
``(seed, kind, session_idx)``. Same ``(topology, start, end, seed,
anomaly_windows)`` always produces an identical event stream.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from blue_bench_generators.it_ot_bridge.bridge import (
    AnomalyKind,
    AnomalyWindow,
    BridgeSession,
    generate_for_topologies,
    session_kind_counts,
)
from blue_bench_generators.ot_protocols.topology import build_ot_network

__all__ = [
    "AnomalyKind",
    "AnomalyWindow",
    "BridgeSession",
    "generate",
    "generate_for_topologies",
    "session_kind_counts",
]


def generate(
    topology,
    activity_model,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Composer-friendly entry point.

    Signature matches the per-source generators in ``it_baseline``. The
    bridge builds the OT network from ``topology.tier`` / ``topology.seed``
    and pairs IT and OT devices internally. ``activity_model`` is
    accepted for signature uniformity and ignored -- session scheduling
    is event-driven, not rate-driven.

    Each yielded event carries a ``_source`` field naming the
    destination source directory; the composer is responsible for
    routing.
    """
    tier = getattr(topology, "tier", None)
    if tier is None:
        raise TypeError(
            f"it_ot_bridge.generate: topology object "
            f"{type(topology).__name__!r} has no ``tier`` attribute; "
            f"expected an IT ``Topology`` dataclass or any object "
            f"exposing ``.tier`` ∈ {{'S','M','L'}}"
        )
    topo_seed = getattr(topology, "seed", seed)
    ot_network = build_ot_network(tier=tier, seed=topo_seed)
    yield from generate_for_topologies(topology, ot_network, start, end, seed=seed)
