"""DNP3 protocol event generator for the OT corpus.

Consumes an ``OTNetwork`` (from ``ot_protocols.topology``) and emits
Zeek-shaped event dicts for DNP3 traffic between masters (HMI /
historian / controller) and outstations (controller / RTU) over
tcp/20000.

Two record streams are produced:

* ``_log="conn"``  - one Zeek conn record per (DNP3 link, hour) carrying
  the aggregated flow attributes (orig/resp IP, ports, byte counters,
  conn_state, history).
* ``_log="dnp3"``  - one record per DNP3 transaction, materialised at a
  per-link cycle derived from ``polling_hz``. Each transaction carries
  ``fc_request`` (READ, DIRECT_OPERATE, SELECT, WRITE, ENABLE_/
  DISABLE_UNSOLICITED, COLD_RESTART, WARM_RESTART, UNSOLICITED_MESSAGE),
  ``fc_reply`` (RESPONSE or UNSOLICITED_RESPONSE), and ``iin`` (16-bit
  internal-indications field as lowercase 4-hex-digit string).

Determinism: ``generate(network, start, end, seed, anomaly_windows)``
is a pure function of its inputs. Per-(link, hour) RNG is keyed on a
blake2b digest of ``f"{seed}|{master}|{slave}|{hour_epoch}"``, so the
record stream is reproducible byte-for-byte across runs and processes.

Anomaly overlays are gated by ``AnomalyWindow`` entries. Supported
kinds in v1: ``cold_restart`` and ``iin_device_restart``. Optional
extensions (``unsolicited_response``, ``disable_unsolicited``) are also
implemented and activated when the relevant ``AnomalyWindow`` is
supplied.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Literal

from blue_bench_generators.ot_protocols.topology import (
    Device,
    MasterSlaveLink,
    OTNetwork,
    PROTOCOL_PORTS,
)

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


DNP3_PORT: int = PROTOCOL_PORTS["dnp3"]


# Function-code distribution for clean baseline reads.
_FC_DISTRIBUTION: tuple[tuple[str, float], ...] = (
    ("READ", 0.85),
    ("DIRECT_OPERATE", 0.06),
    ("SELECT", 0.04),
    ("WRITE", 0.05),
)


# IIN bit layout (16 bits). DNP3 IIN.1 is high byte, IIN.2 is low byte.
# We only model a couple of meaningful bits for the corpus.
_IIN_DEVICE_RESTART = 0x0080  # IIN.1 bit 7 - "device restart"
_IIN_NONE = 0x0000


# Average byte counts for the (link, hour) conn aggregate. Vendor
# implementations vary widely; these values give Zeek conn records a
# plausible non-zero size without pretending precision we don't have.
_CONN_ORIG_BYTES_PER_TRANSACTION: int = 24
_CONN_RESP_BYTES_PER_TRANSACTION: int = 64


# --- dataclasses ----------------------------------------------------------


@dataclass(frozen=True)
class AnomalyWindow:
    """A timed overlay altering DNP3 emission for a target device.

    Attributes:
        kind: which anomaly shape to apply.
            * ``cold_restart`` - emit COLD_RESTART or WARM_RESTART
              requests from a non-engineering source against the
              ``target_device`` outstation during the window.
            * ``disable_unsolicited`` - emit DISABLE_UNSOLICITED at the
              window timestamp(s) against the ``target_device``.
            * ``unsolicited_response`` - emit UNSOLICITED_MESSAGE
              records from a non-enrolled master/outstation pair where
              the canonical link does not exist. ``target_device`` (if
              given) names the slave outstation.
            * ``iin_device_restart`` - normal READ transactions but
              with the IIN device-restart bit asserted, for the
              ``target_device``.
        start: window start (inclusive, naive UTC).
        end:   window end (exclusive, naive UTC).
        target_device: device name (``Device.name``) the overlay scopes
            to. ``None`` means "any matching link in the window".
    """

    kind: Literal[
        "unsolicited_response",
        "cold_restart",
        "disable_unsolicited",
        "iin_device_restart",
    ]
    start: datetime
    end: datetime
    target_device: str | None = None


# --- internal helpers -----------------------------------------------------


def _rng_for_link_hour(
    seed: int, link: MasterSlaveLink, hour_epoch: int
) -> random.Random:
    """Build the per-(link, hour) RNG using a blake2b digest."""
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "little"))


def _ts_str(epoch: float) -> str:
    return f"{epoch:.6f}"


def _uid(seed: int, *parts: int | str) -> str:
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "C" + hashlib.sha256(payload).hexdigest()[:12]


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _devices_by_name(network: OTNetwork) -> dict[str, Device]:
    return {d.name: d for d in network.devices}


def _pick_fc(rng: random.Random) -> str:
    """Sample a function-code request from the clean baseline distribution."""
    r = rng.random()
    cum = 0.0
    for fc, p in _FC_DISTRIBUTION:
        cum += p
        if r < cum:
            return fc
    return _FC_DISTRIBUTION[-1][0]


def _iin_str(bits: int) -> str:
    return f"0x{bits & 0xFFFF:04x}"


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randint(49152, 65535)


# --- record emitters ------------------------------------------------------


def _emit_conn_record(
    *,
    ts_epoch: float,
    master: Device,
    slave: Device,
    orig_port: int,
    uid: str,
    transaction_count: int,
) -> dict:
    orig_bytes = transaction_count * _CONN_ORIG_BYTES_PER_TRANSACTION
    resp_bytes = transaction_count * _CONN_RESP_BYTES_PER_TRANSACTION
    return {
        "_log": "conn",
        "ts": _ts_str(ts_epoch),
        "uid": uid,
        "id.orig_h": master.ip,
        "id.orig_p": str(orig_port),
        "id.resp_h": slave.ip,
        "id.resp_p": str(DNP3_PORT),
        "proto": "tcp",
        "service": "dnp3",
        "orig_bytes": str(orig_bytes),
        "resp_bytes": str(resp_bytes),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def _emit_dnp3_record(
    *,
    ts_epoch: float,
    master: Device,
    slave: Device,
    orig_port: int,
    uid: str,
    fc_request: str,
    fc_reply: str,
    iin_bits: int,
) -> dict:
    return {
        "_log": "dnp3",
        "ts": _ts_str(ts_epoch),
        "uid": uid,
        "id.orig_h": master.ip,
        "id.orig_p": str(orig_port),
        "id.resp_h": slave.ip,
        "id.resp_p": str(DNP3_PORT),
        "fc_request": fc_request,
        "fc_reply": fc_reply,
        "iin": _iin_str(iin_bits),
    }


# --- anomaly helpers ------------------------------------------------------


def _windows_overlapping(
    windows: tuple[AnomalyWindow, ...],
    bucket_start: datetime,
    bucket_end: datetime,
) -> list[AnomalyWindow]:
    return [w for w in windows if w.start < bucket_end and w.end > bucket_start]


def _link_targeted(
    link: MasterSlaveLink, w: AnomalyWindow
) -> bool:
    """True if this overlay applies to this link.

    Restart-style overlays (``cold_restart``, ``disable_unsolicited``,
    ``iin_device_restart``) describe an *outstation* event: the target
    must be the slave of the link, otherwise the overlay would fire on
    the wrong side of a (master, target-also-acts-as-master) device
    such as a controller polling RTUs. ``target_device=None`` matches
    every link.
    """
    if w.target_device is None:
        return True
    if w.kind in (
        "cold_restart",
        "disable_unsolicited",
        "iin_device_restart",
    ):
        return link.slave == w.target_device
    return link.master == w.target_device or link.slave == w.target_device


# --- per-link, per-hour emission -----------------------------------------


def _emit_link_hour(
    *,
    link: MasterSlaveLink,
    devices: dict[str, Device],
    bucket_start: datetime,
    bucket_end: datetime,
    seed: int,
    overlays: tuple[AnomalyWindow, ...],
) -> Iterator[dict]:
    """Emit conn + dnp3 records for one DNP3 link during one bucket."""
    master = devices.get(link.master)
    slave = devices.get(link.slave)
    if master is None or slave is None:
        return
    hour_epoch = int(bucket_start.timestamp())
    rng = _rng_for_link_hour(seed, link, hour_epoch)

    orig_port = _ephemeral_port(rng)
    uid = _uid(seed, "dnp3", link.master, link.slave, hour_epoch)

    bucket_seconds = (bucket_end - bucket_start).total_seconds()
    if bucket_seconds <= 0:
        return

    # Number of DNP3 transactions inside this bucket. polling_hz is
    # reads-per-second; bucket_seconds is the actual interval length so
    # partial buckets at window edges scale proportionally.
    expected = link.polling_hz * bucket_seconds
    transaction_count = int(round(expected))

    # Per-bucket overlay decisions: which kinds apply to THIS link?
    bucket_overlays = [w for w in overlays if _link_targeted(link, w)]
    iin_restart_active = any(
        w.kind == "iin_device_restart" for w in bucket_overlays
    )
    cold_restart_active = any(
        w.kind == "cold_restart" for w in bucket_overlays
    )
    disable_unsol_active = any(
        w.kind == "disable_unsolicited" for w in bucket_overlays
    )

    # Build transaction list deterministically. Each transaction picks a
    # function code from the baseline distribution; overlays may inject
    # one or more anomalous transactions on top of the baseline stream.
    records: list[dict] = []

    if transaction_count > 0:
        # Evenly-spaced timestamps across the bucket (deterministic).
        step = bucket_seconds / transaction_count
        for i in range(transaction_count):
            t_epoch = bucket_start.timestamp() + step * (i + 0.5)
            if not (bucket_start.timestamp() <= t_epoch < bucket_end.timestamp()):
                # Clamp into the bucket interval; can happen with float
                # rounding at the upper edge.
                t_epoch = min(
                    max(t_epoch, bucket_start.timestamp()),
                    bucket_end.timestamp() - 1e-6,
                )
            fc = _pick_fc(rng)
            iin = _IIN_DEVICE_RESTART if iin_restart_active else _IIN_NONE
            records.append(
                _emit_dnp3_record(
                    ts_epoch=t_epoch,
                    master=master,
                    slave=slave,
                    orig_port=orig_port,
                    uid=uid,
                    fc_request=fc,
                    fc_reply="RESPONSE",
                    iin_bits=iin,
                )
            )

    # cold_restart overlay: inject COLD_RESTART or WARM_RESTART against
    # this slave. Choice between cold and warm is RNG-driven and stable.
    if cold_restart_active:
        choice = "COLD_RESTART" if rng.random() < 0.5 else "WARM_RESTART"
        t_epoch = bucket_start.timestamp() + bucket_seconds * 0.25
        records.append(
            _emit_dnp3_record(
                ts_epoch=t_epoch,
                master=master,
                slave=slave,
                orig_port=orig_port,
                uid=uid,
                fc_request=choice,
                fc_reply="RESPONSE",
                # The outstation reports restart in its reply IIN.
                iin_bits=_IIN_DEVICE_RESTART,
            )
        )

    if disable_unsol_active:
        t_epoch = bucket_start.timestamp() + bucket_seconds * 0.5
        records.append(
            _emit_dnp3_record(
                ts_epoch=t_epoch,
                master=master,
                slave=slave,
                orig_port=orig_port,
                uid=uid,
                fc_request="DISABLE_UNSOLICITED",
                fc_reply="RESPONSE",
                iin_bits=_IIN_NONE,
            )
        )

    if records:
        # Emit the conn aggregate first at bucket_start (mirrors Zeek
        # behaviour where the conn record carries the connection's first
        # observed timestamp).
        yield _emit_conn_record(
            ts_epoch=bucket_start.timestamp(),
            master=master,
            slave=slave,
            orig_port=orig_port,
            uid=uid,
            transaction_count=len(records),
        )
        for rec in records:
            yield rec


def _emit_unsolicited_overlay(
    *,
    network: OTNetwork,
    bucket_start: datetime,
    bucket_end: datetime,
    seed: int,
    window: AnomalyWindow,
) -> Iterator[dict]:
    """Emit UNSOLICITED_MESSAGE records from a non-enrolled outstation.

    A "non-enrolled" pair is one where no canonical DNP3 link exists
    between the chosen master and the chosen outstation. We pick:

    * outstation = ``window.target_device`` if given and present in the
      network, otherwise the first controller in the device list.
    * master     = the first HMI or historian that does NOT have a
      canonical DNP3 link to that outstation. If every HMI/historian is
      already enrolled with the outstation, we skip emission (the
      anomaly is meaningless in that topology).

    Direction-of-flow remains supervisory -> control (HMI/historian to
    controller) so the no-out-of-VLAN invariant holds.
    """
    devices = _devices_by_name(network)
    # Pick the outstation.
    target_name = window.target_device
    outstation: Device | None = None
    if target_name is not None and target_name in devices:
        candidate = devices[target_name]
        if candidate.role in ("controller", "safety-controller", "rtu"):
            outstation = candidate
    if outstation is None:
        for d in network.devices:
            if d.role == "controller":
                outstation = d
                break
    if outstation is None:
        return

    # An RTU as the outstation would force a supervisory -> field flow,
    # which crosses two VLAN boundaries. Restrict the unsolicited
    # overlay to controllers so the supervisory -> control invariant
    # holds.
    if outstation.role == "rtu":
        return

    # Find an enrolled master set for this outstation.
    enrolled_masters = {
        link.master
        for link in network.links
        if link.protocol == "dnp3" and link.slave == outstation.name
    }
    # Prefer an HMI / historian NOT enrolled with this outstation. In
    # the canonical topology every HMI / historian polls every
    # controller, so fall back to an engineering workstation: it sits
    # on the supervisory VLAN (preserving the supervisory <-> control
    # invariant) and has no DNP3 link to any controller, making it a
    # textbook "non-enrolled" master for this overlay.
    master: Device | None = None
    for d in network.devices:
        if d.role not in ("hmi", "historian"):
            continue
        if d.name in enrolled_masters:
            continue
        master = d
        break
    if master is None:
        for d in network.devices:
            if d.role == "engineering-workstation":
                master = d
                break
    if master is None:
        return

    # RNG keyed off a synthetic "link" so the overlay is deterministic.
    synthetic_link = MasterSlaveLink(
        master=master.name,
        slave=outstation.name,
        protocol="dnp3",
        polling_hz=0.0,
    )
    hour_epoch = int(bucket_start.timestamp())
    rng = _rng_for_link_hour(seed, synthetic_link, hour_epoch)
    orig_port = _ephemeral_port(rng)
    uid = _uid(seed, "dnp3-unsol", master.name, outstation.name, hour_epoch)

    # Emit a single unsolicited burst in the middle of the bucket.
    bucket_seconds = (bucket_end - bucket_start).total_seconds()
    t_epoch = bucket_start.timestamp() + bucket_seconds * 0.5

    yield _emit_conn_record(
        ts_epoch=bucket_start.timestamp(),
        master=master,
        slave=outstation,
        orig_port=orig_port,
        uid=uid,
        transaction_count=1,
    )
    yield _emit_dnp3_record(
        ts_epoch=t_epoch,
        master=master,
        slave=outstation,
        orig_port=orig_port,
        uid=uid,
        fc_request="UNSOLICITED_MESSAGE",
        fc_reply="UNSOLICITED_RESPONSE",
        iin_bits=_IIN_DEVICE_RESTART,
    )


# --- public API ----------------------------------------------------------


def generate(
    network: OTNetwork,
    start: datetime,
    end: datetime,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterable[dict]:
    """Yield Zeek-shaped event dicts for DNP3 traffic.

    Iterates hours in ``[start, end)``; for each DNP3 link emits one
    conn record plus ``round(polling_hz * bucket_seconds)`` dnp3
    transaction records. Anomaly overlays activate when their window
    intersects the current bucket.

    Args:
        network: the OT topology produced by ``build_ot_network``.
        start: window start (inclusive, naive UTC).
        end:   window end (exclusive, naive UTC).
        seed:  RNG seed. Same inputs always yield the same stream.
        anomaly_windows: optional ``AnomalyWindow`` tuple. Each window
            applies its kind to matching links inside ``[w.start,
            w.end)``.

    Yields:
        Zeek-shaped dicts with ``_log`` in ``{"conn", "dnp3"}``.
    """
    if end <= start:
        log.warning(
            "dnp3.generate called with end<=start (%s <= %s); no events emitted",
            end,
            start,
        )
        return

    devices = _devices_by_name(network)
    dnp3_links = tuple(link for link in network.links if link.protocol == "dnp3")
    if not dnp3_links:
        log.info("dnp3.generate: no DNP3 links in network; nothing to emit")
        return

    log.info(
        "dnp3.generate: tier=%s links=%d window=%s..%s anomalies=%d",
        network.tier,
        len(dnp3_links),
        start.isoformat(),
        end.isoformat(),
        len(anomaly_windows),
    )

    cursor = _hour_floor(start)
    one_hour = timedelta(hours=1)

    while cursor < end:
        next_hour = cursor + one_hour
        clip_start = max(cursor, start)
        clip_end = min(next_hour, end)
        if (clip_end - clip_start).total_seconds() <= 0:
            cursor = next_hour
            continue

        overlays = tuple(
            _windows_overlapping(anomaly_windows, clip_start, clip_end)
        )

        # Sort links deterministically by (master, slave, polling_hz)
        # so the output stream is stable across runs.
        sorted_links = sorted(
            dnp3_links, key=lambda l: (l.master, l.slave, l.polling_hz)
        )

        for link in sorted_links:
            for ev in _emit_link_hour(
                link=link,
                devices=devices,
                bucket_start=clip_start,
                bucket_end=clip_end,
                seed=seed,
                overlays=overlays,
            ):
                if _in_window(ev, start, end):
                    yield ev

        # unsolicited_response overlay is detached from canonical
        # links: it synthesises a non-enrolled master/outstation pair.
        for w in overlays:
            if w.kind != "unsolicited_response":
                continue
            for ev in _emit_unsolicited_overlay(
                network=network,
                bucket_start=clip_start,
                bucket_end=clip_end,
                seed=seed,
                window=w,
            ):
                if _in_window(ev, start, end):
                    yield ev

        cursor = next_hour


def _in_window(event: dict, start: datetime, end: datetime) -> bool:
    ts_epoch = float(event["ts"])
    return start.timestamp() <= ts_epoch < end.timestamp()
