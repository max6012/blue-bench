"""Modbus/TCP protocol generator for the OT heavy-telemetry suite.

Consumes an ``OTNetwork`` (from ``ot_protocols.topology``) and yields
Zeek-shaped event dicts for Modbus/TCP traffic on tcp/502 between
controllers (masters) and RTUs (slaves).

Output streams
--------------

Two ``_log`` discriminators:

* ``conn``  -- one record per (link, hour). Modbus sessions are long-
  lived; the conn record represents the bearing TCP connection that
  carries an hour of polling traffic. Field set mirrors the Zeek conn
  record shape used in ``it_baseline.network_zeek``.
* ``modbus`` -- one record per Modbus PDU. For a 1 Hz link in a full
  hour that yields 3600 records, each carrying ``func``, ``unit_id``,
  ``address``, ``quantity``, and ``exception``.

Function-code mix in the clean baseline is drawn from a fixed weighted
distribution: FC=3 (Read Holding) 0.70, FC=4 (Read Input) 0.20,
FC=6 (Write Single) 0.08, FC=16 (Write Multiple) 0.02. Anomaly windows
shift this mix in a kind-specific way.

Determinism contract
--------------------

``generate(network, start, end, seed, anomaly_windows)`` is a pure
function of its inputs. Per-link RNG is derived from
``blake2b(f"{seed}|{master}|{slave}|{hour_epoch}", digest_size=8)`` so
the stream is process-independent (no use of bare ``hash()`` or module-
level ``random``). UIDs are derived from the same key shape so each
modbus record's uid pairs exactly with one conn record's uid for that
(link, hour) cell.

Vendor neutrality: only the IEC-style protocol vocabulary -- master,
slave, controller, RTU, unit_id, holding/input register -- appears in
this module.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Literal

from blue_bench_generators.ot_protocols._uid import link_uid
from blue_bench_generators.ot_protocols.topology import (
    Device,
    MasterSlaveLink,
    OTNetwork,
    PROTOCOL_PORTS,
)

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


MODBUS_PORT: int = PROTOCOL_PORTS["modbus"]  # 502

# Clean-baseline function-code mix. Tuples are (cumulative_threshold, fc).
# RNG draw ``r < threshold`` selects the corresponding function code.
# 0.70 FC=3 / 0.90 FC=4 / 0.98 FC=6 / 1.00 FC=16.
_CLEAN_FC_TABLE: tuple[tuple[float, int], ...] = (
    (0.70, 3),
    (0.90, 4),
    (0.98, 6),
    (1.00, 16),
)

# Safety-register address range. Anomaly kind ``safety_register_read``
# targets this band -- the contiguous high holding-register space many
# safety-controller vendors expose for trip thresholds and interlocks.
_SAFETY_REGISTER_START: int = 0xFA00
_SAFETY_REGISTER_END: int = 0xFFFF

# Modbus exception code for "illegal data address" -- returned when a
# slave declines to service a read against a non-existent register.
_EXC_ILLEGAL_DATA_ADDRESS: int = 2

# Per-link conn-record byte estimates. A 1 Hz hour-long Modbus session
# moves roughly 3600 PDU pairs * (~12 B request + ~12 B response). The
# exact figure is not load-bearing; the values just need to be
# realistic and stable.
_CONN_BYTES_ORIG: int = 12 * 3600  # ~43 KB
_CONN_BYTES_RESP: int = 12 * 3600  # ~43 KB


# --- AnomalyWindow ---------------------------------------------------------


AnomalyKind = Literal[
    "out_of_cycle_write",
    "safety_register_read",
    "unit_id_scan",
    "diagnostic_burst",
]


@dataclass(frozen=True)
class AnomalyWindow:
    """Time-bounded modbus-protocol anomaly overlay.

    Attributes:
        kind: which anomaly behaviour to emit.
        start: inclusive start (naive UTC).
        end: exclusive end (naive UTC).
        target_device: name of the device the anomaly targets. For
            ``out_of_cycle_write`` and ``safety_register_read`` this is
            the slave (RTU). For ``unit_id_scan`` and
            ``diagnostic_burst`` it is the slave being probed. ``None``
            means "any device" -- the first matching link in the
            network is used (deterministically by link order).
    """

    kind: AnomalyKind
    start: datetime
    end: datetime
    target_device: str | None = None


# --- internal helpers ------------------------------------------------------


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _ts_str(ts: datetime) -> str:
    return f"{ts.timestamp():.6f}"


def _link_hour_rng(seed: int, link: MasterSlaveLink, hour_epoch: int) -> random.Random:
    """Seed a per-(link, hour) RNG.

    Uses blake2b with an 8-byte digest, little-endian, per the project
    determinism contract. Independent of any other (seed, parts)
    tuple; no XOR collisions; process-salt-free.
    """
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "little"))


def _link_hour_uid(seed: int, link: MasterSlaveLink, hour_epoch: int) -> str:
    """UID shared by the (link, hour) conn record and every modbus PDU
    it carries. Delegates to the canonical ``link_uid`` helper -- same
    key shape as ``_link_hour_rng`` so the conn<->modbus pairing is
    reproducible without holding state across yields."""
    return link_uid(seed, link.master, link.slave, hour_epoch, "uid")


def _ephemeral_port(seed: int, link: MasterSlaveLink, hour_epoch: int) -> int:
    """Pick a stable ephemeral source port for the (link, hour) session."""
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}|port".encode()
    digest = hashlib.blake2b(payload, digest_size=4).digest()
    return 49152 + (int.from_bytes(digest, "little") % (65535 - 49152 + 1))


def _draw_clean_func(rng: random.Random) -> int:
    """Draw a function code from the clean-baseline weighted table."""
    r = rng.random()
    for threshold, fc in _CLEAN_FC_TABLE:
        if r < threshold:
            return fc
    return _CLEAN_FC_TABLE[-1][1]  # numerical safety; r == 1.0


def _devices_by_name(network: OTNetwork) -> dict[str, Device]:
    return {d.name: d for d in network.devices}


def _modbus_links(network: OTNetwork) -> list[MasterSlaveLink]:
    return [l for l in network.links if l.protocol == "modbus"]


# --- record emitters -------------------------------------------------------


def _emit_conn_record(
    *,
    ts: datetime,
    master: Device,
    slave: Device,
    uid: str,
    src_port: int,
) -> dict:
    return {
        "_log": "conn",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": master.ip,
        "id.orig_p": str(src_port),
        "id.resp_h": slave.ip,
        "id.resp_p": str(MODBUS_PORT),
        "proto": "tcp",
        "service": "modbus",
        "orig_bytes": str(_CONN_BYTES_ORIG),
        "resp_bytes": str(_CONN_BYTES_RESP),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def _emit_modbus_record(
    *,
    ts: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    uid: str,
    func: int,
    unit_id: int,
    address: int,
    quantity: int,
    exception: str = "-",
) -> dict:
    return {
        "_log": "modbus",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": str(src_port),
        "id.resp_h": dst_ip,
        "id.resp_p": str(MODBUS_PORT),
        "func": str(func),
        "unit_id": str(unit_id),
        "address": str(address),
        "quantity": str(quantity),
        "exception": exception,
    }


# --- anomaly classification ------------------------------------------------


def _anomalies_active_in_hour(
    anomaly_windows: tuple[AnomalyWindow, ...],
    hour_start: datetime,
    hour_end: datetime,
    link: MasterSlaveLink,
) -> list[AnomalyWindow]:
    """Return anomalies that (a) overlap this hour and (b) target this link.

    A window with ``target_device=None`` is treated as matching every
    link; otherwise the window matches only links whose slave matches
    ``target_device`` (the anomalies in v1 all act on the slave side).
    """
    active: list[AnomalyWindow] = []
    for w in anomaly_windows:
        if w.end <= hour_start or w.start >= hour_end:
            continue
        if w.target_device is not None and w.target_device != link.slave:
            continue
        active.append(w)
    return active


# --- baseline polling walk -------------------------------------------------


def _emit_link_hour_baseline(
    *,
    link: MasterSlaveLink,
    master: Device,
    slave: Device,
    hour_start: datetime,
    window_start: datetime,
    window_end: datetime,
    seed: int,
    uid: str,
    src_port: int,
) -> Iterator[dict]:
    """Walk the polling cycle for one (link, hour).

    For polling_hz=1.0 over a full hour this emits 3600 modbus records
    at t=0,1,2,...,3599 seconds past the hour. Function code at each
    tick is drawn from the clean baseline distribution.
    """
    if link.polling_hz <= 0.0:
        return
    hour_epoch = int(hour_start.timestamp())
    rng = _link_hour_rng(seed, link, hour_epoch)
    period = 1.0 / link.polling_hz
    total_seconds = 3600
    steps = int(total_seconds * link.polling_hz)
    for step in range(steps):
        offset_seconds = step * period
        ts = hour_start + timedelta(seconds=offset_seconds)
        if ts < window_start or ts >= window_end:
            continue
        fc = _draw_clean_func(rng)
        # Address / quantity per FC. Read FCs sweep a contiguous low
        # range that maps to typical input-image scan groups. Writes
        # touch a smaller high-side coil/register surface.
        if fc in (3, 4):
            address = rng.randint(0, 999)
            quantity = rng.choice([10, 16, 20, 32, 64])
        elif fc == 6:
            address = rng.randint(0, 511)
            quantity = 1
        else:  # FC=16
            address = rng.randint(0, 255)
            quantity = rng.choice([2, 4, 8])
        # Unit_id is the slave's logical address. For TCP-front-ended
        # Modbus the unit_id often defaults to 1, but a controller
        # behind a serial-bridge may target unit_ids drawn from the
        # bridged segment. We stamp a stable per-slave unit_id from a
        # hash of the slave name to keep this realistic and
        # deterministic without forcing 1 everywhere.
        unit_id = _stable_unit_id(slave.name)
        yield _emit_modbus_record(
            ts=ts,
            src_ip=master.ip,
            src_port=src_port,
            dst_ip=slave.ip,
            uid=uid,
            func=fc,
            unit_id=unit_id,
            address=address,
            quantity=quantity,
        )


def _stable_unit_id(slave_name: str) -> int:
    """Map a slave name to a stable unit_id in [1, 247].

    Modbus unit_id is the slave address; 1..247 are valid. Hashing the
    name keeps the assignment deterministic and bypasses ``hash()``'s
    process-salt.
    """
    digest = hashlib.blake2b(slave_name.encode(), digest_size=4).digest()
    return 1 + (int.from_bytes(digest, "little") % 247)


# --- anomaly emitters ------------------------------------------------------


def _emit_anomaly_out_of_cycle_write(
    *,
    window: AnomalyWindow,
    link: MasterSlaveLink,
    master: Device,
    slave: Device,
    hour_start: datetime,
    window_start: datetime,
    window_end: datetime,
    seed: int,
    uid: str,
    src_port: int,
) -> Iterator[dict]:
    """Sprinkle additional FC=6 / FC=16 writes inside the anomaly window.

    These ride the same (link, hour) conn record -- the anomaly is the
    *content* of the traffic, not a new connection. Off-cycle means
    the writes appear at fractional-second offsets that do NOT coincide
    with the 1 Hz baseline ticks, so a polling-cadence detector can
    see them as out-of-cycle.
    """
    overlap_start = max(window.start, hour_start, window_start)
    overlap_end = min(window.end, hour_start + timedelta(hours=1), window_end)
    if overlap_end <= overlap_start:
        return
    hour_epoch = int(hour_start.timestamp())
    # Per-anomaly RNG keyed off the window kind too so different anomaly
    # kinds active in the same hour don't share a sequence.
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}|out_of_cycle".encode()
    rng = random.Random(int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "little"))
    # Density: a steady stream of off-cycle writes at twice the
    # baseline poll cadence (2 Hz vs 1 Hz). Clean-baseline FC=6/16
    # share is 0.10; doubling traffic with all-writes shifts the in-
    # window write fraction past 0.50 -- well over the 5x test bar.
    duration = (overlap_end - overlap_start).total_seconds()
    extra_count = int(duration * 2.0)
    for i in range(extra_count):
        # Off-cycle offset: 0.25 + i*0.5 keeps the timestamps clear of
        # the integer-second baseline ticks while doubling cadence.
        offset = 0.25 + (i * 0.5)
        ts = overlap_start + timedelta(seconds=offset)
        if ts < window_start or ts >= window_end:
            continue
        fc = 16 if (i % 4 == 0) else 6
        address = rng.randint(0, 255)
        quantity = rng.choice([2, 4, 8]) if fc == 16 else 1
        yield _emit_modbus_record(
            ts=ts,
            src_ip=master.ip,
            src_port=src_port,
            dst_ip=slave.ip,
            uid=uid,
            func=fc,
            unit_id=_stable_unit_id(slave.name),
            address=address,
            quantity=quantity,
        )


def _emit_anomaly_safety_register_read(
    *,
    window: AnomalyWindow,
    link: MasterSlaveLink,
    master: Device,
    slave: Device,
    network: OTNetwork,
    hour_start: datetime,
    window_start: datetime,
    window_end: datetime,
    seed: int,
) -> Iterator[dict]:
    """Emit reads against the safety-register band from a non-canonical source.

    Source is another controller (not the canonical master for this
    link) -- still on ot-control, so the cross-VLAN rule (ot-control
    <-> ot-field) holds, but the link's canonical master-IP invariant
    breaks. That last fact is the detection signal.

    A separate conn record is yielded for the rogue session, paired
    with the modbus records via a new uid.
    """
    overlap_start = max(window.start, hour_start, window_start)
    overlap_end = min(window.end, hour_start + timedelta(hours=1), window_end)
    if overlap_end <= overlap_start:
        return

    hour_epoch = int(hour_start.timestamp())
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}|safety_register".encode()
    rng = random.Random(int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "little"))

    # Pick a non-canonical controller via the per-hour RNG so multiple
    # safety-register windows against different RTUs spread the rogue
    # source across the controller pool rather than always reusing the
    # first non-master in device order.
    candidates = [
        d for d in network.devices
        if d.role in ("controller", "safety-controller") and d.name != link.master
    ]
    if not candidates:
        return  # no rogue source available; skip emission silently
    rogue = rng.choice(candidates)

    # Distinct uid + source port for the rogue session.
    rogue_uid = link_uid(seed, rogue.name, link.slave, hour_epoch, "safety_uid")
    port_payload = f"{seed}|{rogue.name}|{link.slave}|{hour_epoch}|safety_port".encode()
    rogue_port = 49152 + (
        int.from_bytes(hashlib.blake2b(port_payload, digest_size=4).digest(), "little")
        % (65535 - 49152 + 1)
    )

    # Conn record for the rogue session. ts is the overlap start.
    yield {
        "_log": "conn",
        "ts": _ts_str(overlap_start),
        "uid": rogue_uid,
        "id.orig_h": rogue.ip,
        "id.orig_p": str(rogue_port),
        "id.resp_h": slave.ip,
        "id.resp_p": str(MODBUS_PORT),
        "proto": "tcp",
        "service": "modbus",
        "orig_bytes": "256",
        "resp_bytes": "256",
        "conn_state": "SF",
        "history": "ShADadFf",
    }

    # A handful of reads against the safety band, spaced every 10s.
    duration = (overlap_end - overlap_start).total_seconds()
    probe_count = max(1, int(duration / 10.0))
    for i in range(probe_count):
        ts = overlap_start + timedelta(seconds=i * 10.0)
        if ts < window_start or ts >= window_end:
            continue
        # 50/50 between FC=3 (holding) and FC=4 (input) reads.
        fc = 3 if (i % 2 == 0) else 4
        # Address inside the safety band.
        address = rng.randint(_SAFETY_REGISTER_START, _SAFETY_REGISTER_END)
        quantity = rng.choice([1, 2, 4])
        # Slave does not expose the safety band -> illegal data address.
        exception_str = str(_EXC_ILLEGAL_DATA_ADDRESS)
        yield _emit_modbus_record(
            ts=ts,
            src_ip=rogue.ip,
            src_port=rogue_port,
            dst_ip=slave.ip,
            uid=rogue_uid,
            func=fc,
            unit_id=_stable_unit_id(slave.name),
            address=address,
            quantity=quantity,
            exception=exception_str,
        )


# --- public API ------------------------------------------------------------


def generate(
    network: OTNetwork,
    start: datetime,
    end: datetime,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterable[dict]:
    """Yield Zeek-shaped Modbus/TCP records for ``[start, end)``.

    Args:
        network: the OT plant network from ``build_ot_network``.
        start: window start, naive UTC (inclusive).
        end: window end, naive UTC (exclusive).
        seed: RNG seed -- same inputs produce an identical event list.
        anomaly_windows: optional parametric overlays. Empty tuple
            yields a clean baseline.

    Yields:
        dicts with ``_log`` of ``conn`` or ``modbus``. Conn records
        appear at hour boundaries; modbus records walk the polling
        cycle within each hour. Anomaly windows shift content and (for
        ``safety_register_read``) introduce an additional rogue conn
        record + paired modbus records from a non-canonical source.
    """
    if end <= start:
        log.warning(
            "modbus.generate called with end<=start (%s <= %s); no events emitted",
            end,
            start,
        )
        return

    links = _modbus_links(network)
    if not links:
        log.info("modbus.generate: no modbus links in network; nothing to emit")
        return

    devices = _devices_by_name(network)

    # All v1 anomaly kinds are slave-anchored. A caller naming a
    # master-side device in ``target_device`` would silently match zero
    # links -- indistinguishable from a typo. Surface the mismatch.
    slave_names = {l.slave for l in links}
    master_names = {l.master for l in links}
    for w in anomaly_windows:
        if w.target_device is None:
            continue
        if w.target_device in slave_names:
            continue
        if w.target_device in master_names:
            raise ValueError(
                f"AnomalyWindow(kind={w.kind!r}) target_device={w.target_device!r} "
                f"is a master-side device; v1 anomalies are slave-anchored. "
                f"Pass an RTU name (or None for 'any')."
            )
        log.warning(
            "modbus.generate: AnomalyWindow target_device=%r matches no link slave; "
            "anomaly will emit zero events. Did you typo the device name?",
            w.target_device,
        )

    log.info(
        "modbus.generate: tier=%s links=%d window=[%s, %s) anomalies=%d",
        network.tier,
        len(links),
        start,
        end,
        len(anomaly_windows),
    )

    cursor = _hour_floor(start)
    one_hour = timedelta(hours=1)

    while cursor < end:
        hour_end = cursor + one_hour
        # If the hour does not overlap the window at all, skip.
        if hour_end <= start:
            cursor = hour_end
            continue

        for link in links:
            master = devices[link.master]
            slave = devices[link.slave]
            hour_epoch = int(cursor.timestamp())
            uid = _link_hour_uid(seed, link, hour_epoch)
            src_port = _ephemeral_port(seed, link, hour_epoch)

            # Conn record anchored at the later of (hour_start, window_start)
            # so the first emitted event for the link in a partial-hour
            # bucket isn't dropped by the window filter.
            conn_ts = max(cursor, start)
            if conn_ts < end:
                yield _emit_conn_record(
                    ts=conn_ts,
                    master=master,
                    slave=slave,
                    uid=uid,
                    src_port=src_port,
                )

            # Baseline polling walk.
            yield from _emit_link_hour_baseline(
                link=link,
                master=master,
                slave=slave,
                hour_start=cursor,
                window_start=start,
                window_end=end,
                seed=seed,
                uid=uid,
                src_port=src_port,
            )

            # Anomalies overlapping this (link, hour).
            for w in _anomalies_active_in_hour(anomaly_windows, cursor, hour_end, link):
                if w.kind == "out_of_cycle_write":
                    yield from _emit_anomaly_out_of_cycle_write(
                        window=w,
                        link=link,
                        master=master,
                        slave=slave,
                        hour_start=cursor,
                        window_start=start,
                        window_end=end,
                        seed=seed,
                        uid=uid,
                        src_port=src_port,
                    )
                elif w.kind == "safety_register_read":
                    yield from _emit_anomaly_safety_register_read(
                        window=w,
                        link=link,
                        master=master,
                        slave=slave,
                        network=network,
                        hour_start=cursor,
                        window_start=start,
                        window_end=end,
                        seed=seed,
                    )
                # Other anomaly kinds (unit_id_scan, diagnostic_burst)
                # are reserved for a later revision.

        cursor = hour_end
