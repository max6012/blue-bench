"""Siemens S7Comm / S7CommPlus telemetry generator.

Consumes an ``OTNetwork`` (built by ``ot_protocols.topology``) and yields
Zeek-shaped event dicts for engineering-workstation -> vendor-a
controller traffic over tcp/102 (ISO-on-TCP / TPKT + COTP encapsulation).

S7Comm is event-driven, not cyclic. The baseline pattern is:

* A long-lived HMI/EWS poll session per link per business day (09:00 to
  17:00 local, Mon-Fri). Within a session, ``read_var`` PDUs against the
  DB area at roughly 0.5 Hz; each logical read is a (job, ack_data) pair
  sharing one ``pdu_ref``.
* Operator setpoint writes (``write_var`` jobs) at ~1% of total volume.
* Programming (PG) operations -- ``read_szl`` and ``read_var`` against
  the system area -- only during the maintenance window (first Tuesday
  of the month, 14:00-16:00 local).
* Outside business hours, sparse ``read_var`` health-check polls
  (~1 per hour per link). Each health-check is its own short session.

Output streams:

* ``_log = "conn"`` -- one Zeek conn record per S7Comm session.
* ``_log = "s7comm"`` -- one record per S7Comm PDU.

Field shape mirrors ``it_baseline.network_zeek``: dict per record,
``_log`` discriminator, ``ts`` as epoch-seconds string with 6 decimal
places.

Determinism: ``generate(network, start, end, seed, anomaly_windows)`` is
a pure function of its inputs. Per-link, per-hour RNG is keyed on
(seed, link.master, link.slave, hour_epoch) via blake2b.

Anomaly kinds (selected by ``AnomalyWindow.kind``):

* ``download_block_off_hours`` -- controller logic uploaded into a PLC
  outside the maintenance window. Headline anomaly.
* ``read_szl_from_hmi`` -- ``read_szl`` SSL=0x011C originated by an HMI
  rather than an EWS (only EWS should run that diagnostic).
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


S7_PORT: int = PROTOCOL_PORTS["s7comm"]

# Business-hours session: weekday 09:00 to 17:00 local (naive UTC in our
# corpus convention). Within this window an HMI/EWS keeps a long-lived
# session open against each vendor-a controller.
BUSINESS_HOUR_START: int = 9
BUSINESS_HOUR_END: int = 17

# Read cadence inside a business-hours session (per-link, per-second).
# 0.5 Hz -> one job + one ack_data every 2 seconds.
READ_VAR_HZ: float = 0.5

# Probability that a given read in a session is replaced by a write_var
# (operator setpoint change). 1% of total record volume.
WRITE_VAR_FRACTION: float = 0.01

# Maintenance window inside the first Tuesday of each month.
MAINTENANCE_HOUR_START: int = 14
MAINTENANCE_HOUR_END: int = 16

# Number of read_szl PDUs to emit during the maintenance window per
# (link, maintenance window). PG operations are bursty but bounded.
MAINTENANCE_READ_SZL_PER_LINK: int = 6
# Number of system-area read_var PDUs during the same window.
MAINTENANCE_SYSTEM_READ_VAR_PER_LINK: int = 12

# Off-hours health-check rate. ~1 per hour per link. Each health-check
# is its own short session (conn + one job + one ack_data).
HEALTH_CHECK_PER_HOUR: float = 1.0

# Byte sizes for a session's conn record. Approximate -- a long-lived
# 8-hour session at 0.5 Hz carries thousands of PDUs.
SESSION_ORIG_BYTES_PER_PDU: int = 32
SESSION_RESP_BYTES_PER_PDU: int = 48
HEALTHCHECK_ORIG_BYTES: int = 64
HEALTHCHECK_RESP_BYTES: int = 96

# SSL (system status list) IDs we use:
SSL_ID_OPERATOR_INFO: int = 0x011C


# --- dataclasses -----------------------------------------------------------


@dataclass(frozen=True)
class AnomalyWindow:
    """A time-bounded anomaly overlay for the S7Comm generator.

    Attributes:
        kind: anomaly type. v1 implements ``download_block_off_hours``
            and ``read_szl_from_hmi``; other kinds are accepted by the
            API for forward compatibility and currently emit nothing.
        start: anomaly window start (inclusive, naive UTC).
        end: anomaly window end (exclusive, naive UTC).
        target_device: device name (matches ``Device.name``) to scope
            the anomaly to a specific controller. ``None`` means the
            anomaly fires against the first eligible vendor-a
            controller in the network.
    """

    kind: Literal[
        "download_block_off_hours",
        "upload_block",
        "plc_stop",
        "plc_control_restart",
        "read_szl_from_hmi",
    ]
    start: datetime
    end: datetime
    target_device: str | None = None


# --- helpers ---------------------------------------------------------------


def _ts_str(ts: datetime) -> str:
    return f"{ts.timestamp():.6f}"


def _link_hour_rng(
    seed: int, link: MasterSlaveLink, hour_epoch: int
) -> random.Random:
    """Per-link, per-hour RNG, cross-process-deterministic.

    Uses blake2b over labeled components, avoiding ``hash()`` collisions
    that vary with PYTHONHASHSEED.
    """
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "little"))


def _uid(seed: int, *parts: int | str) -> str:
    """Zeek-style UID. ``C`` prefix matches the IT-baseline convention."""
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "C" + hashlib.blake2b(payload, digest_size=6).hexdigest()


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _day_floor(ts: datetime) -> datetime:
    return ts.replace(hour=0, minute=0, second=0, microsecond=0)


def _is_business_hour(ts: datetime) -> bool:
    if ts.weekday() >= 5:  # Sat/Sun
        return False
    return BUSINESS_HOUR_START <= ts.hour < BUSINESS_HOUR_END


def _first_tuesday(year: int, month: int) -> datetime:
    """Date of the first Tuesday in (year, month) at 00:00 UTC."""
    d = datetime(year, month, 1)
    # weekday(): Mon=0, Tue=1
    offset = (1 - d.weekday()) % 7
    return d + timedelta(days=offset)


def _maintenance_interval(year: int, month: int) -> tuple[datetime, datetime]:
    """Maintenance window for the first Tuesday of (year, month)."""
    base = _first_tuesday(year, month)
    return (
        base.replace(hour=MAINTENANCE_HOUR_START),
        base.replace(hour=MAINTENANCE_HOUR_END),
    )


def _in_maintenance(ts: datetime) -> bool:
    mstart, mend = _maintenance_interval(ts.year, ts.month)
    return mstart <= ts < mend


def _devices_by_name(network: OTNetwork) -> dict[str, Device]:
    return {d.name: d for d in network.devices}


def _s7_links(network: OTNetwork) -> list[MasterSlaveLink]:
    return [l for l in network.links if l.protocol == "s7comm"]


# --- record emitters -------------------------------------------------------


def _emit_conn(
    *,
    ts: datetime,
    uid: str,
    src: Device,
    dst: Device,
    orig_p: int,
    orig_bytes: int,
    resp_bytes: int,
) -> dict:
    return {
        "_log": "conn",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": src.ip,
        "id.orig_p": str(orig_p),
        "id.resp_h": dst.ip,
        "id.resp_p": str(S7_PORT),
        "proto": "tcp",
        "service": "s7comm",
        "orig_bytes": str(orig_bytes),
        "resp_bytes": str(resp_bytes),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def _emit_s7(
    *,
    ts: datetime,
    uid: str,
    src: Device,
    dst: Device,
    orig_p: int,
    rosctr: str,
    function: str,
    pdu_ref: int,
    item_count: int,
) -> dict:
    return {
        "_log": "s7comm",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": src.ip,
        "id.orig_p": str(orig_p),
        "id.resp_h": dst.ip,
        "id.resp_p": str(S7_PORT),
        "rosctr": rosctr,
        "function": function,
        "pdu_ref": pdu_ref,
        "item_count": item_count,
    }


# --- session builders ------------------------------------------------------


def _emit_business_day_session(
    *,
    link: MasterSlaveLink,
    src: Device,
    dst: Device,
    day: datetime,
    seed: int,
) -> Iterator[dict]:
    """Emit one long-lived business-hours session for a (link, day).

    Skips weekends. The session starts at 09:00 and ends at 17:00 local
    (naive UTC). One conn record at session open, then a stream of
    ``read_var`` (job + ack_data) PDU pairs at ~0.5 Hz, with a small
    fraction substituted as ``write_var`` jobs.

    If the day's date falls on the first Tuesday of the month, PG
    operations (``read_szl`` + system-area reads) are folded into the
    14:00-16:00 slice of the same session.
    """
    if day.weekday() >= 5:
        return

    session_start = day.replace(
        hour=BUSINESS_HOUR_START, minute=0, second=0, microsecond=0
    )
    session_end = day.replace(
        hour=BUSINESS_HOUR_END, minute=0, second=0, microsecond=0
    )
    duration_s = int((session_end - session_start).total_seconds())

    # Per-day RNG keyed at session-start hour. Stable across processes.
    rng = _link_hour_rng(seed, link, int(session_start.timestamp()))

    # Stable session-uid + ephemeral source port.
    uid = _uid(seed, "session", link.master, link.slave, int(session_start.timestamp()))
    orig_p = rng.randint(49152, 65535)

    # Number of read cycles in the session at 0.5 Hz.
    n_reads = int(duration_s * READ_VAR_HZ)
    orig_bytes = n_reads * SESSION_ORIG_BYTES_PER_PDU * 2  # job + ack
    resp_bytes = n_reads * SESSION_RESP_BYTES_PER_PDU * 2

    yield _emit_conn(
        ts=session_start,
        uid=uid,
        src=src,
        dst=dst,
        orig_p=orig_p,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
    )

    # Stream of read/write PDUs at 0.5 Hz.
    pdu_ref = rng.randint(1, 0xFFFF)
    for i in range(n_reads):
        ts = session_start + timedelta(seconds=int(i / READ_VAR_HZ))
        # write_var substitution at ~1% of reads.
        if rng.random() < WRITE_VAR_FRACTION:
            yield _emit_s7(
                ts=ts,
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="job",
                function="write_var",
                pdu_ref=pdu_ref,
                item_count=1,
            )
        else:
            yield _emit_s7(
                ts=ts,
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="job",
                function="read_var",
                pdu_ref=pdu_ref,
                item_count=rng.randint(1, 4),
            )
            yield _emit_s7(
                ts=ts + timedelta(milliseconds=20),
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="ack_data",
                function="read_var",
                pdu_ref=pdu_ref,
                item_count=rng.randint(1, 4),
            )
        pdu_ref = (pdu_ref + 1) & 0xFFFF

    # PG ops during the maintenance window, if this day is the first
    # Tuesday of the month. Folded into the same session uid.
    mstart, mend = _maintenance_interval(day.year, day.month)
    if mstart.date() == day.date():
        # read_szl bursts.
        for j in range(MAINTENANCE_READ_SZL_PER_LINK):
            offset = j * (
                (mend - mstart).total_seconds() / MAINTENANCE_READ_SZL_PER_LINK
            )
            ts = mstart + timedelta(seconds=int(offset))
            yield _emit_s7(
                ts=ts,
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="userdata",
                function="read_szl",
                pdu_ref=pdu_ref,
                item_count=SSL_ID_OPERATOR_INFO,
            )
            pdu_ref = (pdu_ref + 1) & 0xFFFF
        # System-area reads during the same window.
        for j in range(MAINTENANCE_SYSTEM_READ_VAR_PER_LINK):
            offset = j * (
                (mend - mstart).total_seconds()
                / MAINTENANCE_SYSTEM_READ_VAR_PER_LINK
            )
            ts = mstart + timedelta(seconds=int(offset)) + timedelta(seconds=1)
            yield _emit_s7(
                ts=ts,
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="job",
                function="read_var",
                pdu_ref=pdu_ref,
                item_count=1,
            )
            yield _emit_s7(
                ts=ts + timedelta(milliseconds=20),
                uid=uid,
                src=src,
                dst=dst,
                orig_p=orig_p,
                rosctr="ack_data",
                function="read_var",
                pdu_ref=pdu_ref,
                item_count=1,
            )
            pdu_ref = (pdu_ref + 1) & 0xFFFF


def _emit_offhours_healthcheck_session(
    *,
    link: MasterSlaveLink,
    src: Device,
    dst: Device,
    hour_start: datetime,
    seed: int,
) -> Iterator[dict]:
    """Emit at most one short off-hours health-check session.

    Each health-check is a tiny session of its own: one conn + one
    (read_var job, read_var ack_data) pair.
    """
    rng = _link_hour_rng(seed, link, int(hour_start.timestamp()))
    # Bernoulli at HEALTH_CHECK_PER_HOUR (1.0 by default; the fraction
    # path still leaves room to dial cadence down).
    if HEALTH_CHECK_PER_HOUR < 1.0 and rng.random() >= HEALTH_CHECK_PER_HOUR:
        return
    # Place at a fixed offset inside the hour for determinism.
    offset_s = rng.randint(60, 3540)
    ts = hour_start + timedelta(seconds=offset_s)

    uid = _uid(seed, "healthcheck", link.master, link.slave, int(ts.timestamp()))
    orig_p = rng.randint(49152, 65535)
    pdu_ref = rng.randint(1, 0xFFFF)

    yield _emit_conn(
        ts=ts,
        uid=uid,
        src=src,
        dst=dst,
        orig_p=orig_p,
        orig_bytes=HEALTHCHECK_ORIG_BYTES,
        resp_bytes=HEALTHCHECK_RESP_BYTES,
    )
    yield _emit_s7(
        ts=ts,
        uid=uid,
        src=src,
        dst=dst,
        orig_p=orig_p,
        rosctr="job",
        function="read_var",
        pdu_ref=pdu_ref,
        item_count=1,
    )
    yield _emit_s7(
        ts=ts + timedelta(milliseconds=20),
        uid=uid,
        src=src,
        dst=dst,
        orig_p=orig_p,
        rosctr="ack_data",
        function="read_var",
        pdu_ref=pdu_ref,
        item_count=1,
    )


# --- anomaly overlays ------------------------------------------------------


def _resolve_target_link(
    network: OTNetwork,
    target_device: str | None,
    fallback_master_role: str = "engineering-workstation",
) -> tuple[MasterSlaveLink, Device, Device] | None:
    """Pick a link to fire an anomaly against.

    If ``target_device`` is supplied, prefers a link whose ``slave``
    matches. Otherwise picks the first S7Comm link in the network.
    Returns ``None`` if no eligible link exists.
    """
    devs = _devices_by_name(network)
    links = _s7_links(network)
    if not links:
        return None
    chosen: MasterSlaveLink | None = None
    if target_device is not None:
        for l in links:
            if l.slave == target_device:
                chosen = l
                break
    if chosen is None:
        chosen = links[0]
    master = devs.get(chosen.master)
    slave = devs.get(chosen.slave)
    if master is None or slave is None:
        return None
    _ = fallback_master_role  # reserved for read_szl_from_hmi
    return chosen, master, slave


def _hmi_for(network: OTNetwork) -> Device | None:
    """Pick a deterministic HMI from the network, if any."""
    for d in network.devices:
        if d.role == "hmi":
            return d
    return None


def _emit_download_block_anomaly(
    *,
    window: AnomalyWindow,
    network: OTNetwork,
    seed: int,
) -> Iterator[dict]:
    """Emit a ``download_block`` PDU outside the maintenance window.

    The PDU rides on its own short session (conn + userdata PDU). The
    test contract is: rosctr="userdata" + function="download_block"
    occurs inside the anomaly window and outside the maintenance window.
    """
    resolved = _resolve_target_link(network, window.target_device)
    if resolved is None:
        return
    link, master, slave = resolved
    # Place the PDU at the midpoint of the anomaly window.
    midpoint = window.start + (window.end - window.start) / 2
    if _in_maintenance(midpoint):
        # Caller specified a window that overlaps maintenance; refuse
        # to emit -- the anomaly definition is "off-hours".
        return
    rng = _link_hour_rng(seed, link, int(_hour_floor(midpoint).timestamp()))
    uid = _uid(seed, "anomaly-dlb", link.master, link.slave, int(midpoint.timestamp()))
    orig_p = rng.randint(49152, 65535)
    pdu_ref = rng.randint(1, 0xFFFF)
    yield _emit_conn(
        ts=midpoint,
        uid=uid,
        src=master,
        dst=slave,
        orig_p=orig_p,
        orig_bytes=4096,
        resp_bytes=1024,
    )
    yield _emit_s7(
        ts=midpoint,
        uid=uid,
        src=master,
        dst=slave,
        orig_p=orig_p,
        rosctr="userdata",
        function="download_block",
        pdu_ref=pdu_ref,
        item_count=1,
    )


def _emit_read_szl_from_hmi_anomaly(
    *,
    window: AnomalyWindow,
    network: OTNetwork,
    seed: int,
) -> Iterator[dict]:
    """Emit a ``read_szl`` PDU originated by an HMI rather than an EWS.

    The anomaly is the source role, not the PDU type -- a baseline
    read_szl during maintenance is normal; an HMI-sourced read_szl is
    not.
    """
    hmi = _hmi_for(network)
    if hmi is None:
        return
    # Find a vendor-a controller (the S7Comm slave universe).
    target: Device | None = None
    if window.target_device is not None:
        for d in network.devices:
            if d.name == window.target_device and d.vendor == "vendor-a":
                target = d
                break
    if target is None:
        s7 = _s7_links(network)
        if not s7:
            return
        devs = _devices_by_name(network)
        target = devs.get(s7[0].slave)
    if target is None:
        return

    midpoint = window.start + (window.end - window.start) / 2
    # Synthesize an HMI-sourced link for the RNG key.
    synth_link = MasterSlaveLink(
        master=hmi.name, slave=target.name, protocol="s7comm", polling_hz=0.0
    )
    rng = _link_hour_rng(seed, synth_link, int(_hour_floor(midpoint).timestamp()))
    uid = _uid(seed, "anomaly-szl", hmi.name, target.name, int(midpoint.timestamp()))
    orig_p = rng.randint(49152, 65535)
    pdu_ref = rng.randint(1, 0xFFFF)
    yield _emit_conn(
        ts=midpoint,
        uid=uid,
        src=hmi,
        dst=target,
        orig_p=orig_p,
        orig_bytes=256,
        resp_bytes=512,
    )
    yield _emit_s7(
        ts=midpoint,
        uid=uid,
        src=hmi,
        dst=target,
        orig_p=orig_p,
        rosctr="userdata",
        function="read_szl",
        pdu_ref=pdu_ref,
        item_count=SSL_ID_OPERATOR_INFO,
    )


_ANOMALY_DISPATCH = {
    "download_block_off_hours": _emit_download_block_anomaly,
    "read_szl_from_hmi": _emit_read_szl_from_hmi_anomaly,
}


# --- public API ------------------------------------------------------------


def generate(
    network: OTNetwork,
    start: datetime,
    end: datetime,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterable[dict]:
    """Yield Zeek-shaped event dicts for S7Comm traffic in [start, end).

    Args:
        network: ``OTNetwork`` built by ``build_ot_network``.
        start: window start (inclusive, naive UTC).
        end: window end (exclusive, naive UTC).
        seed: RNG seed. Same inputs always produce the same records.
        anomaly_windows: optional tuple of ``AnomalyWindow`` overlays
            applied on top of the clean baseline.

    Yields:
        dicts with ``_log`` in {"conn", "s7comm"}.
    """
    if end <= start:
        log.warning(
            "s7comm.generate called with end<=start (%s <= %s); no events",
            end,
            start,
        )
        return

    devs = _devices_by_name(network)
    links = _s7_links(network)
    if not links:
        log.info("s7comm.generate: no s7comm links in network; nothing to emit")
        return

    log.info(
        "s7comm.generate: tier=%s s7_links=%d window=%s..%s",
        network.tier,
        len(links),
        start,
        end,
    )

    # Iterate business-day sessions: one per (link, weekday) overlapping
    # the window.
    day = _day_floor(start)
    one_day = timedelta(days=1)
    while day < end:
        for link in links:
            master = devs.get(link.master)
            slave = devs.get(link.slave)
            if master is None or slave is None:
                continue
            for ev in _emit_business_day_session(
                link=link, src=master, dst=slave, day=day, seed=seed
            ):
                ts = float(ev["ts"])
                if start.timestamp() <= ts < end.timestamp():
                    yield ev
        day = day + one_day

    # Off-hours health-check sessions. One per (link, hour) where the
    # hour is NOT business-hours.
    hour = _hour_floor(start)
    one_hour = timedelta(hours=1)
    while hour < end:
        if not _is_business_hour(hour):
            for link in links:
                master = devs.get(link.master)
                slave = devs.get(link.slave)
                if master is None or slave is None:
                    continue
                for ev in _emit_offhours_healthcheck_session(
                    link=link,
                    src=master,
                    dst=slave,
                    hour_start=hour,
                    seed=seed,
                ):
                    ts = float(ev["ts"])
                    if start.timestamp() <= ts < end.timestamp():
                        yield ev
        hour = hour + one_hour

    # Anomaly overlays.
    for win in anomaly_windows:
        if win.end <= win.start:
            continue
        emitter = _ANOMALY_DISPATCH.get(win.kind)
        if emitter is None:
            # Forward-compat: unimplemented kinds are silently skipped.
            continue
        for ev in emitter(window=win, network=network, seed=seed):
            ts = float(ev["ts"])
            if start.timestamp() <= ts < end.timestamp():
                yield ev
