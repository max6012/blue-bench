"""IEC-60870-5-104 protocol traffic generator.

Consumes an :class:`OTNetwork` and yields Zeek-shaped event dicts for
IEC-104 traffic between controlling-stations (HMIs on the supervisory
VLAN) and controlled-stations (controllers on the control VLAN) over
tcp/2404.

Two output streams (selected by the ``_log`` discriminator key):

* ``conn``  -- one row per (link, hour) summarising the underlying TCP
  flow, with the same field shape as
  ``blue_bench_generators.it_baseline.network_zeek`` conn records.
* ``iec104`` -- one row per APDU (I / S / U frame) carrying APDU type,
  ASDU type id, cause of transmission, common address, information
  object address, and information-object count.

Clean baseline pattern (per link, per hour):

* Link startup (first emitted hour only) -- one U-APDU STARTDT_act ->
  STARTDT_con exchange.
* Cyclic I-frames -- ``M_ME_NA_1`` measured-value reports at
  ``link.polling_hz`` cadence, mostly ``cot=1`` (periodic).
* Spontaneous I-frames -- a sprinkle of ``cot=3`` reports.
* Interrogation cycles -- every ~5 minutes: ``C_IC_NA_1`` (cot=6) ->
  ack (cot=7) -> a burst of ``cot=20`` data reports.
* Operator commands -- ~1% of the volume: ``C_SC_NA_1``,
  ``C_DC_NA_1``, ``C_SE_NA_1``.
* Keep-alive S-frames -- one every ~10 seconds.

Anomaly overlays (applied when an ``AnomalyWindow`` matches the current
hour and ``target_device``):

* ``stopdt_off_hours``               -- U-APDU STOPDT_act outside
  09:00-17:00 weekday business hours.
* ``unknown_station_interrogation``  -- C_IC_NA_1 from a non-HMI IP.
* ``implausible_ioa_write``          -- C_SE_NA_1 with ioa > 1_000_000.
* ``spontaneous_burst``              -- 100x burst of cot=3 M_ME
  reports.

Determinism: ``generate(network, start, end, seed, anomaly_windows)``
is a pure function of its inputs. Per-link RNGs are derived from
``blake2b(seed | master | slave | hour_epoch)``; the module never uses
``random`` at module scope and never relies on the unsalted built-in
``hash()``.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from random import Random
from typing import Iterable, Iterator, Literal

from blue_bench_generators.ot_protocols.topology import (
    PROTOCOL_PORTS,
    Device,
    MasterSlaveLink,
    OTNetwork,
)

log = logging.getLogger(__name__)


# --- constants ------------------------------------------------------------


IEC104_PORT: int = PROTOCOL_PORTS["iec104"]

# Interrogation cycle cadence (one C_IC_NA_1 round trip every N seconds).
_INTERROGATION_PERIOD_S: int = 300  # ~5 minutes

# Keep-alive S-frame cadence.
_KEEPALIVE_PERIOD_S: int = 10

# Operator-command share of all emitted records (target).
_OPERATOR_COMMAND_FRACTION: float = 0.01

# Spontaneous-report (cot=3) probability per cyclic tick. Small so cot=1
# stays dominant in clean baselines.
_SPONTANEOUS_FRACTION: float = 0.05

# Number of data reports emitted following an interrogation activation.
_REPORTS_PER_INTERROGATION: int = 12

# Implausibility threshold for the ``implausible_ioa_write`` anomaly.
_IMPLAUSIBLE_IOA_THRESHOLD: int = 1_000_000

# Multiplier on cyclic rate for the ``spontaneous_burst`` anomaly.
_SPONTANEOUS_BURST_MULTIPLIER: int = 100

# Business hours window for the ``stopdt_off_hours`` anomaly. Weekdays
# only (Mon-Fri). The anomaly is materialised only when the window
# intersects a non-business interval.
_BUSINESS_HOUR_START: int = 9
_BUSINESS_HOUR_END: int = 17  # exclusive

# Operator command ASDU types (cycled deterministically).
_OPERATOR_COMMAND_TYPES: tuple[str, ...] = (
    "C_SC_NA_1",
    "C_DC_NA_1",
    "C_SE_NA_1",
)

# APDU + ASDU type constants the test suite references.
_APDU_I: str = "I"
_APDU_S: str = "S"
_APDU_U: str = "U"


AnomalyKind = Literal[
    "stopdt_off_hours",
    "unknown_station_interrogation",
    "implausible_ioa_write",
    "spontaneous_burst",
]


@dataclass(frozen=True)
class AnomalyWindow:
    """A window over which an IEC-104 anomaly overlay applies.

    The window is half-open ``[start, end)``. ``target_device`` may
    be the name of a controller (controlled-station) the anomaly is
    aimed at; ``None`` means "apply to any IEC-104 link in the
    window".
    """

    kind: AnomalyKind
    start: datetime
    end: datetime
    target_device: str | None = None


# --- internal helpers -----------------------------------------------------


def _ts_str(ts: datetime) -> str:
    """Epoch-seconds string, matching the IT-baseline Zeek convention."""
    return f"{ts.timestamp():.6f}"


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _rng_for_link_hour(seed: int, link: MasterSlaveLink, hour_epoch: int) -> Random:
    """Derive a stable per-(link, hour) RNG.

    Uses blake2b over a labelled payload so independent (seed, link,
    hour) tuples produce independent streams. Avoids the XOR-collision
    pitfalls of bare ``hash()`` / arithmetic mixing.
    """
    payload = f"{seed}|{link.master}|{link.slave}|{hour_epoch}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return Random(int.from_bytes(digest, "little"))


def _uid_for(seed: int, master: str, slave: str, hour_epoch: int, kind: str, idx: int) -> str:
    """Stable Zeek-style UID. ``C`` prefix matches the IT-baseline shape."""
    payload = f"{seed}|{master}|{slave}|{hour_epoch}|{kind}|{idx}".encode()
    return "C" + hashlib.blake2b(payload, digest_size=9).hexdigest()[:12]


def _src_port(rng: Random) -> int:
    return rng.randint(49152, 65535)


def _is_business_hours(ts: datetime) -> bool:
    """True when ``ts`` falls in Mon-Fri 09:00-17:00."""
    if ts.weekday() >= 5:  # 5 = Sat, 6 = Sun
        return False
    return _BUSINESS_HOUR_START <= ts.hour < _BUSINESS_HOUR_END


def _device_lookup(network: OTNetwork) -> dict[str, Device]:
    return {d.name: d for d in network.devices}


def _common_address_for(link: MasterSlaveLink) -> int:
    """Deterministic common address (ASDU addr) per link in [1, 65534]."""
    payload = f"{link.master}->{link.slave}".encode()
    digest = hashlib.blake2b(payload, digest_size=4).digest()
    return (int.from_bytes(digest, "little") % 65533) + 1


def _supervisory_subnet_prefix(network: OTNetwork) -> str:
    """Return the dotted-quad /24 prefix of the supervisory VLAN.

    Used to synthesise "unknown station" source IPs for the
    ``unknown_station_interrogation`` anomaly: an address inside the
    supervisory VLAN that no real HMI / EWS / historian holds.
    """
    for v in network.vlans:
        if v.name == "ot-supervisory":
            cidr = v.subnet  # e.g. "10.40.0.0/24"
            net_only = cidr.split("/", 1)[0]  # "10.40.0.0"
            return net_only.rsplit(".", 1)[0]  # "10.40.0"
    # Defensive fallback: should never happen for OT networks built by
    # ``build_ot_network``.
    return "10.40.0"


def _unknown_supervisory_ip(network: OTNetwork) -> str:
    """Pick a supervisory-VLAN IP that no device holds.

    Walks the /24 from .250 downward to .10 looking for an unused octet.
    Deterministic given the network.
    """
    prefix = _supervisory_subnet_prefix(network)
    used = {d.ip for d in network.devices}
    for octet in range(250, 9, -1):
        candidate = f"{prefix}.{octet}"
        if candidate not in used:
            return candidate
    return f"{prefix}.250"


# --- record emitters ------------------------------------------------------


def _emit_conn_record(
    *,
    ts: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    orig_bytes: int,
    resp_bytes: int,
    uid: str,
) -> dict:
    return {
        "_log": "conn",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": str(src_port),
        "id.resp_h": dst_ip,
        "id.resp_p": str(IEC104_PORT),
        "proto": "tcp",
        "service": "iec104",
        "orig_bytes": str(orig_bytes),
        "resp_bytes": str(resp_bytes),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def _emit_iec104_record(
    *,
    ts: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    apdu_type: str,
    asdu_type: str | None,
    cot: int | None,
    asdu_addr: int | None,
    ioa: int | None,
    ioa_count: int,
    uid: str,
) -> dict:
    return {
        "_log": "iec104",
        "ts": _ts_str(ts),
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": str(src_port),
        "id.resp_h": dst_ip,
        "id.resp_p": str(IEC104_PORT),
        "apdu_type": apdu_type,
        "asdu_type": "" if asdu_type is None else asdu_type,
        "cot": "" if cot is None else str(cot),
        "asdu_addr": "" if asdu_addr is None else str(asdu_addr),
        "ioa": "" if ioa is None else str(ioa),
        "ioa_count": str(ioa_count),
    }


# --- per-link per-hour generation ----------------------------------------


def _generate_link_hour(
    *,
    network: OTNetwork,
    link: MasterSlaveLink,
    devices: dict[str, Device],
    hour_start: datetime,
    hour_end: datetime,
    is_first_hour: bool,
    seed: int,
    matching_anomalies: tuple[AnomalyWindow, ...],
) -> Iterator[dict]:
    """Yield all conn + iec104 records for one link over one hour."""
    master = devices[link.master]
    slave = devices[link.slave]
    if master.vlan != "ot-supervisory" or slave.vlan != "ot-control":
        # Topology guarantees this for ``iec104`` links; defensive only.
        return

    hour_epoch = int(hour_start.timestamp())
    rng = _rng_for_link_hour(seed, link, hour_epoch)
    src_port = _src_port(rng)
    asdu_addr = _common_address_for(link)

    clip_seconds = (hour_end - hour_start).total_seconds()
    if clip_seconds <= 0:
        return

    apdu_records: list[dict] = []

    def _add_apdu(
        ts: datetime,
        apdu_type: str,
        asdu_type: str | None,
        cot: int | None,
        ioa: int | None,
        ioa_count: int,
        *,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        kind_label: str = "apdu",
    ) -> None:
        idx = len(apdu_records)
        uid = _uid_for(seed, link.master, link.slave, hour_epoch, kind_label, idx)
        apdu_records.append(
            _emit_iec104_record(
                ts=ts,
                src_ip=src_ip if src_ip is not None else master.ip,
                src_port=src_port,
                dst_ip=dst_ip if dst_ip is not None else slave.ip,
                apdu_type=apdu_type,
                asdu_type=asdu_type,
                cot=cot,
                asdu_addr=asdu_addr,
                ioa=ioa,
                ioa_count=ioa_count,
                uid=uid,
            )
        )

    # --- link startup (only on the first emitted hour) ------------------
    if is_first_hour:
        startup_ts = hour_start + timedelta(seconds=0.5)
        if startup_ts < hour_end:
            _add_apdu(startup_ts, _APDU_U, None, None, None, 0, kind_label="startup")
            ack_ts = startup_ts + timedelta(milliseconds=50)
            if ack_ts < hour_end:
                _add_apdu(
                    ack_ts,
                    _APDU_U,
                    None,
                    None,
                    None,
                    0,
                    src_ip=slave.ip,
                    dst_ip=master.ip,
                    kind_label="startup",
                )

    # --- cyclic M_ME_NA_1 measured-value reports ------------------------
    base_rate_hz = max(link.polling_hz, 0.0)
    burst_multiplier = 1
    for win in matching_anomalies:
        if win.kind == "spontaneous_burst":
            burst_multiplier = _SPONTANEOUS_BURST_MULTIPLIER
    cyclic_rate_hz = base_rate_hz * burst_multiplier

    if cyclic_rate_hz > 0.0:
        interval_s = 1.0 / cyclic_rate_hz
        # Phase offset deterministic per (link, hour).
        phase = rng.random() * interval_s
        # Cap at a sane upper bound so the burst doesn't OOM tests.
        max_records = int(clip_seconds * cyclic_rate_hz) + 1
        max_records = min(max_records, 200_000)
        # Each cyclic tick picks a deterministic ioa within [1, 32].
        for k in range(max_records):
            offset = phase + k * interval_s
            if offset >= clip_seconds:
                break
            ts = hour_start + timedelta(seconds=offset)
            ioa = (k % 32) + 1
            # Most records cot=1; a sprinkle cot=3.
            is_spontaneous = rng.random() < _SPONTANEOUS_FRACTION
            cot = 3 if is_spontaneous else 1
            _add_apdu(ts, _APDU_I, "M_ME_NA_1", cot, ioa, 1, kind_label="cyclic")

    # --- interrogation cycles every ~5 minutes --------------------------
    if base_rate_hz > 0.0:
        # First interrogation offset within the hour.
        first_offset = (_INTERROGATION_PERIOD_S // 2) + rng.randint(0, 30)
        offset = first_offset
        while offset < clip_seconds:
            ts0 = hour_start + timedelta(seconds=offset)
            # Activation (master -> outstation).
            _add_apdu(ts0, _APDU_I, "C_IC_NA_1", 6, 0, 1, kind_label="interrogation")
            # Activation-confirmation (outstation -> master).
            ts1 = ts0 + timedelta(milliseconds=80)
            if ts1 < hour_end:
                _add_apdu(
                    ts1,
                    _APDU_I,
                    "C_IC_NA_1",
                    7,
                    0,
                    1,
                    src_ip=slave.ip,
                    dst_ip=master.ip,
                    kind_label="interrogation",
                )
            # Burst of cot=20 interrogated-by-station data reports.
            for j in range(_REPORTS_PER_INTERROGATION):
                ts_j = ts0 + timedelta(milliseconds=120 + 40 * j)
                if ts_j >= hour_end:
                    break
                ioa = (j % 16) + 1
                _add_apdu(
                    ts_j,
                    _APDU_I,
                    "M_ME_NA_1",
                    20,
                    ioa,
                    1,
                    src_ip=slave.ip,
                    dst_ip=master.ip,
                    kind_label="interrogation",
                )
            offset += _INTERROGATION_PERIOD_S

    # --- operator commands (~1% of volume) ------------------------------
    if base_rate_hz > 0.0:
        target_op_count = max(
            1, int(len(apdu_records) * _OPERATOR_COMMAND_FRACTION)
        )
        for k in range(target_op_count):
            # Spread roughly evenly across the bucket.
            t_frac = (k + 0.5) / max(1, target_op_count)
            ts = hour_start + timedelta(seconds=t_frac * clip_seconds)
            if ts >= hour_end:
                break
            asdu = _OPERATOR_COMMAND_TYPES[k % len(_OPERATOR_COMMAND_TYPES)]
            ioa = ((k * 3) % 64) + 100
            _add_apdu(ts, _APDU_I, asdu, 6, ioa, 1, kind_label="opcmd")
            # Activation-confirmation back from the outstation.
            ts_ack = ts + timedelta(milliseconds=60)
            if ts_ack < hour_end:
                _add_apdu(
                    ts_ack,
                    _APDU_I,
                    asdu,
                    7,
                    ioa,
                    1,
                    src_ip=slave.ip,
                    dst_ip=master.ip,
                    kind_label="opcmd",
                )

    # --- S-frame keep-alives every ~10 seconds --------------------------
    if base_rate_hz > 0.0:
        offset = float(_KEEPALIVE_PERIOD_S)
        while offset < clip_seconds:
            ts = hour_start + timedelta(seconds=offset)
            _add_apdu(ts, _APDU_S, None, None, None, 0, kind_label="keepalive")
            offset += _KEEPALIVE_PERIOD_S

    # --- anomaly overlays ----------------------------------------------
    for win in matching_anomalies:
        if win.kind == "stopdt_off_hours":
            # Emit a STOPDT_act at the first off-hours moment inside the
            # overlap of (window, hour, non-business).
            overlap_start = max(hour_start, win.start)
            overlap_end = min(hour_end, win.end)
            cursor = overlap_start
            tick = timedelta(minutes=5)
            while cursor < overlap_end:
                if not _is_business_hours(cursor):
                    _add_apdu(
                        cursor,
                        _APDU_U,
                        None,
                        None,
                        None,
                        0,
                        kind_label="stopdt",
                    )
                    break
                cursor = cursor + tick

        elif win.kind == "unknown_station_interrogation":
            overlap_start = max(hour_start, win.start)
            if overlap_start < hour_end and overlap_start < win.end:
                unknown_ip = _unknown_supervisory_ip(network)
                _add_apdu(
                    overlap_start,
                    _APDU_I,
                    "C_IC_NA_1",
                    6,
                    0,
                    1,
                    src_ip=unknown_ip,
                    dst_ip=slave.ip,
                    kind_label="unk-station",
                )

        elif win.kind == "implausible_ioa_write":
            overlap_start = max(hour_start, win.start)
            if overlap_start < hour_end and overlap_start < win.end:
                _add_apdu(
                    overlap_start,
                    _APDU_I,
                    "C_SE_NA_1",
                    6,
                    _IMPLAUSIBLE_IOA_THRESHOLD + 17,
                    1,
                    kind_label="implausible-ioa",
                )

        # ``spontaneous_burst`` was handled above by scaling cyclic rate.

    # --- emit: one conn record per (link, hour), then APDU stream ------
    # Sort APDUs by timestamp for a clean wire-order stream.
    apdu_records.sort(key=lambda r: float(r["ts"]))

    # Sum bytes very roughly: I frames ~70B, S frames ~6B, U frames ~6B.
    orig_bytes = 0
    resp_bytes = 0
    for r in apdu_records:
        sz = 70 if r["apdu_type"] == _APDU_I else 6
        if r["id.orig_h"] == master.ip:
            orig_bytes += sz
        else:
            resp_bytes += sz
    # Conn pairing: emit conn before APDUs at the same flow-start
    # timestamp. UID matches the IT-baseline conn-uid pattern; APDU
    # records carry their own UIDs (not paired by UID -- IEC-104
    # records pair with conn rows by 5-tuple + time, like Zeek's
    # iec104.log).
    if apdu_records:
        conn_uid = _uid_for(seed, link.master, link.slave, hour_epoch, "conn", 0)
        # Anchor the conn record at the first APDU's timestamp so the
        # conn row stays inside ``[start, end)`` even for partial-hour
        # window edges.
        first_apdu_epoch = float(apdu_records[0]["ts"])
        conn_ts = hour_start + timedelta(seconds=first_apdu_epoch - hour_epoch)
        yield _emit_conn_record(
            ts=conn_ts,
            src_ip=master.ip,
            src_port=src_port,
            dst_ip=slave.ip,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            uid=conn_uid,
        )

    for r in apdu_records:
        yield r


# --- public API -----------------------------------------------------------


def generate(
    network: OTNetwork,
    start: datetime,
    end: datetime,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterable[dict]:
    """Yield Zeek-shaped IEC-104 event dicts for ``[start, end)``.

    Args:
        network: OT plant network (devices, VLANs, master-slave links).
            Only links with ``protocol == "iec104"`` are materialised.
        start: window start (inclusive). Naive UTC datetime.
        end:   window end   (exclusive). Naive UTC datetime.
        seed:  RNG seed. Same inputs ALWAYS yield identical output.
        anomaly_windows: optional anomaly overlays applied in addition
            to the clean baseline.

    Yields:
        dicts with the ``_log`` field set to ``conn`` or ``iec104``,
        each carrying the IT-baseline-style ``ts`` (epoch-seconds
        string) plus the documented per-stream field set.
    """
    if end <= start:
        log.info(
            "iec104.generate called with end<=start (%s <= %s); no events emitted",
            end,
            start,
        )
        return

    devices = _device_lookup(network)
    iec_links = [l for l in network.links if l.protocol == "iec104"]
    if not iec_links:
        log.info("iec104.generate: no iec104 links in network; nothing to emit")
        return

    log.info(
        "iec104.generate: tier=%s links=%d start=%s end=%s seed=%d anomalies=%d",
        network.tier,
        len(iec_links),
        start,
        end,
        seed,
        len(anomaly_windows),
    )

    cursor = _hour_floor(start)
    one_hour = timedelta(hours=1)
    first_hour_floor = cursor

    while cursor < end:
        next_hour = cursor + one_hour
        clip_start = max(cursor, start)
        clip_end = min(next_hour, end)
        if (clip_end - clip_start).total_seconds() <= 0:
            cursor = next_hour
            continue
        is_first_hour = cursor == first_hour_floor

        for link in iec_links:
            slave = devices.get(link.slave)
            matching: list[AnomalyWindow] = []
            for win in anomaly_windows:
                if win.end <= clip_start or win.start >= clip_end:
                    continue
                if win.target_device is not None and slave is not None:
                    if win.target_device != slave.name:
                        continue
                matching.append(win)
            matching_tup = tuple(matching)

            for ev in _generate_link_hour(
                network=network,
                link=link,
                devices=devices,
                hour_start=clip_start,
                hour_end=clip_end,
                is_first_hour=is_first_hour,
                seed=seed,
                matching_anomalies=matching_tup,
            ):
                ts_epoch = float(ev["ts"])
                if start.timestamp() <= ts_epoch < end.timestamp():
                    yield ev

        cursor = next_hour
