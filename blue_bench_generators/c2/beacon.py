"""Deterministic beacon-event stream generator.

Given a profile + a target host + a list of callback targets + a time
window + a seed, produces a sequence of ``BeaconEvent`` records. Each
beacon carries:

    * ``sequence`` -- monotonic per-stream counter (deterministic per seed)
    * ``timestamp`` -- UTC datetime
    * ``src_ip`` -- the target host (RFC1918 by convention)
    * ``src_port`` -- ephemeral high port, deterministic per sequence
    * ``dst_ip`` -- one of the callbacks (round-robin under jitter)
    * ``dst_port`` -- 443 for https, 80 for http, 53 for dns
    * ``payload_size_bytes`` -- sampled from the profile's payload distribution

Beacon timing follows the profile's mean + jitter. We use a uniform jitter
window around the mean: each interval is sampled from
``[mean*(1-j), mean*(1+j)]``. No long-tail distribution -- the goal is a
predictable, statistically-distinguishable cadence between commodity and
stealth, not adversarial realism.

This module is PURE: no IO, no subprocess. Tests can drive it directly.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from blue_bench_generators.c2.profiles import C2Profile

log = logging.getLogger(__name__)


_DEFAULT_DEST_PORTS = {
    "http": 80,
    "https": 443,
    "dns": 53,
}


@dataclass(frozen=True)
class BeaconEvent:
    """One beacon callback.

    Times are UTC. Payload bytes are NOT included (would be random and
    cost a lot of memory); ``payload_size_bytes`` records what would be
    sent so emitters can synthesise the right-sized random data
    on-the-fly.
    """

    sequence: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport_proto: str  # "tcp" or "udp"
    payload_size_bytes: int


def _ephemeral_port(rng: random.Random) -> int:
    """Pick a deterministic ephemeral src port from 49152-65535."""
    return rng.randint(49152, 65535)


def _sample_interval(profile: C2Profile, rng: random.Random) -> float:
    """Sample one inter-beacon interval (seconds)."""
    mean = profile.beacon_interval_seconds
    j = profile.beacon_jitter_fraction
    low = mean * (1.0 - j)
    high = mean * (1.0 + j)
    return rng.uniform(low, high)


def _sample_payload_size(profile: C2Profile, rng: random.Random) -> int:
    """Sample one payload size (bytes)."""
    mean = profile.payload_size_mean_bytes
    j = profile.payload_size_jitter_fraction
    low = max(1, int(mean * (1.0 - j)))
    high = max(low + 1, int(mean * (1.0 + j)))
    return rng.randint(low, high)


def generate_beacons(
    *,
    profile: C2Profile,
    target_host_ip: str,
    callback_targets: list[str],
    start_time: datetime,
    duration_seconds: int,
    seed: int,
) -> list[BeaconEvent]:
    """Produce a deterministic list of ``BeaconEvent`` for one stream.

    Args:
        profile: a ``CommodityProfile`` or ``StealthProfile``.
        target_host_ip: the internal host this beacon stream originates
            from. Convention: an RFC1918 address.
        callback_targets: at least one C2 destination IP. Multiple values
            rotate across beacons.
        start_time: first beacon is scheduled at ``start_time + first_interval``
            (i.e. the first interval is drawn BEFORE the first beacon, not
            zero-offset). UTC.
        duration_seconds: stop generating once the next scheduled beacon
            would land beyond ``start_time + duration_seconds``.
        seed: seeds the RNG. Same seed + same inputs => same output.

    Returns:
        Empty list if the duration is too short for even one beacon's mean
        interval (no exceptions for short windows; caller decides whether
        zero events is acceptable).
    """
    if not callback_targets:
        raise ValueError("callback_targets must contain at least one IP")
    if duration_seconds < 0:
        raise ValueError("duration_seconds must be >= 0")
    if start_time.tzinfo is None:
        raise ValueError("start_time must be timezone-aware (UTC expected)")
    start_utc = start_time.astimezone(timezone.utc)
    end_utc = start_utc + timedelta(seconds=duration_seconds)

    rng = random.Random(seed)
    transport_proto = "udp" if profile.transport == "dns" else "tcp"
    dst_port = _DEFAULT_DEST_PORTS[profile.transport]

    beacons: list[BeaconEvent] = []
    cursor = start_utc
    sequence = 0
    # Safety cap: if a misconfigured profile would loop forever, bail
    # loudly. 100k beacons is generous; commodity 60s for 24h is 1440.
    safety_cap = 100_000

    while True:
        interval = _sample_interval(profile, rng)
        cursor = cursor + timedelta(seconds=interval)
        if cursor > end_utc:
            break
        sequence += 1
        if sequence > safety_cap:
            raise RuntimeError(
                f"beacon stream exceeded safety cap of {safety_cap}; "
                f"profile {profile.name!r} interval {profile.beacon_interval_seconds}s "
                f"is too tight for duration {duration_seconds}s"
            )
        dst_ip = callback_targets[(sequence - 1) % len(callback_targets)]
        src_port = _ephemeral_port(rng)
        payload = _sample_payload_size(profile, rng)
        beacons.append(BeaconEvent(
            sequence=sequence,
            timestamp=cursor,
            src_ip=target_host_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            transport_proto=transport_proto,
            payload_size_bytes=payload,
        ))
    log.info(
        "generated %d beacons (profile=%s, duration=%ds)",
        len(beacons),
        profile.name,
        duration_seconds,
    )
    return beacons
