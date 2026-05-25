"""Beacon-stream generator -- determinism, cadence, jitter."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.beacon import BeaconEvent, generate_beacons


START = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)
CALLBACKS = ["203.0.113.42", "203.0.113.99"]
TARGET = "10.42.0.5"


def _run(preset_name: str, duration_s: int, seed: int = 1234) -> list[BeaconEvent]:
    return generate_beacons(
        profile=profiles.get_preset(preset_name),
        target_host_ip=TARGET,
        callback_targets=CALLBACKS,
        start_time=START,
        duration_seconds=duration_s,
        seed=seed,
    )


def test_determinism_same_seed_same_output():
    a = _run("cobalt-strike-default", duration_s=3600, seed=42)
    b = _run("cobalt-strike-default", duration_s=3600, seed=42)
    assert a == b
    assert len(a) > 0


def test_determinism_different_seed_different_output():
    a = _run("cobalt-strike-default", duration_s=3600, seed=1)
    b = _run("cobalt-strike-default", duration_s=3600, seed=2)
    assert a != b


def test_commodity_produces_far_more_beacons_than_stealth():
    # Same 24-hour window. Cobalt Strike default: mean 60s
    # (~1440 beacons in 24h). Stealth lotl-https-cloudfront: mean 14400s
    # (~6 beacons in 24h). Per advisor: keep the assertion loose.
    window = 86400
    commodity = _run("cobalt-strike-default", duration_s=window)
    stealth = _run("lotl-https-cloudfront", duration_s=window)
    assert len(commodity) > 50 * max(1, len(stealth)), (
        f"commodity={len(commodity)} stealth={len(stealth)} -- "
        f"commodity must dominate beacon count"
    )


def test_stealth_jitter_window_wider_than_commodity():
    commodity_p = profiles.get_preset("cobalt-strike-default")
    stealth_p = profiles.get_preset("lotl-https-cloudfront")
    # Profile-declared jitter range: stealth > commodity. Tested at
    # the profile level (the beacon generator samples uniformly from
    # this range, so stealth jitter range > commodity jitter range
    # transitively guarantees wider observed inter-beacon spread).
    assert stealth_p.beacon_jitter_fraction > commodity_p.beacon_jitter_fraction


def test_beacons_timestamps_monotonic():
    bs = _run("cobalt-strike-default", duration_s=3600)
    assert all(bs[i].timestamp < bs[i + 1].timestamp for i in range(len(bs) - 1))


def test_beacons_destinations_rotate_through_callbacks():
    bs = _run("cobalt-strike-default", duration_s=3600)
    seen = {b.dst_ip for b in bs}
    assert seen == set(CALLBACKS)


def test_dns_profile_uses_udp_and_port_53():
    bs = _run("lotl-dns-tunneled", duration_s=86400 * 7, seed=7)  # 1 week
    assert bs, "expected at least one beacon over a week"
    for b in bs:
        assert b.transport_proto == "udp"
        assert b.dst_port == 53


def test_https_profile_uses_tcp_and_port_443():
    bs = _run("bumblebee-tls", duration_s=3600, seed=7)
    assert bs
    for b in bs:
        assert b.transport_proto == "tcp"
        assert b.dst_port == 443


def test_payload_size_within_jitter_band():
    p = profiles.get_preset("cobalt-strike-default")
    bs = _run("cobalt-strike-default", duration_s=3600)
    low = int(p.payload_size_mean_bytes * (1.0 - p.payload_size_jitter_fraction))
    high = int(p.payload_size_mean_bytes * (1.0 + p.payload_size_jitter_fraction))
    for b in bs:
        assert low <= b.payload_size_bytes <= high


def test_short_window_returns_empty_list():
    # 10-second window with cobalt-strike (mean 60s) MAY yield 0 beacons
    # depending on jitter. The function must return an empty list, not
    # raise.
    bs = _run("cobalt-strike-default", duration_s=10, seed=999)
    # Could be 0 or 1; the contract is: no exception, no fractional.
    assert isinstance(bs, list)
    for b in bs:
        assert b.timestamp <= START.replace(second=10)


def test_rejects_naive_start_time():
    p = profiles.get_preset("cobalt-strike-default")
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_beacons(
            profile=p,
            target_host_ip=TARGET,
            callback_targets=CALLBACKS,
            start_time=datetime(2026, 6, 10, 0, 0, 0),  # naive!
            duration_seconds=3600,
            seed=1,
        )


def test_rejects_empty_callbacks():
    p = profiles.get_preset("cobalt-strike-default")
    with pytest.raises(ValueError, match="callback_targets"):
        generate_beacons(
            profile=p,
            target_host_ip=TARGET,
            callback_targets=[],
            start_time=START,
            duration_seconds=3600,
            seed=1,
        )
