"""Deterministic time + IP rewriting tests.

The rewriter must be deterministic across runs given a fixed ``incident_id``:
private IPs in the source events map to the same target IPs every time. We
also assert that public IPs are preserved (they are the IOCs) and that
timestamps shift by the correct delta.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import pytest

from blue_bench_generators.cybercrime_foil.rewrite import (
    build_ip_map_for_test,
    rewrite_events,
)


def _zeek_event(ts: float, src: str, dst: str) -> dict:
    return {
        "_log": "conn",
        "ts": f"{ts:.6f}",
        "uid": "C0001",
        "id.orig_h": src,
        "id.orig_p": "49152",
        "id.resp_h": dst,
        "id.resp_p": "443",
        "proto": "tcp",
        "service": "ssl",
    }


def _suricata_event(ts_iso: str, src: str, dst: str) -> dict:
    return {
        "_log": "eve",
        "timestamp": ts_iso,
        "event_type": "flow",
        "src_ip": src,
        "src_port": 49153,
        "dest_ip": dst,
        "dest_port": 443,
        "proto": "TCP",
    }


def test_ip_map_is_deterministic_per_incident_id():
    events = [
        _zeek_event(1671558720.0, "10.0.0.5", "203.0.113.42"),
        _zeek_event(1671558730.0, "10.0.0.6", "198.51.100.17"),
        _zeek_event(1671558740.0, "10.0.0.5", "203.0.113.99"),
    ]
    map1 = build_ip_map_for_test(events, "mta-2022-12-20-icedid-cs", "10.42.0.0/16")
    map2 = build_ip_map_for_test(events, "mta-2022-12-20-icedid-cs", "10.42.0.0/16")
    assert map1 == map2
    # Each original private IP got a unique target IP within the subnet.
    target = ipaddress.IPv4Network("10.42.0.0/16")
    for orig, mapped in map1.items():
        assert ipaddress.IPv4Address(mapped) in target.hosts()
    assert len(set(map1.values())) == len(map1)


def test_ip_map_differs_across_incident_ids():
    events = [_zeek_event(1671558720.0, "10.0.0.5", "203.0.113.42")]
    a = build_ip_map_for_test(events, "incident-a", "10.42.0.0/16")
    b = build_ip_map_for_test(events, "incident-b", "10.42.0.0/16")
    # 65k+ host space means collision under different seeds is negligible.
    assert a != b


def test_public_ips_preserved():
    events = [_zeek_event(1671558720.0, "10.0.0.5", "203.0.113.42")]
    target_epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    out = rewrite_events(
        events,
        incident_id="mta-2022-12-20-icedid-cs",
        target_epoch=target_epoch,
        target_subnet="10.42.0.0/16",
    )
    assert out[0]["id.resp_h"] == "203.0.113.42"  # public preserved


def test_private_ips_rewritten_into_target_subnet():
    events = [_zeek_event(1671558720.0, "10.0.0.5", "203.0.113.42")]
    target_epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    out = rewrite_events(
        events,
        incident_id="mta-2022-12-20-icedid-cs",
        target_epoch=target_epoch,
        target_subnet="10.42.0.0/16",
    )
    new_src = ipaddress.IPv4Address(out[0]["id.orig_h"])
    assert new_src in ipaddress.IPv4Network("10.42.0.0/16")
    assert str(new_src) != "10.0.0.5"


def test_timestamps_shift_to_target_epoch():
    earliest_pcap_ts = 1671558720.0  # 2022-12-20 19:12:00Z
    later_pcap_ts = earliest_pcap_ts + 60.0
    events = [
        _zeek_event(earliest_pcap_ts, "10.0.0.5", "203.0.113.42"),
        _zeek_event(later_pcap_ts, "10.0.0.5", "203.0.113.43"),
    ]
    target_epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    out = rewrite_events(
        events,
        incident_id="t",
        target_epoch=target_epoch,
        target_subnet="10.42.0.0/16",
    )
    # First event lands exactly on target_epoch (delta absorbs earliest_ts).
    assert float(out[0]["ts"]) == pytest.approx(target_epoch.timestamp(), rel=0, abs=1e-3)
    # Second event keeps its 60s offset from the first.
    assert float(out[1]["ts"]) - float(out[0]["ts"]) == pytest.approx(60.0, abs=1e-3)


def test_suricata_event_timestamp_format_preserved():
    earliest_iso = "2022-12-20T19:12:00.000000+0000"
    later_iso = "2022-12-20T19:13:00.000000+0000"
    events = [
        _suricata_event(earliest_iso, "10.0.0.5", "203.0.113.42"),
        _suricata_event(later_iso, "10.0.0.6", "203.0.113.43"),
    ]
    target_epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    out = rewrite_events(
        events,
        incident_id="t",
        target_epoch=target_epoch,
        target_subnet="10.42.0.0/16",
    )
    # Suricata format kept: "YYYY-MM-DDTHH:MM:SS.ffffff+0000"
    assert out[0]["timestamp"].startswith("2026-06-10T14:32:00")
    assert out[0]["timestamp"].endswith("+0000")


def test_rewrite_idempotent_across_runs():
    events = [
        _zeek_event(1671558720.0, "10.0.0.5", "203.0.113.42"),
        _zeek_event(1671558730.0, "10.0.0.6", "198.51.100.17"),
    ]
    epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    out1 = rewrite_events(events, incident_id="x", target_epoch=epoch, target_subnet="10.42.0.0/16")
    out2 = rewrite_events(events, incident_id="x", target_epoch=epoch, target_subnet="10.42.0.0/16")
    assert out1 == out2


def test_subnet_too_small_raises():
    events = [
        _zeek_event(1671558720.0, f"10.0.0.{i}", "203.0.113.42")
        for i in range(1, 20)
    ]
    # /30 has only 2 usable hosts; rewriting 19 distinct private IPs must fail.
    with pytest.raises(ValueError):
        rewrite_events(
            events,
            incident_id="x",
            target_epoch=datetime(2026, 6, 10, tzinfo=timezone.utc),
            target_subnet="10.42.0.0/30",
        )


def test_empty_event_list_returns_empty():
    assert rewrite_events([], incident_id="x", target_epoch=datetime.now(timezone.utc), target_subnet="10.42.0.0/16") == []


# --- regression: _parse_iso must round-trip the writer's own +0000 offset ---


def test_parse_iso_accepts_no_colon_offset():
    """rewrite._parse_iso must accept ``+HHMM`` (no colon) because the
    matching writer emits Suricata timestamps in that format. Python
    3.10's fromisoformat rejects it without normalisation; this test
    pins the normalisation behaviour.
    """
    from datetime import datetime as _dt, timezone as _tz
    from blue_bench_generators.cybercrime_foil.rewrite import _parse_iso

    expected = _dt(2026, 6, 10, 14, 32, 7, 123456, tzinfo=_tz.utc)
    parsed = _parse_iso("2026-06-10T14:32:07.123456+0000")
    assert parsed == expected
    # Also accepts the standard colonised form.
    assert _parse_iso("2026-06-10T14:32:07.123456+00:00") == expected
    # And ``Z`` suffix.
    assert _parse_iso("2026-06-10T14:32:07.123456Z") == expected


def test_ipv6_address_logs_warning_and_passes_through(caplog):
    """v1 does not rewrite IPv6; it must log a warning per unique
    address rather than silently passing through.
    """
    import logging
    from blue_bench_generators.cybercrime_foil.rewrite import rewrite_events

    events = [
        {
            "_log": "conn",
            "ts": "1700000000.000000",
            "id.orig_h": "10.5.5.5",
            "id.resp_h": "2001:db8::1",  # IPv6
        }
    ]
    caplog.set_level(logging.WARNING, logger="blue_bench_generators.cybercrime_foil.rewrite")
    out = rewrite_events(
        events,
        incident_id="ipv6-warn-test",
        target_epoch=datetime(2026, 1, 1, tzinfo=timezone.utc),
        target_subnet="10.42.0.0/24",
    )
    # IPv6 token survives unchanged.
    assert out[0]["id.resp_h"] == "2001:db8::1"
    # And a warning was emitted.
    assert any("IPv6" in r.message for r in caplog.records)
