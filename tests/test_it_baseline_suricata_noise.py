"""Tests for the IT-baseline Suricata benign-noise generator (t-pu0g)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.suricata_noise import (
    _BENIGN_RULE_SIGNATURES,
    generate,
)
from blue_bench_generators.it_baseline.topology import build_topology


# Pin to a known weekday business hour so volume is solidly non-zero.
WEEKDAY_10AM = datetime(2026, 5, 11, 10, 0, 0)  # Monday 10am
WEEKDAY_3AM = datetime(2026, 5, 11, 3, 0, 0)    # Monday 3am (overnight)


# Cybercrime / APT family vocabulary that MUST NOT appear in benign-noise
# alerts. Drawn from the c2 + cybercrime_foil generators.
_FORBIDDEN_ALERT_SUBSTRINGS: tuple[str, ...] = (
    "Cobalt Strike",
    "IcedID",
    "Lumma",
    "Qakbot",
    "Emotet",
    "TrickBot",
    "MALWARE",
    "Trojan",
    "C2",
    "Beacon",
)


@pytest.fixture
def small_corpus():
    """Small S-tier topology + activity model fixture."""
    topo = build_topology("S", seed=0)
    am = build_activity_model(topo, seed=0)
    return topo, am


def _run(small_corpus, *, hours: int = 1, seed: int = 0, alert_ratio: float = 0.01):
    topo, am = small_corpus
    start = WEEKDAY_10AM
    end = start + timedelta(hours=hours)
    return list(
        generate(topo, am, start, end, seed=seed, alert_ratio=alert_ratio)
    )


def test_deterministic_with_seed(small_corpus):
    """Same seed => byte-identical event stream across runs."""
    a = _run(small_corpus, seed=42)
    b = _run(small_corpus, seed=42)
    assert a == b
    # And different seeds should NOT collide (extremely unlikely to match).
    c = _run(small_corpus, seed=43)
    assert a != c


def test_no_events_outside_window(small_corpus):
    events = _run(small_corpus, hours=2)
    assert events, "fixture should produce events at 10am-12pm weekday"
    start_iso = WEEKDAY_10AM.strftime("%Y-%m-%dT%H:%M:%S")
    end = WEEKDAY_10AM + timedelta(hours=2)
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%S")
    for e in events:
        ts = e["timestamp"]
        # Drop the fractional + timezone tail for comparison.
        head = ts[:19]
        assert head >= start_iso, f"event before window: {ts}"
        assert head < end_iso, f"event after window: {ts}"


def test_alert_ratio_is_respected(small_corpus):
    """count(alerts)/count(flows) ~= alert_ratio within +-50% on small windows."""
    target = 0.05
    events = _run(small_corpus, hours=2, alert_ratio=target)
    n_flows = sum(1 for e in events if e["event_type"] == "flow")
    n_alerts = sum(1 for e in events if e["event_type"] == "alert")
    assert n_flows > 0, "expected non-zero flows in a 2-hour weekday window"
    observed = n_alerts / n_flows
    # Small windows + per-(host, hour, sig) dedup permit broad tolerance.
    assert target * 0.5 <= observed <= target * 1.5, (
        f"alert ratio {observed:.4f} outside [{target*0.5:.4f}, {target*1.5:.4f}] "
        f"(flows={n_flows}, alerts={n_alerts})"
    )


def test_alert_signatures_in_vocabulary(small_corpus):
    events = _run(small_corpus, hours=4, alert_ratio=0.1)
    for e in events:
        if e["event_type"] != "alert":
            continue
        sig = e["alert"]["signature"]
        assert sig in _BENIGN_RULE_SIGNATURES, (
            f"alert signature {sig!r} not in benign-noise pool"
        )


def test_alerts_have_sid_zero_and_low_severity(small_corpus):
    events = _run(small_corpus, hours=4, alert_ratio=0.1)
    alerts = [e for e in events if e["event_type"] == "alert"]
    assert alerts, "fixture should produce some alerts at ratio 0.1"
    for a in alerts:
        assert a["alert"]["sid"] == 0
        assert a["alert"]["severity"] == 3


def test_flow_records_carry_5tuple(small_corpus):
    events = _run(small_corpus, hours=1)
    flows = [e for e in events if e["event_type"] == "flow"]
    assert flows, "fixture should produce flow events"
    for f in flows:
        for field in ("src_ip", "src_port", "dest_ip", "dest_port", "proto"):
            assert field in f, f"flow missing {field}: {f}"
        assert isinstance(f["src_port"], int)
        assert isinstance(f["dest_port"], int)
        assert f["proto"] in ("TCP", "UDP")


def test_dns_event_carries_rrname(small_corpus):
    events = _run(small_corpus, hours=1)
    dns_events = [e for e in events if e["event_type"] == "dns"]
    assert dns_events, "fixture should produce dns events"
    for d in dns_events:
        assert "dns" in d
        assert d["dns"].get("rrname"), f"dns event missing rrname: {d}"


def test_tls_event_carries_sni(small_corpus):
    events = _run(small_corpus, hours=1)
    tls_events = [e for e in events if e["event_type"] == "tls"]
    assert tls_events, "fixture should produce tls events"
    for t in tls_events:
        assert "tls" in t
        assert t["tls"].get("sni"), f"tls event missing sni: {t}"


def test_no_alerts_named_after_cybercrime_or_apt_families(small_corpus):
    """Critical: this generator is benign-noise only. Never name a malware family."""
    events = _run(small_corpus, hours=4, alert_ratio=0.5)  # crank alerts to stress
    for e in events:
        if e["event_type"] != "alert":
            continue
        sig = e["alert"]["signature"]
        for banned in _FORBIDDEN_ALERT_SUBSTRINGS:
            assert banned not in sig, (
                f"benign-noise generator emitted forbidden family substring "
                f"{banned!r} in signature {sig!r}"
            )


def test_volume_responds_to_time_of_day(small_corpus):
    """A 1-hour 10am business-hour window emits more than a 1-hour 3am window."""
    topo, am = small_corpus
    morning = list(
        generate(topo, am, WEEKDAY_10AM, WEEKDAY_10AM + timedelta(hours=1), seed=7)
    )
    overnight = list(
        generate(topo, am, WEEKDAY_3AM, WEEKDAY_3AM + timedelta(hours=1), seed=7)
    )
    # Workstations dominate the host count at S tier, so 10am should
    # produce strictly more events than 3am.
    assert len(morning) > len(overnight), (
        f"expected 10am volume ({len(morning)}) > 3am volume ({len(overnight)})"
    )


def test_alert_dedup_per_host_per_hour(small_corpus):
    """Same alert sig fires <= once per (host, hour, sig)."""
    topo, am = small_corpus
    events = list(
        generate(
            topo,
            am,
            WEEKDAY_10AM,
            WEEKDAY_10AM + timedelta(hours=3),
            seed=11,
            alert_ratio=0.5,
        )
    )
    # Bucket: (src_ip, hour_of_day, signature).
    seen: dict[tuple[str, str, str], int] = {}
    for e in events:
        if e["event_type"] != "alert":
            continue
        host_ip = e["src_ip"]
        hour_key = e["timestamp"][:13]  # "YYYY-MM-DDTHH"
        sig = e["alert"]["signature"]
        key = (host_ip, hour_key, sig)
        seen[key] = seen.get(key, 0) + 1
    for key, count in seen.items():
        assert count == 1, f"dedup violated: {key} fired {count} times"


def test_log_field_set_on_every_record(small_corpus):
    """_log: "eve" convention is required by the cybercrime_foil replay parser."""
    events = _run(small_corpus, hours=1, alert_ratio=0.1)
    assert events
    for e in events:
        assert e.get("_log") == "eve", f"missing or wrong _log on {e}"


def test_empty_window_yields_nothing(small_corpus):
    topo, am = small_corpus
    out = list(generate(topo, am, WEEKDAY_10AM, WEEKDAY_10AM, seed=0))
    assert out == []
    # End before start also empty.
    out = list(
        generate(topo, am, WEEKDAY_10AM, WEEKDAY_10AM - timedelta(hours=1), seed=0)
    )
    assert out == []
