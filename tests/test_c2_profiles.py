"""Profile preset library shape + invariants."""

from __future__ import annotations

import re

import pytest

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.profiles import (
    COMMODITY_PRESETS,
    STEALTH_PRESETS,
    CommodityProfile,
    StealthProfile,
    get_preset,
    preset_names,
)


TTP_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_at_least_5_commodity_presets():
    assert len(COMMODITY_PRESETS) >= 5


def test_at_least_4_stealth_presets():
    assert len(STEALTH_PRESETS) >= 4


def test_required_commodity_preset_names_present():
    expected = {
        "cobalt-strike-default",
        "icedid-http",
        "bumblebee-tls",
        "lumma-https",
        "hancitor-stage",
    }
    names = {p.name for p in COMMODITY_PRESETS}
    assert expected.issubset(names), f"missing: {expected - names}"


def test_required_stealth_preset_names_present():
    expected = {
        "lotl-https-cloudfront",
        "lotl-https-azure",
        "lotl-dns-tunneled",
        "lotl-domain-fronted",
    }
    names = {p.name for p in STEALTH_PRESETS}
    assert expected.issubset(names), f"missing: {expected - names}"


def test_all_presets_have_non_empty_ttps():
    for p in (*COMMODITY_PRESETS, *STEALTH_PRESETS):
        assert p.ttps, f"preset {p.name} has empty ttps"


def test_all_ttps_match_regex():
    for p in (*COMMODITY_PRESETS, *STEALTH_PRESETS):
        for ttp in (*p.ttps, *p.ttps_optional):
            assert TTP_RE.match(ttp), f"{p.name}: bad ttp {ttp!r}"


def test_commodity_invariants():
    for p in COMMODITY_PRESETS:
        assert isinstance(p, CommodityProfile)
        assert p.source_class == "cybercrime"
        assert p.confidence == "high"
        # Commodity MUST be alertable.
        assert p.suricata_rule_families, (
            f"commodity {p.name}: must declare Suricata rule families"
        )
        assert p.kind() == "commodity"


def test_stealth_invariants():
    for p in STEALTH_PRESETS:
        assert isinstance(p, StealthProfile)
        assert p.source_class == "apt"
        assert p.confidence == "medium"
        # Stealth MUST be alert-silent.
        assert p.suricata_rule_families == (), (
            f"stealth {p.name}: must NOT declare Suricata rule families"
        )
        assert p.kind() == "stealth"


def test_field_types_match_declared_shape():
    for p in (*COMMODITY_PRESETS, *STEALTH_PRESETS):
        assert isinstance(p.name, str)
        assert isinstance(p.family, str)
        assert p.transport in {"http", "https", "dns"}
        assert isinstance(p.beacon_interval_seconds, float)
        assert isinstance(p.beacon_jitter_fraction, float)
        assert isinstance(p.payload_size_mean_bytes, int)
        assert isinstance(p.payload_size_jitter_fraction, float)
        assert isinstance(p.url_path_pattern, str)
        assert isinstance(p.tls_sni_pattern, str)
        assert isinstance(p.dns_query_pattern, str)
        assert isinstance(p.tls_fingerprint_hint, str)
        assert isinstance(p.suricata_rule_families, tuple)
        assert isinstance(p.ttps, tuple)
        assert isinstance(p.ttps_optional, tuple)


def test_commodity_beacons_faster_than_stealth():
    # Sanity invariant: every commodity profile has shorter mean
    # interval than every stealth profile.
    commodity_max = max(p.beacon_interval_seconds for p in COMMODITY_PRESETS)
    stealth_min = min(p.beacon_interval_seconds for p in STEALTH_PRESETS)
    assert commodity_max < stealth_min, (
        f"commodity_max={commodity_max}s, stealth_min={stealth_min}s -- "
        f"profiles must keep these strictly separated"
    )


def test_get_preset_lookup_and_unknown():
    p = get_preset("cobalt-strike-default")
    assert p.name == "cobalt-strike-default"
    with pytest.raises(KeyError):
        get_preset("not-a-preset")


def test_preset_names_returns_all_unique():
    names = preset_names()
    assert len(names) == len(set(names))
    assert "cobalt-strike-default" in names
    assert "lotl-dns-tunneled" in names


def test_no_real_domain_in_any_preset():
    # All SNI / DNS / URL patterns must reference *.example.invalid
    # OR be empty. We're protecting against accidental real-domain
    # references slipping in.
    for p in (*COMMODITY_PRESETS, *STEALTH_PRESETS):
        for field_name in ("tls_sni_pattern", "dns_query_pattern"):
            v = getattr(p, field_name)
            if not v:
                continue
            assert v.endswith(".example.invalid") or "%(payload)s" in v, (
                f"{p.name}.{field_name}={v!r} must end with .example.invalid "
                f"(or be empty) to satisfy NEVER-real-domains constraint"
            )


def test_dns_tunneled_profile_uses_payload_template():
    # The DNS-tunneled preset MUST use the %(payload)s template so
    # zeek_emit / suricata_emit produce subdomain-encoded queries.
    p = profiles.get_preset("lotl-dns-tunneled")
    assert "%(payload)s" in p.dns_query_pattern
    assert p.transport == "dns"
