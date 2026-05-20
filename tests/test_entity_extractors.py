"""Tests for the deterministic entity extractors.

Two categories per extractor:
  - Positive: a known-good string yields exactly the expected entities at the
    right offsets.
  - Negative: prose-shaped strings that look like entities (paraphrased ranges,
    octet-shaped years, naked numbers) yield zero entities — strict-by-design.
"""
from __future__ import annotations

import pytest

from blue_bench_client.entities import (
    SLICE_ENTITY_TYPES,
    extract_entities,
)
from blue_bench_client.trace import EntityClaim


# ── IPv4 ─────────────────────────────────────────────────────────────────────


def test_ip_extracts_single_address():
    claims = extract_entities("Host 10.10.5.99 was contacted.")
    ips = [c for c in claims if c.entity_type == "ip"]
    assert len(ips) == 1
    assert ips[0].value == "10.10.5.99"
    assert ips[0].span_start == 5
    assert ips[0].span_end == 15


def test_ip_extracts_multiple_addresses():
    text = "Lateral movement: 10.10.5.22 → 10.10.5.45 → 10.10.5.71."
    ips = [c for c in extract_entities(text) if c.entity_type == "ip"]
    assert [c.value for c in ips] == ["10.10.5.22", "10.10.5.45", "10.10.5.71"]


def test_ip_rejects_out_of_range_octets():
    """999.999.999.999 looks like an IP but isn't — extractor rejects via octet validation."""
    text = "Not a real IP: 999.999.999.999."
    ips = [c for c in extract_entities(text) if c.entity_type == "ip"]
    assert ips == []


def test_ip_rejects_paraphrased_range():
    """The strict-by-design contract: '10.10.5.x range' and '/24 subnet' do NOT
    extract as IPs. The model that paraphrases dodges grounding — that's the
    point. The unverifiable bucket catches these."""
    text = "Three hosts in the 10.10.5.0/24 subnet — the 10.10.5.x range — were seen."
    ips = [c for c in extract_entities(text) if c.entity_type == "ip"]
    # The literal "10.10.5.0" IS extracted (it's a valid IP), but neither
    # "10.10.5.x" nor "/24" are paraphrase-aware.
    assert [c.value for c in ips] == ["10.10.5.0"]


def test_ip_negative_on_prose_with_no_address():
    text = "Three hosts in the subnet exhibited beaconing behaviour."
    ips = [c for c in extract_entities(text) if c.entity_type == "ip"]
    assert ips == []


# ── Hashes ───────────────────────────────────────────────────────────────────


MD5_SAMPLE = "5d41402abc4b2a76b9719d911017c592"  # md5("hello")
SHA1_SAMPLE = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"  # sha1("hello")
SHA256_SAMPLE = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"  # sha256("hello")


def test_md5_sha1_sha256_each_extract_their_own_type():
    text = f"md5={MD5_SAMPLE} sha1={SHA1_SAMPLE} sha256={SHA256_SAMPLE}"
    claims = extract_entities(text)
    by_type = {c.entity_type: c.value for c in claims if c.entity_type.startswith("hash_")}
    assert by_type == {
        "hash_md5": MD5_SAMPLE,
        "hash_sha1": SHA1_SAMPLE,
        "hash_sha256": SHA256_SAMPLE,
    }


def test_sha256_not_double_claimed_as_md5():
    """A 64-char hex string CONTAINS a 32-char substring; the extractor must
    claim it as sha256 once, not as sha256 + md5(prefix) + md5(suffix)."""
    text = f"Hash: {SHA256_SAMPLE}"
    claims = [c for c in extract_entities(text) if c.entity_type.startswith("hash_")]
    assert len(claims) == 1, (
        f"sha256 matched {len(claims)} times — overlap dedup is broken: {claims}"
    )
    assert claims[0].entity_type == "hash_sha256"


def test_hash_negative_on_short_hex():
    """A short hex run like 'abc123' must not be picked up as a hash."""
    text = "Color code #abc123 is teal."
    claims = [c for c in extract_entities(text) if c.entity_type.startswith("hash_")]
    assert claims == []


# ── CVE ──────────────────────────────────────────────────────────────────────


def test_cve_extracts_canonical_form():
    text = "Affected by CVE-2024-12345."
    claims = [c for c in extract_entities(text) if c.entity_type == "cve"]
    assert len(claims) == 1
    assert claims[0].value == "CVE-2024-12345"


def test_cve_normalizes_lowercase_prefix():
    """Operators sometimes write 'cve-2024-1234'; we normalize to canonical."""
    text = "See cve-2024-1234 for details."
    claims = [c for c in extract_entities(text) if c.entity_type == "cve"]
    assert claims[0].value == "CVE-2024-1234"


def test_cve_negative_on_non_cve_pattern():
    text = "Project A-2024-1234 is unrelated."
    claims = [c for c in extract_entities(text) if c.entity_type == "cve"]
    assert claims == []


# ── Event IDs ────────────────────────────────────────────────────────────────


def test_event_id_extracts_with_label():
    text = "Triggered event ID 4688 on the endpoint."
    claims = [c for c in extract_entities(text) if c.entity_type == "event_id"]
    assert len(claims) == 1
    assert claims[0].value == "4688"


@pytest.mark.parametrize(
    "phrasing",
    [
        "Event 4688 fired",
        "event id 4688",
        "EventID: 4688",
        "EventCode 4688",
        "event_id=4688",
        "event-id 4688",
    ],
)
def test_event_id_label_variants(phrasing: str):
    claims = [c for c in extract_entities(phrasing) if c.entity_type == "event_id"]
    assert len(claims) == 1, f"failed to extract from {phrasing!r}: {claims}"
    assert claims[0].value == "4688"


def test_event_id_negative_on_naked_number():
    """A naked 4-digit number in prose is too ambiguous — port, year, count, etc.
    Without a label nearby, do not extract."""
    text = "In 2024, the team responded to 4688 alerts in total."
    claims = [c for c in extract_entities(text) if c.entity_type == "event_id"]
    assert claims == []


# ── Surface / API contract ───────────────────────────────────────────────────


def test_empty_text_returns_empty_list():
    assert extract_entities("") == []
    assert extract_entities(None or "") == []


def test_entities_returned_in_text_order():
    """Sorting by span_start lets the renderer walk claims left-to-right."""
    text = f"CVE-2024-9999 hit host 10.10.5.10 with hash {MD5_SAMPLE}."
    claims = extract_entities(text)
    starts = [c.span_start for c in claims]
    assert starts == sorted(starts)


def test_type_filter_narrows_extraction():
    """Passing ``types=`` restricts which extractors run — used by the profile's
    defenses.grounding.entity_types config."""
    text = f"CVE-2024-9999 hit host 10.10.5.10 with hash {MD5_SAMPLE}."
    only_ip = extract_entities(text, types=("ip",))
    assert all(c.entity_type == "ip" for c in only_ip)
    assert len(only_ip) == 1
    only_cve_and_hash = extract_entities(text, types=("cve", "hash_md5"))
    assert {c.entity_type for c in only_cve_and_hash} == {"cve", "hash_md5"}


def test_slice_entity_types_constant_matches_extractor_coverage():
    """SLICE_ENTITY_TYPES must list exactly the types the extractor implements —
    if someone adds a type without adding an extractor (or vice versa), this
    test catches the drift."""
    text = (
        f"10.10.5.99 {MD5_SAMPLE} {SHA1_SAMPLE} {SHA256_SAMPLE} "
        f"CVE-2024-1234 event id 5156"
    )
    found_types = {c.entity_type for c in extract_entities(text)}
    assert found_types == set(SLICE_ENTITY_TYPES), (
        f"SLICE_ENTITY_TYPES ({SLICE_ENTITY_TYPES}) does not match extractor "
        f"coverage ({found_types}) — update one to match the other"
    )


def test_returned_claims_are_entity_claim_instances():
    text = "Host 10.10.5.99."
    for c in extract_entities(text):
        assert isinstance(c, EntityClaim)
        assert c.span_start >= 0
        assert c.span_end > c.span_start
        # The value at the recorded span must equal the claim value.
        assert text[c.span_start : c.span_end] == c.value
