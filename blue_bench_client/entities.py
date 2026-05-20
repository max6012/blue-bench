"""Deterministic entity extractors for the mechanical grounding pass.

Each extractor takes a text string and yields :class:`EntityClaim` objects with
character offsets. Strict-by-design: prefer recall losses (entity not extracted)
over precision losses (entity extracted from prose where it isn't an entity).
The grounding pass then matches each extracted entity against the tool-call
ledger; entities the model paraphrased away will land in the unverifiable
bucket rather than being silently treated as grounded.

Slice scope: ip, hash_md5, hash_sha1, hash_sha256, cve, event_id. Hostname,
domain, port, cidr, pid, username, path deferred — they have higher ambiguity
in prose and need more careful precision tuning before they earn a place.
"""
from __future__ import annotations

import re
from collections.abc import Iterator

from blue_bench_client.trace import EntityClaim, EntityType


# ── primitive patterns ───────────────────────────────────────────────────────
#
# Each pattern is anchored by word boundaries so we don't pick up substrings.
# More-specific patterns (sha256 = 64 hex) must run before less-specific ones
# (md5 = 32 hex) so a sha256 hash isn't double-claimed as md5 of a slice.

_IPV4_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Event IDs are extracted only when there is a clear label nearby. Naked
# 4-digit integers in prose are too ambiguous (port numbers, counts, years).
# Pattern matches the digit run; the span returned is the digits only.
_EVENT_ID = re.compile(
    r"\b(?:event[ _-]?id|eventcode|event_?code|event)\s*[:=#]?\s*(\d{3,6})\b",
    re.IGNORECASE,
)


# ── extractor functions ─────────────────────────────────────────────────────


def _yield_ip(text: str) -> Iterator[EntityClaim]:
    for m in _IPV4_CANDIDATE.finditer(text):
        octets = m.group(0).split(".")
        if all(0 <= int(p) <= 255 for p in octets):
            yield EntityClaim(
                entity_type="ip",
                value=m.group(0),
                span_start=m.start(),
                span_end=m.end(),
            )


def _yield_hashes(text: str, taken: set[tuple[int, int]]) -> Iterator[EntityClaim]:
    """Yield hash entities longest-first so a sha256 isn't double-claimed.

    ``taken`` is a set of (start, end) spans already claimed; subsequent
    patterns skip overlapping matches. Mutated in-place by the caller pattern.
    """
    for pattern, hash_type in (
        (_HASH_SHA256, "hash_sha256"),
        (_HASH_SHA1, "hash_sha1"),
        (_HASH_MD5, "hash_md5"),
    ):
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            # Skip if this match is fully contained in a longer hash already taken.
            if any(s <= span[0] and span[1] <= e for s, e in taken):
                continue
            taken.add(span)
            yield EntityClaim(
                entity_type=hash_type,
                value=m.group(0),
                span_start=m.start(),
                span_end=m.end(),
            )


def _yield_cve(text: str) -> Iterator[EntityClaim]:
    for m in _CVE.finditer(text):
        yield EntityClaim(
            entity_type="cve",
            value=m.group(0).upper(),  # normalize "cve-2024-1234" → "CVE-2024-1234"
            span_start=m.start(),
            span_end=m.end(),
        )


def _yield_event_ids(text: str) -> Iterator[EntityClaim]:
    """Event IDs require an adjacent label (event/eventid/eventcode) — naked
    4-digit numbers are too ambiguous in prose."""
    for m in _EVENT_ID.finditer(text):
        # Span is the digit group only, not the label.
        digit_start = m.start(1)
        digit_end = m.end(1)
        yield EntityClaim(
            entity_type="event_id",
            value=m.group(1),
            span_start=digit_start,
            span_end=digit_end,
        )


# ── public surface ──────────────────────────────────────────────────────────


SLICE_ENTITY_TYPES: tuple[EntityType, ...] = (
    "ip",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "cve",
    "event_id",
)
"""The entity types the slice extractor supports. Listed in the order they
will be extracted; the grounding pass uses this order for tie-breaking when
two patterns overlap (longest-first within hash variants)."""


def extract_entities(
    text: str,
    types: tuple[EntityType, ...] | None = None,
) -> list[EntityClaim]:
    """Run every requested extractor over ``text`` and return all claims.

    ``types`` defaults to ``SLICE_ENTITY_TYPES``. Pass a subset to narrow the
    extraction surface — useful when a profile's ``defenses.grounding.entity_types``
    is restricted.

    Returned in order of appearance in ``text`` (sorted by ``span_start``).
    Overlapping hash matches are de-duplicated via longest-first tie-break.
    """
    if not text:
        return []
    selected = set(types) if types is not None else set(SLICE_ENTITY_TYPES)
    claims: list[EntityClaim] = []
    hash_spans: set[tuple[int, int]] = set()

    if "ip" in selected:
        claims.extend(_yield_ip(text))
    if any(t.startswith("hash_") for t in selected):
        for claim in _yield_hashes(text, hash_spans):
            if claim.entity_type in selected:
                claims.append(claim)
    if "cve" in selected:
        claims.extend(_yield_cve(text))
    if "event_id" in selected:
        claims.extend(_yield_event_ids(text))

    claims.sort(key=lambda c: (c.span_start, c.span_end))
    return claims
