"""Tests for the shared ISO-8601 parsing helper.

The helper centralises Suricata-``+HHMM``-tolerance across rewrite,
bundle validation, and CLI input. Tests pin the three shapes our
writers and upstream sources emit.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from blue_bench_generators._isotime import parse_iso


_EXPECTED = datetime(2026, 6, 10, 14, 32, 7, 123456, tzinfo=timezone.utc)


def test_z_suffix():
    assert parse_iso("2026-06-10T14:32:07.123456Z") == _EXPECTED


def test_no_colon_offset():
    """Suricata convention: ``+HHMM`` (no colon). 3.10's fromisoformat
    rejects this; the helper must normalise it.
    """
    assert parse_iso("2026-06-10T14:32:07.123456+0000") == _EXPECTED


def test_colonised_offset():
    assert parse_iso("2026-06-10T14:32:07.123456+00:00") == _EXPECTED


def test_negative_offset():
    """``-HHMM`` normalises the same way ``+HHMM`` does."""
    result = parse_iso("2026-06-10T14:32:07-0500")
    # Resulting tzinfo should be a -5h offset.
    assert result.utcoffset().total_seconds() == -5 * 3600


def test_no_microseconds():
    assert parse_iso("2026-06-10T14:32:07Z") == datetime(
        2026, 6, 10, 14, 32, 7, tzinfo=timezone.utc
    )


def test_malformed_raises():
    with pytest.raises(ValueError):
        parse_iso("not-a-timestamp")
