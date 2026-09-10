"""Anchoring must keep a record's embedded clocks in sync with @timestamp.

Regression for the sysmon UtcTime (March) vs @timestamp (June) split that broke
host<->network correlation: --anchor-end-to-now shifted @timestamp but left
UtcTime / ts / timestamp_ms at their original capture time.
"""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ingest_ef", Path(__file__).resolve().parent.parent / "scripts" / "ingest_ef.py")
ingest_ef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ingest_ef)


def test_shift_embedded_times_moves_every_clock():
    delta = timedelta(days=90)  # ~ the March->June offset that caused the bug
    doc = {
        "UtcTime": "2026-03-20 08:04:00.523",
        "TimeCreated": "2026-03-20T08:04:00.523000+00:00",
        "ts": "1774339440.523000",
        "timestamp_ms": 1774339440523,
        "Image": "C:\\Windows\\System32\\cmd.exe",   # non-time field untouched
    }
    before_utc = ingest_ef._parse_iso(doc["UtcTime"].replace(" ", "T"))
    before_ts = float(doc["ts"])
    before_ms = doc["timestamp_ms"]

    ingest_ef._shift_embedded_times(doc, delta)

    assert ingest_ef._parse_iso(doc["UtcTime"].replace(" ", "T")) == before_utc + delta
    assert ingest_ef._parse_iso(doc["TimeCreated"]) == \
        datetime(2026, 3, 20, 8, 4, 0, 523000, tzinfo=timezone.utc) + delta
    assert float(doc["ts"]) == before_ts + delta.total_seconds()
    assert doc["timestamp_ms"] == before_ms + int(delta.total_seconds() * 1000)
    assert doc["Image"] == "C:\\Windows\\System32\\cmd.exe"


def test_utctime_and_timestamp_agree_after_shift():
    # The whole point: after anchoring, UtcTime and @timestamp are the same clock.
    when = datetime(2026, 3, 20, 8, 4, 0, 523000, tzinfo=timezone.utc)
    delta = datetime(2026, 6, 20, tzinfo=timezone.utc) - when.replace(hour=0, minute=0, second=0, microsecond=0)
    doc = {"UtcTime": "2026-03-20 08:04:00.523"}
    at = (when + delta).isoformat()          # what @timestamp would become
    ingest_ef._shift_embedded_times(doc, delta)
    shifted_utc = ingest_ef._parse_iso(doc["UtcTime"].replace(" ", "T"))
    assert abs((shifted_utc - ingest_ef._parse_iso(at)).total_seconds()) < 0.01


def test_no_shift_when_delta_zero_semantics():
    # Helper is only called under anchoring; a no-op-ish tiny delta stays exact.
    doc = {"ts": "1774339440.000000"}
    ingest_ef._shift_embedded_times(doc, timedelta(0))
    assert float(doc["ts"]) == 1774339440.0
