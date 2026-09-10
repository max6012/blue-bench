"""Shared ISO-8601 timestamp parsing and UTC coercion.

Python 3.10's ``datetime.fromisoformat`` rejects the ``+HHMM`` offset
(no colon) shape that Suricata's ``eve.json`` emits by convention. Our
own writers also emit ``+0000`` to match Suricata's wire format, so the
writers' output is not round-trippable on 3.10 (the project's declared
minimum in ``pyproject.toml``) without normalisation. Centralise the
normalisation here so every site uses the same logic.

3.11+ accepts both ``+HHMM`` and ``+HH:MM``; this helper still works
there and is a no-op on already-normalised input.
"""

from __future__ import annotations

from datetime import datetime, timezone


def as_utc(ts: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    The generators' calling convention is "naive UTC": callers hand in
    naive datetimes that *mean* UTC. But ``datetime.timestamp()`` on a
    naive datetime interprets it in the **local** timezone, so any epoch
    derived from one shifts with the build machine's ``TZ`` (issue #30).
    Attaching ``timezone.utc`` makes ``.timestamp()`` TZ-independent
    without changing the wall-clock fields, so a naive-UTC caller gets
    the epoch it already meant.

    Args:
        ts: naive datetime (interpreted as UTC) or any aware datetime.

    Returns:
        The same instant as a ``timezone.utc``-aware datetime. Naive
        input keeps its wall-clock fields; aware input is converted.
    """
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def parse_iso(ts: str) -> datetime:
    """ISO-8601 parse tolerant of ``Z`` and ``+HHMM`` (no-colon) offsets.

    Args:
        ts: timestamp string. Accepts the three forms our writers and
            upstream sources emit:
              * ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z``
              * ``YYYY-MM-DDTHH:MM:SS[.ffffff]+HHMM``
              * ``YYYY-MM-DDTHH:MM:SS[.ffffff]+HH:MM``

    Returns:
        ``datetime`` with timezone preserved.

    Raises:
        ValueError: on any other malformed input.
    """
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    elif len(ts) >= 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)
