"""Shared ISO-8601 timestamp parsing.

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

from datetime import datetime


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
