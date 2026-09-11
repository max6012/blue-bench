"""The @timestamp range every list / aggregate tool filters on, built in one place.

Two ways to bound a query:

* ``timerange_minutes`` -- a lookback from *now*. The original and still the
  default; fine for an analyst at a console.
* ``since`` / ``until`` -- absolute UTC instants. Needed by the fan-out harness:
  a worker investigates one time band of an 18-day corpus, and a lookback
  cannot bound the band's trailing edge, so adjacent slices overlapped and a
  slice could see evidence that belongs to its neighbour. When either absolute
  bound is given it wins and ``timerange_minutes`` is ignored -- mixing the two
  would let a stale default silently narrow an explicit band.

Seven tools carried their own copy of the ``now-Nm`` clause before this
module existed; the semantics live here so they cannot drift apart.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

ISO_EXAMPLE = "2026-08-26T00:00:00Z"
BAD_BOUND = f"Error: since/until must be ISO-8601 UTC, e.g. {ISO_EXAMPLE}"


class TimeRangeError(ValueError):
    """A ``since`` / ``until`` value the tool must refuse before touching ES.

    ``str(err)`` is the exact ``Error: ...`` line the tool returns to the model.
    """


@dataclass(frozen=True)
class TimeRange:
    gte: str | None
    """Lower bound, or ``None`` for unbounded (``until`` given without ``since``)."""
    lte: str
    label: str
    """Human wording for result headers (``last 240m`` / ``2026-… to 2026-…``)."""

    @property
    def clause(self) -> dict:
        bounds = {"gte": self.gte, "lte": self.lte} if self.gte is not None else {"lte": self.lte}
        return {"range": {"@timestamp": bounds}}


def _parse_utc(value: str, name: str) -> datetime:
    """One bound as an aware UTC datetime.

    Accepts a trailing ``Z`` or an explicit offset (converted to UTC) and
    treats a naive timestamp as UTC -- the corpus is UTC throughout, and a
    worker prompt that omits the suffix should not be refused for it.
    """
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise TimeRangeError(f"{BAD_BOUND} ({name}={value!r})") from None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def timestamp_range(timerange_minutes: int, since: str = "", until: str = "") -> TimeRange:
    """Build the ``@timestamp`` bound for a query.

    Raises :class:`TimeRangeError` for an unparseable bound or ``since`` after
    ``until``; callers return ``str(err)`` without calling ES.
    """
    since = (since or "").strip()
    until = (until or "").strip()
    if not since and not until:
        return TimeRange(gte=f"now-{timerange_minutes}m", lte="now",
                         label=f"last {timerange_minutes}m")
    lo = _parse_utc(since, "since") if since else None
    hi = _parse_utc(until, "until") if until else None
    if lo and hi and lo > hi:
        # ES answers a reversed range with zero hits, which the model would
        # read as "no evidence" -- a false negative dressed as a result.
        raise TimeRangeError(f"Error: since ({_iso_z(lo)}) is after until ({_iso_z(hi)})")
    gte = _iso_z(lo) if lo else None
    lte = _iso_z(hi) if hi else "now"
    return TimeRange(gte=gte, lte=lte, label=f"{gte or 'the beginning'} to {lte}")
