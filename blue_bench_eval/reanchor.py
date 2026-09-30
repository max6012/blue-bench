"""Re-anchor the ingested corpus in place so it ends at "now" again.

The corpus is ingested with ``--anchor-end-to-now`` (scripts/ingest_ef.py):
one delta is added to every ``@timestamp`` and to every embedded clock so an
18-day corpus ends at ingest time. It then decays. Every tool looks back from
*now* (``now-240m`` by default), so a few hours after ingest the default
lookback already returns nothing, and a few days after ingest a whole slate
of grades is void -- that happened once (see docs/EVAL.md, "Phase-3 grades")
and preflight's window check now catches it. Catching it is not fixing it:
re-ingesting 11.9M documents takes hours. This module fixes it in minutes.

How: one ``_update_by_query`` per index with a Painless script that adds the
same delta to ``@timestamp`` AND to every embedded clock, exactly as
``ingest_ef._shift_embedded_times`` does at ingest (Zeek ``ts`` epoch-seconds
string, eCAR ``timestamp_ms`` int, Sysmon ``UtcTime`` ``yyyy-MM-dd HH:mm:ss.SSS``,
and the ISO fields ``TimeCreated``/``EventTime``/``timestamp`` in Python
``isoformat()`` form). ``_id``s are untouched, so every ground-truth pointer
still resolves. ``tests/test_reanchor.py`` proves the Painless output equals the
Python function's output field by field on a throwaway index.

Where "now" is measured from: NOT ``max(@timestamp)``. A handful of benign
records sit up to ~3h in the future of the true tail (generator clock skew on
8 sysmon, 8 security and 2 syslog events), so the max is the wrong anchor and
would drift the corpus 3h early on every run. The anchor is persisted instead:
index ``bb-meta``, document ``corpus-anchor`` (see ``AnchorDoc``). Ingest
writes it; every re-anchor advances it by exactly the delta applied.
``bootstrap_anchor`` derives it once for a corpus ingested before the document
existed.

Delta is whole seconds. ``now - current_window_end`` has microseconds; carrying
them would make every embedded-clock format a rounding argument (Python
``.6f`` vs Java, ms truncation, ...). Truncating to seconds makes every
sub-second digit pass through untouched. Losing sub-second precision on a
multi-hour shift costs nothing.

Hazards, and what is done about them:
  * Not atomic, not resumable. ``conflicts=proceed`` SKIPS a conflicting
    document, so a run with ``version_conflicts > 0`` or ``failures`` leaves a
    corpus where most documents moved and some did not. The anchor is still
    advanced (the majority moved) and the run raises; the remedy is re-ingest,
    not re-run -- a re-run would double-shift the documents that moved.
  * Concurrent writers. Refused while ingest holds its lock (``bb-meta`` /
    ``ingest-lock``, written by scripts/ingest_ef.py), while another re-anchor
    is in progress (the anchor doc's ``in_progress`` flag, plus any live
    ``*byquery`` task), and while any target index reports in-flight indexing
    operations (``_stats/indexing`` ``index_current``).
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

META_INDEX = "bb-meta"
ANCHOR_DOC_ID = "corpus-anchor"
INGEST_LOCK_DOC_ID = "ingest-lock"

# Indices with at least this many documents vote in the bootstrap median. The
# small ones (wazuh-alerts=2, zeek-pe=118, suricata=345, ot-conn=1373 on the L
# corpus) end wherever their last event happened to be and would only add noise.
BOOTSTRAP_MIN_DOCS = 100_000
# Measured on the L corpus (2026-09-14): the per-index maxes of the large
# indices span 3.2h (zeek-files 16:10 .. windows-sysmon 19:23, the latter
# being the clock-skew outliers). A spread well beyond that means the indices
# were not ingested together (a partial re-ingest), and no single anchor is
# right for all of them.
BOOTSTRAP_MAX_SPREAD_HOURS = 6.0

# --- the Painless shift -------------------------------------------------------
#
# Mirrors ingest_ef._shift_embedded_times field for field. Every field is
# handled independently and left untouched when it does not parse, because
# that is what the Python does (`_parse_iso` -> None, or a ValueError swallowed).
# ``@timestamp`` is the exception: if IT does not parse the whole document is a
# `noop`, which the task result counts, and the caller fails loudly on it.
#
# ISO output is CPython ``datetime.isoformat()``: ``YYYY-MM-DDTHH:MM:SS``, then
# ``.ffffff`` only when the microsecond is non-zero (six digits, never three),
# then the offset as ``+HH:MM`` (never ``Z``). ``_parse_iso`` accepts ``Z``,
# ``+HHMM``, a space separator, 1-9 fraction digits (7+ truncated to 6) and a
# naive value (UTC), so the parser here does too.
PAINLESS_FUNCTIONS = r"""
String pad(long v, int width) {
  String s = Long.toString(v);
  while (s.length() < width) { s = "0" + s; }
  return s;
}

boolean allDigits(String s) {
  if (s.length() == 0) { return false; }
  for (int i = 0; i < s.length(); i++) {
    if (!Character.isDigit((char)s.charAt(i))) { return false; }
  }
  return true;
}

/* Parse an ISO-8601 date-time the way ingest_ef._parse_iso does. Returns
   [LocalDateTime wallClock, String offset "+HH:MM"] or null. */
def parseIso(String raw) {
  String s = raw.replace(" ", "T");
  int n = s.length();
  if (n < 10) { return null; }
  if (s.charAt(4) != (char)"-" || s.charAt(7) != (char)"-") { return null; }
  if (!allDigits(s.substring(0, 4)) || !allDigits(s.substring(5, 7)) || !allDigits(s.substring(8, 10))) { return null; }
  int y = Integer.parseInt(s.substring(0, 4));
  int mo = Integer.parseInt(s.substring(5, 7));
  int d = Integer.parseInt(s.substring(8, 10));
  int hh = 0; int mi = 0; int ss = 0; int nanos = 0;
  int pos = 10;
  if (n > 10) {
    if (s.charAt(10) != (char)"T" || n < 16) { return null; }
    if (!allDigits(s.substring(11, 13)) || s.charAt(13) != (char)":" || !allDigits(s.substring(14, 16))) { return null; }
    hh = Integer.parseInt(s.substring(11, 13));
    mi = Integer.parseInt(s.substring(14, 16));
    pos = 16;
    if (pos < n && s.charAt(pos) == (char)":") {
      if (n < 19 || !allDigits(s.substring(17, 19))) { return null; }
      ss = Integer.parseInt(s.substring(17, 19));
      pos = 19;
      if (pos < n && s.charAt(pos) == (char)".") {
        int start = pos + 1; int end = start;
        while (end < n && Character.isDigit((char)s.charAt(end))) { end++; }
        if (end == start) { return null; }
        String frac = s.substring(start, end);
        if (frac.length() > 6) { frac = frac.substring(0, 6); }   /* _parse_iso truncates 7+ digits */
        while (frac.length() < 9) { frac = frac + "0"; }
        nanos = Integer.parseInt(frac);
        pos = end;
      }
    }
  }
  String off = "+00:00";                                          /* naive -> UTC */
  if (pos < n) {
    char c = (char)s.charAt(pos);
    String rest = s.substring(pos + 1);
    if (c == (char)"Z" && rest.length() == 0) {
      off = "+00:00";
    } else if (c == (char)"+" || c == (char)"-") {
      if (rest.length() == 5 && rest.charAt(2) == (char)":" && allDigits(rest.substring(0, 2)) && allDigits(rest.substring(3, 5))) {
        off = String.valueOf(c) + rest;
      } else if (rest.length() == 4 && allDigits(rest)) {         /* +0000 -> +00:00 */
        off = String.valueOf(c) + rest.substring(0, 2) + ":" + rest.substring(2, 4);
      } else {
        return null;
      }
      if (off.equals("-00:00")) { off = "+00:00"; }
    } else {
      return null;
    }
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mi > 59 || ss > 59) { return null; }
  try {
    return [LocalDateTime.of(y, mo, d, hh, mi, ss, nanos), off];
  } catch (Exception e) {
    return null;
  }
}

/* CPython datetime.isoformat() of an aware datetime. */
String fmtIso(LocalDateTime t, String off) {
  String s = pad(t.getYear(), 4) + "-" + pad(t.getMonthValue(), 2) + "-" + pad(t.getDayOfMonth(), 2)
    + "T" + pad(t.getHour(), 2) + ":" + pad(t.getMinute(), 2) + ":" + pad(t.getSecond(), 2);
  int micros = t.getNano() / 1000;
  if (micros != 0) { s = s + "." + pad(micros, 6); }
  return s + off;
}

/* strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] -- milliseconds, truncated. */
String fmtUtcTime(LocalDateTime t) {
  return pad(t.getYear(), 4) + "-" + pad(t.getMonthValue(), 2) + "-" + pad(t.getDayOfMonth(), 2)
    + " " + pad(t.getHour(), 2) + ":" + pad(t.getMinute(), 2) + ":" + pad(t.getSecond(), 2)
    + "." + pad(t.getNano() / 1000000, 3);
}

/* Shift one document's clocks in place. Returns false when @timestamp is
   present but unparseable (caller turns that into a noop). */
boolean shiftDoc(Map src, long deltaMicros, long deltaMs) {
  long deltaNanos = deltaMicros * 1000L;

  def ts = src.get("ts");
  if (ts != null && !(ts instanceof String && ((String)ts).length() == 0)) {
    try {
      double x = (ts instanceof String) ? Double.parseDouble((String)ts) : ((Number)ts).doubleValue();
      long micros = Math.round(x * 1000000.0d) + deltaMicros;
      src.put("ts", Long.toString(micros / 1000000L) + "." + pad(micros % 1000000L, 6));
    } catch (Exception e) { }
  }

  def ms = src.get("timestamp_ms");
  if (ms != null && !(ms instanceof String && ((String)ms).length() == 0)) {
    boolean have = false; long base = 0L;
    if (ms instanceof Long || ms instanceof Integer) { base = ((Number)ms).longValue(); have = true; }
    else if (ms instanceof Double || ms instanceof Float) { base = (long)((Number)ms).doubleValue(); have = true; }
    else if (ms instanceof String) {
      try { base = Long.parseLong(((String)ms).trim()); have = true; } catch (Exception e) { }
    }
    if (have) { src.put("timestamp_ms", base + deltaMs); }
  }

  def ut = src.get("UtcTime");
  if (ut instanceof String && ((String)ut).length() > 0) {
    def p = parseIso((String)ut);
    if (p != null) { src.put("UtcTime", fmtUtcTime(((LocalDateTime)p[0]).plusNanos(deltaNanos))); }
  }

  for (String f : ["TimeCreated", "EventTime", "timestamp"]) {
    def v = src.get(f);
    if (v instanceof String && ((String)v).length() > 0) {
      String sv = (String)v;
      if (allDigits(sv.replace(".", ""))
          && (sv.indexOf(".") == sv.lastIndexOf("."))) { continue; }  /* epoch-shaped: skipped, as Python does */
      def p = parseIso(sv);
      if (p != null) { src.put(f, fmtIso(((LocalDateTime)p[0]).plusNanos(deltaNanos), (String)p[1])); }
    }
  }

  def at = src.get("@timestamp");
  if (at != null) {
    if (!(at instanceof String)) { return false; }
    def p = parseIso((String)at);
    if (p == null) { return false; }
    src.put("@timestamp", fmtIso(((LocalDateTime)p[0]).plusNanos(deltaNanos), (String)p[1]));
  }
  return true;
}
"""

# The update_by_query body: ctx._source is the map; an unparseable @timestamp
# becomes a counted noop rather than a silently half-shifted document.
PAINLESS_UPDATE = PAINLESS_FUNCTIONS + r"""
if (!shiftDoc(ctx._source, params.delta_micros, params.delta_ms)) { ctx.op = "noop"; }
"""


def script_params(delta: timedelta) -> dict[str, int]:
    """Painless params for a delta, computed the way ingest computes them.

    ``delta_ms`` is ``int(round(secs * 1000))`` exactly as
    ``_shift_embedded_times`` does for ``timestamp_ms``.
    """
    secs = delta.total_seconds()
    return {
        "delta_micros": int(round(secs * 1_000_000)),
        "delta_ms": int(round(secs * 1000)),
    }


# --- anchor document ----------------------------------------------------------


@dataclass
class AnchorDoc:
    """``bb-meta`` / ``corpus-anchor``: where the corpus window sits right now.

    ``current_window_end`` is where ``original_window_end`` sits after every
    shift so far -- the value "now" is measured against. Ingest sets it exactly
    (``window.end + delta``); ``bootstrap_anchor`` approximates it (median of
    per-index max ``@timestamp``, error of seconds, baked in for good); every
    re-anchor sets it to the ``now`` it shifted to, exactly.
    ``applied_delta_seconds`` accumulates: it is always
    ``current_window_end - original_window_end``.
    """
    original_window_start: str | None
    original_window_end: str
    current_window_end: str
    applied_delta_seconds: float
    anchored_at: str
    build_hash: str | None = None
    tier: str | None = None
    reanchor_runs: int = 0
    in_progress: bool = False
    # Free text about how the document came to be (ingest / bootstrap / reanchor).
    note: str = ""

    @property
    def current_end(self) -> datetime:
        return _parse_ts(self.current_window_end)

    @classmethod
    def from_source(cls, src: dict[str, Any]) -> "AnchorDoc":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in src.items() if k in known})


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ReanchorError(RuntimeError):
    """Refused or failed re-anchor. The message says what to do."""


# --- ES admin client ----------------------------------------------------------


class ESAdmin:
    """The few admin calls a re-anchor needs, over sync httpx.

    Same dependency as ``scripts/ingest_ef.py`` and ``preflight.HttpxESClient``.
    Kept separate from the preflight client because these are writes.
    """

    def __init__(
        self,
        url: str,
        *,
        auth: tuple[str, str] | None = None,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.url = url.rstrip("/")
        self._auth = auth
        self._verify = verify_ssl
        self.timeout = timeout

    @classmethod
    def from_config(cls, cfg) -> "ESAdmin":
        auth = (
            (cfg.elastic.user, cfg.elastic.password)
            if cfg.elastic.user and cfg.elastic.password
            else None
        )
        return cls(
            cfg.elastic.url,
            auth=auth,
            verify_ssl=cfg.elastic.verify_ssl,
            timeout=float(cfg.limits.query_timeout),
        )

    def _c(self, timeout: float | None = None) -> httpx.Client:
        return httpx.Client(
            verify=self._verify, auth=self._auth,
            timeout=timeout if timeout is not None else self.timeout,
        )

    def _req(self, method: str, path: str, *, params: dict | None = None,
             json_body: Any = None, timeout: float | None = None, ok404: bool = False) -> Any:
        try:
            with self._c(timeout) as c:
                r = c.request(method, f"{self.url}{path}", params=params, json=json_body)
        except httpx.HTTPError as e:
            raise ReanchorError(f"{method} {path} failed: {type(e).__name__}: {e}") from e
        if r.status_code == 404 and ok404:
            return None
        if r.status_code >= 400:
            raise ReanchorError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else {}

    # -- read side --

    def indices(self) -> dict[str, int]:
        """{index: doc count} for every non-system index, ``bb-meta`` excluded."""
        rows = self._req("GET", "/_cat/indices", params={"format": "json", "h": "index,docs.count"})
        out: dict[str, int] = {}
        for row in rows or []:
            name = row["index"]
            if name.startswith(".") or name == META_INDEX:
                continue
            out[name] = int(row.get("docs.count") or 0)
        return out

    def has_timestamp_mapping(self, index: str) -> bool:
        m = self._req("GET", f"/{index}/_mapping", ok404=True)
        if not m:
            return False
        props = m.get(index, {}).get("mappings", {}).get("properties", {})
        return props.get("@timestamp", {}).get("type") == "date"

    def count_with_timestamp(self, index: str) -> int:
        body = {"query": {"exists": {"field": "@timestamp"}}}
        r = self._req("GET", f"/{index}/_count", json_body=body)
        return int(r.get("count", 0))

    def max_timestamp(self, index: str) -> datetime | None:
        body = {"size": 0, "aggs": {"mx": {"max": {"field": "@timestamp"}}}}
        r = self._req("POST", f"/{index}/_search", json_body=body)
        vs = r.get("aggregations", {}).get("mx", {}).get("value_as_string")
        return _parse_ts(vs) if vs else None

    def indexing_in_flight(self, index: str) -> int:
        """Number of indexing operations currently executing on the index."""
        r = self._req("GET", f"/{index}/_stats/indexing", ok404=True)
        if not r:
            return 0
        return int(r.get("_all", {}).get("total", {}).get("indexing", {}).get("index_current", 0))

    def byquery_tasks(self) -> list[str]:
        """Descriptions of update/delete-by-query tasks currently running."""
        r = self._req("GET", "/_tasks", params={"actions": "*byquery", "detailed": "true"})
        out = []
        for node in (r or {}).get("nodes", {}).values():
            for tid, t in node.get("tasks", {}).items():
                out.append(f"{tid}: {t.get('description', t.get('action'))}")
        return out

    # -- meta doc --

    def _ensure_meta_index(self) -> None:
        if self._req("HEAD", f"/{META_INDEX}", ok404=True) is None:
            body = {
                "mappings": {
                    "properties": {
                        "original_window_start": {"type": "date"},
                        "original_window_end": {"type": "date"},
                        "current_window_end": {"type": "date"},
                        "applied_delta_seconds": {"type": "double"},
                        "anchored_at": {"type": "date"},
                        "build_hash": {"type": "keyword"},
                        "tier": {"type": "keyword"},
                        "reanchor_runs": {"type": "integer"},
                        "in_progress": {"type": "boolean"},
                        "note": {"type": "text"},
                        "started_at": {"type": "date"},
                        "ef_dir": {"type": "keyword"},
                        "pid": {"type": "long"},
                    }
                }
            }
            self._req("PUT", f"/{META_INDEX}", json_body=body)

    def read_anchor(self) -> AnchorDoc | None:
        r = self._req("GET", f"/{META_INDEX}/_doc/{ANCHOR_DOC_ID}", ok404=True)
        if not r or not r.get("found"):
            return None
        return AnchorDoc.from_source(r["_source"])

    def write_anchor(self, doc: AnchorDoc) -> None:
        self._ensure_meta_index()
        self._req("PUT", f"/{META_INDEX}/_doc/{ANCHOR_DOC_ID}", params={"refresh": "true"},
                  json_body=asdict(doc))

    def read_ingest_lock(self) -> dict | None:
        r = self._req("GET", f"/{META_INDEX}/_doc/{INGEST_LOCK_DOC_ID}", ok404=True)
        if not r or not r.get("found"):
            return None
        return r["_source"]

    def write_ingest_lock(self, info: dict) -> None:
        self._ensure_meta_index()
        self._req("PUT", f"/{META_INDEX}/_doc/{INGEST_LOCK_DOC_ID}", params={"refresh": "true"},
                  json_body=info)

    def clear_ingest_lock(self) -> None:
        self._req("DELETE", f"/{META_INDEX}/_doc/{INGEST_LOCK_DOC_ID}", params={"refresh": "true"},
                  ok404=True)

    # -- the shift --

    def submit_update_by_query(self, index: str, params: dict[str, int], *, scroll_size: int = 2000) -> str:
        body = {
            "query": {"match_all": {}},   # NOT a @timestamp range: docs without one still carry embedded clocks
            "script": {"lang": "painless", "source": PAINLESS_UPDATE, "params": params},
        }
        q = {
            "conflicts": "proceed",
            "wait_for_completion": "false",
            "slices": "auto",
            "scroll_size": str(scroll_size),
            "refresh": "true",
        }
        r = self._req("POST", f"/{index}/_update_by_query", params=q, json_body=body)
        return r["task"]

    def task_status(self, task_id: str) -> dict:
        return self._req("GET", f"/_tasks/{task_id}")

    def refresh(self, index: str) -> None:
        self._req("POST", f"/{index}/_refresh", timeout=120)


# --- ingest-side helpers ------------------------------------------------------


def write_ingest_anchor(
    admin: ESAdmin,
    *,
    window_start: datetime | None,
    window_end: datetime,
    delta: timedelta | None,
    build_hash: str | None,
    tier: str | None,
) -> AnchorDoc:
    """Called by scripts/ingest_ef.py once the corpus is in.

    Written even for an un-anchored ingest (delta None): the window end is
    still the truth about where the corpus sits, and preflight ``--reanchor``
    can then bring an un-anchored corpus to now the same way it fixes decay.
    """
    d = delta or timedelta(0)
    doc = AnchorDoc(
        original_window_start=_iso(window_start) if window_start else None,
        original_window_end=_iso(window_end),
        current_window_end=_iso(window_end + d),
        applied_delta_seconds=d.total_seconds(),
        anchored_at=_iso(_now()),
        build_hash=build_hash,
        tier=tier,
        note="written by scripts/ingest_ef.py" + ("" if delta else " (ingest was not anchored)"),
    )
    admin.write_anchor(doc)
    return doc


# --- bootstrap ---------------------------------------------------------------


@dataclass
class BootstrapResult:
    anchor: AnchorDoc
    per_index_max: dict[str, str]
    voters: list[str]
    spread_hours: float
    min_based_estimate: str | None

    def summary(self) -> str:
        lines = ["bootstrap-anchor derivation:"]
        for idx, mx in sorted(self.per_index_max.items()):
            vote = "vote" if idx in self.voters else "    "
            lines.append(f"  {vote} {idx:26s} max(@timestamp) = {mx}")
        lines.append(f"  voters: indices with >= {BOOTSTRAP_MIN_DOCS} docs ({len(self.voters)})")
        lines.append(f"  spread of voter maxes: {self.spread_hours:.2f}h (limit {BOOTSTRAP_MAX_SPREAD_HOURS}h)")
        lines.append(f"  current_window_end (median of voter maxes) = {self.anchor.current_window_end}")
        if self.min_based_estimate:
            lines.append(f"  cross-check, min(@timestamp) + window length = {self.min_based_estimate}")
        lines.append(f"  original window: {self.anchor.original_window_start} .. {self.anchor.original_window_end}")
        lines.append(f"  applied_delta_seconds = {self.anchor.applied_delta_seconds:.0f}")
        lines.append(f"  build_hash = {self.anchor.build_hash}  tier = {self.anchor.tier}")
        return "\n".join(lines)


def _read_manifest(manifest_path: Path) -> tuple[datetime | None, datetime, str | None, str | None]:
    import yaml

    m = yaml.safe_load(manifest_path.read_text()) or {}
    w = m.get("window", {}) or {}
    if not w.get("end"):
        raise ReanchorError(f"{manifest_path}: no window.end")
    start = _parse_ts(w["start"]) if w.get("start") else None
    return start, _parse_ts(w["end"]), m.get("build_hash"), m.get("tier")


def bootstrap_anchor(
    admin: ESAdmin,
    manifest_path: Path,
    *,
    min_docs: int = BOOTSTRAP_MIN_DOCS,
    max_spread_hours: float = BOOTSTRAP_MAX_SPREAD_HOURS,
    write: bool = True,
    force: bool = False,
) -> BootstrapResult:
    """Derive the anchor for a corpus ingested before ``bb-meta`` existed.

    ``current_window_end`` = median of per-index ``max(@timestamp)`` over the
    large indices -- robust to the few future-skewed records, which drag only
    the sysmon/security maxes. Refuses when the large indices' maxes disagree
    by more than ``max_spread_hours``: that is not skew, that is a corpus whose
    indices were not ingested together, and one anchor cannot be right for all.
    """
    existing = admin.read_anchor()
    if existing is not None and not force:
        raise ReanchorError(
            f"{META_INDEX}/{ANCHOR_DOC_ID} already exists (current_window_end="
            f"{existing.current_window_end}); bootstrap is for a corpus that has none. "
            "Pass --force to overwrite it."
        )
    win_start, win_end, build_hash, tier = _read_manifest(manifest_path)
    counts = admin.indices()
    per_max: dict[str, datetime] = {}
    per_min: dict[str, datetime] = {}
    for idx, n in counts.items():
        if n == 0 or not admin.has_timestamp_mapping(idx):
            continue
        mx = admin.max_timestamp(idx)
        if mx is not None:
            per_max[idx] = mx
    voters = sorted(i for i, n in counts.items() if n >= min_docs and i in per_max)
    if len(voters) < 3:
        raise ReanchorError(
            f"only {len(voters)} indices have >= {min_docs} docs and a @timestamp; "
            "refusing to derive an anchor from fewer than 3"
        )
    vals = [per_max[i] for i in voters]
    spread_h = (max(vals) - min(vals)).total_seconds() / 3600
    if spread_h > max_spread_hours:
        raise ReanchorError(
            f"per-index max(@timestamp) of the large indices disagree by {spread_h:.1f}h "
            f"(> {max_spread_hours}h): "
            + ", ".join(f"{i}={per_max[i].isoformat()}" for i in voters)
            + ". That is a partially ingested corpus, not clock skew; re-ingest it whole."
        )
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    median_s = statistics.median((v - epoch).total_seconds() for v in vals)
    current_end = epoch + timedelta(seconds=median_s)
    # Cross-check only: the first event of the corpus sits at (or seconds after)
    # the window start, so min + window length lands near the same place.
    min_based = None
    if win_start is not None:
        body_min = None
        for idx in voters:
            r = admin._req("POST", f"/{idx}/_search",
                           json_body={"size": 0, "aggs": {"mn": {"min": {"field": "@timestamp"}}}})
            vs = r.get("aggregations", {}).get("mn", {}).get("value_as_string")
            if vs:
                mn = _parse_ts(vs)
                body_min = mn if body_min is None else min(body_min, mn)
        if body_min is not None:
            min_based = _iso(body_min + (win_end - win_start))
    anchor = AnchorDoc(
        original_window_start=_iso(win_start) if win_start else None,
        original_window_end=_iso(win_end),
        current_window_end=_iso(current_end),
        applied_delta_seconds=(current_end - win_end).total_seconds(),
        anchored_at=_iso(_now()),
        build_hash=build_hash,
        tier=tier,
        note=f"bootstrapped from median max(@timestamp) of {len(voters)} indices; manifest {manifest_path}",
    )
    if write:
        admin.write_anchor(anchor)
    return BootstrapResult(
        anchor=anchor,
        per_index_max={i: v.isoformat() for i, v in per_max.items()},
        voters=voters,
        spread_hours=spread_h,
        min_based_estimate=min_based,
    )


# --- the re-anchor ------------------------------------------------------------


@dataclass
class IndexShift:
    index: str
    total: int = 0
    updated: int = 0
    noops: int = 0
    version_conflicts: int = 0
    failures: int = 0
    seconds: float = 0.0
    skipped_reason: str = ""


@dataclass
class ReanchorResult:
    delta_seconds: int
    gap_before_hours: float
    gap_after_hours: float
    anchor_before: str
    anchor_after: str
    shifts: list[IndexShift] = field(default_factory=list)
    wall_seconds: float = 0.0
    dry_run: bool = False

    @property
    def problems(self) -> list[str]:
        out = []
        for s in self.shifts:
            if s.skipped_reason:
                continue
            if s.version_conflicts or s.failures or s.noops:
                out.append(
                    f"{s.index}: updated={s.updated} noops={s.noops} "
                    f"version_conflicts={s.version_conflicts} failures={s.failures}"
                )
        return out

    @property
    def docs_updated(self) -> int:
        return sum(s.updated for s in self.shifts)

    def summary(self) -> str:
        head = "would apply" if self.dry_run else "applied"
        lines = [
            f"re-anchor: {head} delta = +{self.delta_seconds}s "
            f"({self.delta_seconds / 3600:.2f}h); gap before = {self.gap_before_hours:.2f}h, "
            f"after = {self.gap_after_hours:.2f}h; anchor {self.anchor_before} -> {self.anchor_after}"
        ]
        for s in self.shifts:
            if s.skipped_reason:
                lines.append(f"  skip {s.index:26s} {s.skipped_reason}")
            elif self.dry_run:
                lines.append(f"  {s.index:26s} {s.total} docs")
            else:
                flag = "" if not (s.version_conflicts or s.failures or s.noops) else "  <-- PROBLEM"
                lines.append(
                    f"  {s.index:26s} updated={s.updated} noops={s.noops} "
                    f"conflicts={s.version_conflicts} failures={s.failures} {s.seconds:.0f}s{flag}"
                )
        if not self.dry_run:
            lines.append(f"  total docs updated: {self.docs_updated} in {self.wall_seconds:.0f}s")
        return "\n".join(lines)


def gap_hours(anchor: AnchorDoc, now: datetime | None = None) -> float:
    return ((now or _now()) - anchor.current_end).total_seconds() / 3600


def plan_delta(anchor: AnchorDoc, now: datetime | None = None) -> timedelta:
    """Whole-second delta that moves ``current_window_end`` to ``now``."""
    now = now or _now()
    secs = int((now - anchor.current_end).total_seconds())
    return timedelta(seconds=secs)


def refuse_if_unsafe(admin: ESAdmin, anchor: AnchorDoc, indices: list[str], *, ignore_ingest_lock: bool = False) -> None:
    lock = admin.read_ingest_lock()
    if lock is not None and not ignore_ingest_lock:
        raise ReanchorError(
            f"an ingest holds {META_INDEX}/{INGEST_LOCK_DOC_ID} (started {lock.get('started_at')}, "
            f"ef_dir={lock.get('ef_dir')}, pid={lock.get('pid')}); re-anchoring under an ingest "
            "would shift half a corpus. If that ingest is dead, clear the lock with "
            "--ignore-ingest-lock (or DELETE the document)."
        )
    if anchor.in_progress:
        raise ReanchorError(
            f"{META_INDEX}/{ANCHOR_DOC_ID} says a re-anchor is in progress (anchored_at="
            f"{anchor.anchored_at}). If it crashed, the corpus may be half-shifted: check "
            "per-index max(@timestamp); if they agree, clear the flag with --clear-in-progress."
        )
    running = admin.byquery_tasks()
    if running:
        raise ReanchorError("update/delete-by-query tasks are already running: " + "; ".join(running))
    busy = [i for i in indices if admin.indexing_in_flight(i) > 0]
    if busy:
        raise ReanchorError(f"indexing operations in flight on: {', '.join(busy)}; something is writing")


def _poll(admin: ESAdmin, task_id: str, *, interval: float = 2.0, log=None) -> dict:
    while True:
        st = admin.task_status(task_id)
        if st.get("completed"):
            return st
        if log is not None:
            s = st.get("task", {}).get("status", {})
            log(f"    ... {s.get('updated', 0)}/{s.get('total', '?')} updated")
        time.sleep(interval)


def reanchor(
    admin: ESAdmin,
    *,
    tolerance_hours: float,
    dry_run: bool = False,
    now: datetime | None = None,
    ignore_ingest_lock: bool = False,
    log=None,
) -> ReanchorResult | None:
    """Shift the whole corpus so its window ends at ``now``.

    Returns None when the gap is within tolerance (a no-op, idempotent), a
    ``ReanchorResult`` otherwise. With ``dry_run`` nothing is written and the
    result carries the delta that would have been applied. Raises
    ``ReanchorError`` when refused, and after a shift whose task results show
    any noop / version conflict / failure (the anchor is advanced first, since
    the rest of the corpus did move -- the remedy is re-ingest).
    """
    log = log or (lambda s: None)
    now = now or _now()
    anchor = admin.read_anchor()
    if anchor is None:
        raise ReanchorError(
            f"no {META_INDEX}/{ANCHOR_DOC_ID} document: the corpus was ingested before the anchor "
            "existed. Derive it once with: python -m blue_bench_eval.reanchor --config config.yaml "
            "--bootstrap-anchor --manifest <corpus>/corpus-manifest.yaml"
        )
    before_h = gap_hours(anchor, now)
    if before_h <= tolerance_hours:
        log(f"re-anchor: gap {before_h:.2f}h is within tolerance {tolerance_hours}h; nothing to do")
        return None
    delta = plan_delta(anchor, now)
    counts = admin.indices()
    shifts: list[IndexShift] = []
    targets: list[str] = []
    for idx in sorted(counts):
        n = counts[idx]
        if n == 0:
            shifts.append(IndexShift(idx, total=0, skipped_reason="empty"))
        elif not admin.has_timestamp_mapping(idx):
            shifts.append(IndexShift(idx, total=n, skipped_reason="no @timestamp mapping"))
        elif admin.count_with_timestamp(idx) == 0:
            # ot-assets: the mapping declares @timestamp (every index gets it)
            # but no document carries one -- an inventory has no time.
            shifts.append(IndexShift(idx, total=n, skipped_reason="no document carries @timestamp"))
        else:
            shifts.append(IndexShift(idx, total=n))
            targets.append(idx)
    new_end = anchor.current_end + delta
    result = ReanchorResult(
        delta_seconds=int(delta.total_seconds()),
        gap_before_hours=before_h,
        gap_after_hours=(now - new_end).total_seconds() / 3600,
        anchor_before=anchor.current_window_end,
        anchor_after=_iso(new_end),
        shifts=shifts,
        dry_run=dry_run,
    )
    if dry_run:
        return result
    refuse_if_unsafe(admin, anchor, targets, ignore_ingest_lock=ignore_ingest_lock)

    t0 = time.monotonic()
    anchor.in_progress = True
    admin.write_anchor(anchor)
    params = script_params(delta)
    log(f"re-anchor: applying delta +{result.delta_seconds}s to {len(targets)} indices "
        f"(params {params})")
    try:
        for s in shifts:
            if s.skipped_reason:
                continue
            ti = time.monotonic()
            log(f"  {s.index}: {s.total} docs")
            task = admin.submit_update_by_query(s.index, params)
            st = _poll(admin, task, log=log)
            resp = st.get("response", {}) or st.get("task", {}).get("status", {})
            s.updated = int(resp.get("updated", 0))
            s.noops = int(resp.get("noops", 0))
            s.version_conflicts = int(resp.get("version_conflicts", 0))
            s.failures = len(resp.get("failures", []) or [])
            if st.get("error"):
                s.failures += 1
                log(f"    task error: {json.dumps(st['error'])[:400]}")
            admin.refresh(s.index)
            s.seconds = time.monotonic() - ti
            log(f"    updated={s.updated} noops={s.noops} conflicts={s.version_conflicts} "
                f"failures={s.failures} in {s.seconds:.0f}s")
    finally:
        # The anchor moves even on failure: the indices that completed DID
        # move, and leaving the old value would make a retry double-shift them.
        anchor.current_window_end = _iso(new_end)
        anchor.applied_delta_seconds = float(anchor.applied_delta_seconds) + delta.total_seconds()
        anchor.anchored_at = _iso(_now())
        anchor.reanchor_runs = int(anchor.reanchor_runs) + 1
        anchor.in_progress = False
        anchor.note = f"last re-anchor +{result.delta_seconds}s"
        admin.write_anchor(anchor)
    result.wall_seconds = time.monotonic() - t0
    if result.problems:
        raise ReanchorError(
            "re-anchor finished with problems: " + "; ".join(result.problems)
            + ". The corpus is now MIXED (most documents moved, these did not). "
            "Do not re-run -- that double-shifts the ones that moved. Re-ingest."
        )
    return result


# --- CLI ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m blue_bench_eval.reanchor",
        description="Shift the ingested corpus in place so it ends at now again.",
    )
    p.add_argument("--config", required=True, type=Path, help="MCP server config.yaml")
    p.add_argument("--dry-run", action="store_true", help="print the delta and per-index plan; write nothing")
    p.add_argument("--tolerance-hours", type=float, default=None,
                   help="no-op when the gap is within this (default: preflight.reanchor_tolerance_hours from config)")
    p.add_argument("--bootstrap-anchor", action="store_true",
                   help="derive and write bb-meta/corpus-anchor for a corpus ingested before it existed")
    p.add_argument("--manifest", type=Path, default=None, help="corpus-manifest.yaml (with --bootstrap-anchor)")
    p.add_argument("--force", action="store_true", help="with --bootstrap-anchor: overwrite an existing anchor")
    p.add_argument("--ignore-ingest-lock", action="store_true", help="proceed even if bb-meta/ingest-lock exists")
    p.add_argument("--clear-in-progress", action="store_true",
                   help="clear a stale in_progress flag left by a crashed re-anchor, then exit")
    p.add_argument("--show-anchor", action="store_true", help="print the anchor document and exit")
    args = p.parse_args(argv)

    from blue_bench_mcp.config import load_config

    cfg = load_config(args.config)
    admin = ESAdmin.from_config(cfg)
    tol = args.tolerance_hours if args.tolerance_hours is not None else cfg.preflight.reanchor_tolerance_hours
    try:
        if args.show_anchor:
            a = admin.read_anchor()
            print(json.dumps(asdict(a), indent=2) if a else f"no {META_INDEX}/{ANCHOR_DOC_ID}")
            if a:
                print(f"gap now: {gap_hours(a):.2f}h (tolerance {tol}h)")
            return 0
        if args.clear_in_progress:
            a = admin.read_anchor()
            if a is None:
                print("no anchor document")
                return 1
            a.in_progress = False
            admin.write_anchor(a)
            print("in_progress cleared")
            return 0
        if args.bootstrap_anchor:
            if args.manifest is None:
                p.error("--bootstrap-anchor needs --manifest")
            res = bootstrap_anchor(admin, args.manifest, write=not args.dry_run, force=args.force)
            print(res.summary())
            print("(dry run: not written)" if args.dry_run else f"written to {META_INDEX}/{ANCHOR_DOC_ID}")
            return 0
        res = reanchor(admin, tolerance_hours=tol, dry_run=args.dry_run, log=print,
                       ignore_ingest_lock=args.ignore_ingest_lock)
        if res is not None:
            print(res.summary())
        return 0
    except ReanchorError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
