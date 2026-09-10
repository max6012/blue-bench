"""Preflight — fail-closed corpus/SIEM readiness guard for a Blue-Bench run.

A prior run graded models against an EMPTY Elasticsearch and produced
meaningless "all fail" results: the corpus had been ingested WITHOUT
time-anchoring, so every document sat in an old (e.g. March-2026) window while
the MCP tools look back from *now* (`now-Xm` ranges). Every query returned `[]`,
and the grader could not tell "model failed" from "there was nothing to find".

This module makes that impossible to ship again. `run_preflight` checks, in
order of how early they bite:

  1. ES reachable at the configured URL.
  2. Every index the SELECTED prompt slate reads exists and has docs. Scoped to
     the union of ``_indices_for_tools`` over the selected prompts (respecting
     ``prompts_prefix``), NOT the config-total union — a phase-2 run must not
     demand auth/OT/Sysmon indices it never touches.
  3. Corpus window covers "now": the MAX ``@timestamp`` of each index the
     selected slate reads is within ``now_tolerance_hours`` of now, checked
     per-index. THIS is the check that catches the un-anchored-ingest bug — a
     stale max ``@timestamp`` means lookback-from-now queries miss everything.
  4. (optional) Per-prompt probe: for each prompt, a cheap now-relative
     match-over-time-window count on the indices that prompt's expected_tools
     read, confirming the SIEM is not empty for something the prompt could
     ground on. This is the only coverage for host-only indices (sysmon) that
     check 2 does not enumerate.

FAIL-CLOSED: ``PreflightReport.ok`` is True only when every *critical* check
passed. ES being unreachable, or any transport error mid-run, becomes a clean
failed check with a one-line detail — never a traceback. The CLI
(`python -m blue_bench_eval.preflight --config config.yaml`) exits non-zero when
not ok.

ES access goes through a small injectable ``ESClient`` (sync httpx, the same
dependency ``scripts/ingest_ef.py`` uses) so unit tests run fully offline by
supplying a stub.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import httpx

from blue_bench_mcp.config import ServerConfig, load_config

# --- tool -> ES index resolution --------------------------------------------
# Only ES-backed tools contribute indices to a per-prompt probe; a prompt whose
# expected_tools resolve to no ES index (OpenEDR / evidence files / nmap / sigma
# validation) reports "n/a" — see _indices_for_tools.


def _split_pattern(pattern: str) -> list[str]:
    """Split a comma-separated ES index pattern into concrete names."""
    return [p.strip() for p in pattern.split(",") if p.strip()]


def _zeek_index(cfg: ServerConfig) -> str:
    return cfg.zeek.index if cfg.zeek.use_elastic else cfg.elastic.index_pattern


def _optional_indices(cfg: ServerConfig) -> set[str]:
    """Indices a legitimate deployment may simply not have.

    The OT segment and the Linux auth substrate are optional by design: an
    IT-only corpus has no ``ot/`` tree (``scenarios/heavy-telemetry/README.md``
    documents baseline-only ingest, and neither bb-benign-s nor bb-benign-m has
    a plant segment), and a Windows-only corpus has no syslog. The tools already
    tolerate their absence — ``tool_classes/elastic.py`` queries with
    ``ignore_unavailable=true`` precisely so "ot-conn absent in an IT-only
    deployment" degrades to no-data rather than a 404.

    So preflight must not be stricter than the tool it gates: an ABSENT optional
    index is reported non-critically. Present-but-empty and present-but-stale
    are still critical failures — those mean ingest ran and produced nothing,
    which is the void-grade condition this gate exists to catch.
    """
    return {cfg.zeek.ot_conn_index, cfg.auth.linux_syslog_index}


def _indices_for_tools(tools: list[str], cfg: ServerConfig) -> list[str]:
    """Resolve the ES indices an expected_tools list would read.

    Returns de-duplicated concrete index names, in stable order. Tools with no
    ES backing contribute nothing.
    """
    out: list[str] = []
    for tool in tools:
        if tool in ("search_alerts", "count_by_field"):
            out.extend(_split_pattern(cfg.elastic.index_pattern))
        elif tool in ("get_connections", "detect_beaconing"):
            # get_connections spans zeek-conn AND ot-conn (OT reachability).
            out.append(_zeek_index(cfg))
            out.append(cfg.zeek.ot_conn_index)
        elif tool in ("get_agent_alerts", "wazuh_list_agents"):
            out.append(cfg.wazuh.es_fallback_index)
        elif tool in ("get_process_events", "get_process_tree"):
            out.append(cfg.sysmon.index)
        elif tool == "search_auth_events":
            out.append(cfg.auth.windows_security_index)
            out.append(cfg.auth.linux_syslog_index)
    # De-dup preserving order.
    seen: set[str] = set()
    uniq: list[str] = []
    for idx in out:
        if idx not in seen:
            seen.add(idx)
            uniq.append(idx)
    return uniq


def _all_read_indices(cfg: ServerConfig) -> list[str]:
    """Union of every ES index the tool surface reads (for the window check).

    Wider than ``index_pattern`` on purpose: the un-anchored bug shifts the
    whole corpus together, but sysmon lives in its own index — checking the
    window over index_pattern alone would let a stale host-telemetry window slip
    through. Cheap to widen; directly serves "impossible to repeat".
    """
    idxs = _split_pattern(cfg.elastic.index_pattern)
    idxs.append(_zeek_index(cfg))
    idxs.append(cfg.zeek.ot_conn_index)
    idxs.append(cfg.sysmon.index)
    idxs.append(cfg.wazuh.es_fallback_index)
    idxs.append(cfg.auth.windows_security_index)
    idxs.append(cfg.auth.linux_syslog_index)
    seen: set[str] = set()
    uniq: list[str] = []
    for idx in idxs:
        if idx not in seen:
            seen.add(idx)
            uniq.append(idx)
    return uniq


def _indices_for_specs(specs: list, cfg: ServerConfig) -> list[str]:
    """Union of the ES indices a selected prompt slate reads.

    Scoped to the prompts actually being run (respecting ``prompts_prefix``), so
    a phase-2 run does not demand auth/OT/Sysmon indices it never touches. This
    is the correct denominator for checks 2 and 3 — the config-total union
    (``_all_read_indices``) would over-demand and break phase-scoped runs.
    """
    seen: set[str] = set()
    uniq: list[str] = []
    for spec in specs:
        for idx in _indices_for_tools(spec.expected_tools, cfg):
            if idx not in seen:
                seen.add(idx)
                uniq.append(idx)
    return uniq


# --- ES client (injectable) --------------------------------------------------


class ESClient(Protocol):
    """Minimal Elasticsearch surface the preflight needs.

    Tests supply a stub implementing this Protocol so no live ES is required.
    """

    def ping(self) -> tuple[bool, str]:
        """(reachable, detail). Never raises."""

    def count(self, index: str) -> int | None:
        """Doc count for a single index; None if the index is missing (404)."""

    def max_timestamp(self, indices: list[str]) -> datetime | None:
        """Max @timestamp across the given indices, or None if unavailable."""

    def probe_hits(self, indices: list[str], window_hours: int) -> int:
        """Count docs in [now-window_hours, now] across indices (0 if none)."""


class HttpxESClient:
    """Real ESClient over sync httpx — same dependency as scripts/ingest_ef.py.

    All searches pass ``ignore_unavailable`` + ``allow_no_indices`` so a missing
    index in the explicit (non-wildcard) pattern degrades to "no data" instead
    of a 404 index_not_found_exception — otherwise the window check would error
    out in exactly the missing-index case preflight exists to catch.
    """

    def __init__(self, cfg: ServerConfig, *, timeout: float | None = None) -> None:
        self.url = cfg.elastic.url.rstrip("/")
        self.verify_ssl = cfg.elastic.verify_ssl
        self._auth = (
            (cfg.elastic.user, cfg.elastic.password)
            if cfg.elastic.user and cfg.elastic.password
            else None
        )
        self.timeout = timeout if timeout is not None else float(cfg.limits.query_timeout)

    def _client(self, timeout: float | None = None) -> httpx.Client:
        return httpx.Client(
            verify=self.verify_ssl,
            auth=self._auth,
            timeout=timeout if timeout is not None else self.timeout,
        )

    def ping(self) -> tuple[bool, str]:
        try:
            with self._client(timeout=min(self.timeout, 5.0)) as c:
                r = c.get(f"{self.url}/_cluster/health")
            if r.status_code == 200:
                status = r.json().get("status", "unknown")
                return True, f"cluster health: {status}"
            return False, f"HTTP {r.status_code} from {self.url}/_cluster/health"
        except httpx.HTTPError as e:
            return False, f"unreachable at {self.url}: {type(e).__name__}: {e}"

    def count(self, index: str) -> int | None:
        try:
            with self._client() as c:
                r = c.get(f"{self.url}/{index}/_count")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return int(r.json().get("count", 0))
        except httpx.HTTPError as e:
            raise ESError(f"count({index}) failed: {type(e).__name__}: {e}") from e

    def _search(self, indices: list[str], body: dict) -> dict:
        idx = ",".join(indices)
        params = {"ignore_unavailable": "true", "allow_no_indices": "true"}
        try:
            with self._client() as c:
                r = c.post(f"{self.url}/{idx}/_search", params=params, json=body)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as e:
            raise ESError(f"search({idx}) failed: {type(e).__name__}: {e}") from e

    def max_timestamp(self, indices: list[str]) -> datetime | None:
        body = {"size": 0, "aggs": {"max_ts": {"max": {"field": "@timestamp"}}}}
        data = self._search(indices, body)
        vs = data.get("aggregations", {}).get("max_ts", {}).get("value_as_string")
        if not vs:
            return None
        return _parse_ts(vs)

    def probe_hits(self, indices: list[str], window_hours: int) -> int:
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"range": {"@timestamp": {"gte": f"now-{window_hours}h", "lte": "now"}}},
        }
        data = self._search(indices, body)
        return int(data.get("hits", {}).get("total", {}).get("value", 0))


class ESError(RuntimeError):
    """Transport/query failure talking to ES; caught and turned into a failed check."""


def _parse_ts(value: str) -> datetime | None:
    """Parse an ES @timestamp string to an aware UTC datetime."""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --- report structures -------------------------------------------------------


@dataclass
class PreflightCheck:
    name: str
    passed: bool
    detail: str
    critical: bool = True


@dataclass
class PreflightReport:
    config_path: str
    checks: list[PreflightCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Fail-closed: True only if every critical check passed."""
        return all(c.passed for c in self.checks if c.critical)

    def add(self, name: str, passed: bool, detail: str, *, critical: bool = True) -> PreflightCheck:
        chk = PreflightCheck(name=name, passed=passed, detail=detail, critical=critical)
        self.checks.append(chk)
        return chk

    def summary(self) -> str:
        lines = [f"Blue-Bench preflight — config: {self.config_path}"]
        for c in self.checks:
            mark = "PASS" if c.passed else "FAIL"
            crit = "" if c.critical else " (non-critical)"
            lines.append(f"  [{mark}] {c.name}{crit}: {c.detail}")
        verdict = "OK — safe to run" if self.ok else "NOT OK — do not run (fail-closed)"
        lines.append(f"==> {verdict}")
        return "\n".join(lines)


# --- checks ------------------------------------------------------------------


def run_preflight(
    config_path: str | Path,
    prompts_dir: str | Path | None = None,
    *,
    now_tolerance_hours: int = 48,
    probe_window_hours: int | None = None,
    prompts_prefix: str = "p",
    client: ESClient | None = None,
) -> PreflightReport:
    """Run the fail-closed readiness checks and return a structured report.

    Args:
        config_path: path to the MCP server config.yaml (ElasticConfig lives here).
        prompts_dir: if given, run the per-prompt probe (check 4) over these prompts.
        now_tolerance_hours: max allowed gap between now and the corpus max
            @timestamp before the window check fails.
        probe_window_hours: now-relative lookback for per-prompt probes. Defaults
            to a generous window (>= corpus span) so a healthy corpus whose data
            for one index clusters early in the span is not false-failed, while a
            fully-stale (un-anchored) corpus still yields 0 hits.
        prompts_prefix: glob prefix for the per-prompt probe. Defaults to ``"p"``
            (all tiers). A phase-scoped run should pass ``f"p{phase}-"`` so a
            phase-2 run does not demand phase-1/3 indices be populated too.
        client: injectable ESClient (tests supply a stub). Defaults to a real
            httpx-backed client built from the config.
    """
    config_path = Path(config_path)
    report = PreflightReport(config_path=str(config_path))

    cfg = load_config(config_path)
    if client is None:
        client = HttpxESClient(cfg)
    if probe_window_hours is None:
        # Generous: cover the whole corpus span, not just the tolerance window.
        probe_window_hours = max(now_tolerance_hours, 30 * 24)

    # Load the selected prompt slate once (if a prompts dir was given) so checks
    # 2 and 3 can scope to the indices the run actually reads — not the
    # config-total union, which would over-demand and break phase-scoped runs.
    specs: list = []
    if prompts_dir is not None:
        from blue_bench_eval.prompts._schema import load_all

        specs = load_all(Path(prompts_dir), prefix=prompts_prefix)
        seen_ids: set[str] = set()
        ordered = []
        for s in specs:
            if s.id not in seen_ids:
                seen_ids.add(s.id)
                ordered.append(s)
        specs = ordered

    # The indices this run's prompts read. When no prompts dir is given (a bare
    # `preflight --config` invocation), fall back to index_pattern — the only
    # thing we can know without a slate.
    scoped_indices = _indices_for_specs(specs, cfg) if specs else _split_pattern(cfg.elastic.index_pattern)

    # --- check 1: ES reachable ---
    reachable, ping_detail = client.ping()
    report.add("es_reachable", reachable, ping_detail)
    if not reachable:
        # Fail fast: every downstream check needs ES. Report them as failed
        # (not silently skipped) so the guard stays fail-closed and legible.
        report.add("indices_populated", False, "skipped: ES unreachable")
        report.add("window_covers_now", False, "skipped: ES unreachable")
        if prompts_dir is not None:
            report.add("prompt_probes", False, "skipped: ES unreachable")
        return report

    # --- check 2: every index the selected slate reads exists and has docs ---
    _check_indices_populated(cfg, client, report, scoped_indices)

    # --- check 3: corpus window covers now (per-index, scoped) ---
    _check_window_covers_now(cfg, client, report, now_tolerance_hours, scoped_indices)

    # --- check 4: per-prompt probes ---
    if prompts_dir is not None:
        _check_prompt_probes(
            cfg, client, report, specs, probe_window_hours
        )

    return report


def _check_indices_populated(
    cfg: ServerConfig, client: ESClient, report: PreflightReport, indices: list[str]
) -> None:
    # Enumerate every index the SELECTED slate reads (scoped by the caller), not
    # just index_pattern — otherwise an empty auth/Sysmon/OT index slips through
    # while the alert indices are healthy (the exact void-grade failure this gate
    # exists to catch). Scoping to the slate (not the config-total union) is what
    # keeps a phase-2 run from demanding indices it never touches.
    counts: dict[str, int | None] = {}
    try:
        for idx in indices:
            counts[idx] = client.count(idx)
    except ESError as e:
        report.add("indices_populated", False, str(e))
        return
    optional = _optional_indices(cfg)
    # An ABSENT optional index is a deployment shape, not a fault (see
    # _optional_indices). Present-but-empty stays critical for every index:
    # the index existing means ingest created it and wrote nothing.
    absent_optional = [i for i, n in counts.items() if n is None and i in optional]
    missing = [i for i, n in counts.items() if n is None and i not in optional]
    empty = [i for i, n in counts.items() if n == 0]
    detail_parts = [
        f"{i}={'MISSING' if counts[i] is None else counts[i]}" for i in indices
    ]
    detail = "; ".join(detail_parts)
    if missing or empty:
        problems = []
        if missing:
            problems.append(f"missing: {', '.join(missing)}")
        if empty:
            problems.append(f"empty: {', '.join(empty)}")
        report.add("indices_populated", False, f"{detail} ({'; '.join(problems)})")
    else:
        report.add("indices_populated", True, detail)
    if absent_optional:
        report.add(
            "optional_indices_absent",
            True,
            f"not present, tolerated: {', '.join(absent_optional)} — the tools "
            "query with ignore_unavailable, so prompts reading them degrade to "
            "no-data rather than erroring",
            critical=False,
        )


def _check_window_covers_now(
    cfg: ServerConfig,
    client: ESClient,
    report: PreflightReport,
    now_tolerance_hours: int,
    indices: list[str],
) -> None:
    # Check each index's max @timestamp INDIVIDUALLY. A single max agg over the
    # union would let one fresh index mask six stale ones — the same OR flaw the
    # per-prompt probe had. Every index the selected slate reads must cover now.
    now = datetime.now(timezone.utc)
    optional = _optional_indices(cfg)
    stale: list[str] = []
    no_ts: list[str] = []
    absent_optional: list[str] = []
    details: list[str] = []
    try:
        for idx in indices:
            max_ts = client.max_timestamp([idx])
            if max_ts is None:
                # An absent optional index has no @timestamp because it does not
                # exist — a deployment shape, not a stale window. A present
                # optional index that IS stale still lands in `stale` below.
                if idx in optional and client.count(idx) is None:
                    absent_optional.append(idx)
                else:
                    no_ts.append(idx)
                continue
            gap_hours = (now - max_ts).total_seconds() / 3600.0
            if gap_hours < 0:
                gap_desc = f"{abs(gap_hours):.1f}h in the future"
            else:
                gap_desc = f"{gap_hours:.1f}h ago"
            details.append(f"{idx}: {max_ts.isoformat()} ({gap_desc})")
            if gap_hours > now_tolerance_hours:
                stale.append(idx)
    except ESError as e:
        report.add("window_covers_now", False, str(e))
        return
    # Report BOTH failure classes together — an early return on no_ts would hide
    # a concurrent stale index (and vice versa).
    passed = not stale and not no_ts
    detail = "; ".join(details) + f"; tolerance = {now_tolerance_hours}h"
    if absent_optional:
        detail += f" — absent (optional, tolerated): {', '.join(absent_optional)}"
    if no_ts:
        detail += (
            f" — no @timestamp in: {', '.join(no_ts)} (empty corpus or "
            "missing/mismatched @timestamp field)"
        )
    if stale:
        detail += (
            f" — STALE: {', '.join(stale)} end before now, so lookback-from-now "
            "queries will miss data (un-anchored ingest? re-run ingest with "
            "--anchor-end-to-now)"
        )
    report.add("window_covers_now", passed, detail)


def _check_prompt_probes(
    cfg: ServerConfig,
    client: ESClient,
    report: PreflightReport,
    specs: list,
    probe_window_hours: int,
) -> None:
    if not specs:
        report.add(
            "prompt_probes",
            False,
            "no prompts found",
        )
        return

    for spec in specs:
        indices = _indices_for_tools(spec.expected_tools, cfg)
        name = f"probe:{spec.id}"
        if not indices:
            # No ES-backed tools — nothing to probe; must not drag ok false.
            report.add(
                name,
                True,
                f"n/a: no ES-backed tools (expected_tools={spec.expected_tools})",
                critical=False,
            )
            continue
        # Probe each index INDIVIDUALLY and require EVERY one to have data. A
        # single union search would pass if ANY index has data — so an auth-only
        # prompt whose auth indices are empty would be masked by the alert
        # indices (the exact void-grade failure this gate exists to catch).
        optional = _optional_indices(cfg)
        empty_indices: list[str] = []
        per_index: list[str] = []
        try:
            for idx in indices:
                hits = client.probe_hits([idx], probe_window_hours)
                # probe_hits uses ignore_unavailable, so a MISSING index and a
                # present-but-empty one both read 0. Distinguish via count():
                # an absent optional index is tolerated here (check 2 reports it
                # non-critically); present-but-empty stays a probe failure.
                if hits < 1 and idx in optional and client.count(idx) is None:
                    per_index.append(f"{idx}=absent(optional)")
                    continue
                per_index.append(f"{idx}={hits}")
                if hits < 1:
                    empty_indices.append(idx)
        except ESError as e:
            report.add(name, False, str(e))
            continue
        passed = not empty_indices
        detail = (
            f"docs in last {probe_window_hours}h: " + ", ".join(per_index)
        )
        if not passed:
            detail += (
                f" — SIEM empty for {', '.join(empty_indices)} within the "
                "lookback window"
            )
        report.add(name, passed, detail)


# --- CLI ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m blue_bench_eval.preflight",
        description="Fail-closed corpus/SIEM readiness guard for a Blue-Bench run.",
    )
    p.add_argument("--config", required=True, type=Path, help="MCP server config.yaml")
    p.add_argument(
        "--prompts",
        type=Path,
        default=None,
        help="Prompts dir (enables per-prompt probe, e.g. blue_bench_eval/prompts)",
    )
    p.add_argument(
        "--now-tolerance-hours",
        type=int,
        default=48,
        help="Max gap (hours) between now and corpus max @timestamp (default: 48)",
    )
    args = p.parse_args(argv)

    report = run_preflight(
        args.config,
        prompts_dir=args.prompts,
        now_tolerance_hours=args.now_tolerance_hours,
    )
    print(report.summary())
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
