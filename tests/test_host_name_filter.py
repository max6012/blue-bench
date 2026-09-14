"""The shared host-name filter (blue_bench_mcp.es_queries) and every tool that
uses it.

The defect class this guards: a host filter that silently matches nothing or
everything. A bare ``term`` on ``Computer.keyword`` matched nothing for a
short name (the slice resolver returns one for hosts it learned from EDR); a
bare ``match`` on the text field matched every host in the domain (issue #46).

Offline: a tiny evaluator applies the clauses the way ES would on a keyword
subfield, so each tool's query is checked for what it MATCHES, not for its
literal shape. Live: the counts on the corpus for the short name, the FQDN and
the near-miss prefix ``wkst-1``.
"""
from __future__ import annotations

import pytest

from blue_bench_mcp.config import (
    ElasticConfig,
    LimitsConfig,
    ServerConfig,
    SysmonConfig,
)
from blue_bench_mcp.es_queries import host_name_clause, host_name_clauses
from blue_bench_mcp.tool_classes.auth import AuthTool
from blue_bench_mcp.tool_classes.elastic import ElasticTool

ES_URL = "http://localhost:9200"
SYSMON_INDEX = "windows-sysmon"
FQDN = "wkst-13.corp.example.invalid"
SHORT = "wkst-13"
# A wide absolute band: the corpus spans 18 days, so the band is not what
# differs between the two spellings.
SINCE, UNTIL = "2026-08-01T00:00:00Z", "2026-10-01T00:00:00Z"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


def _sysmon_populated() -> bool:
    import httpx
    try:
        r = httpx.get(f"{ES_URL}/{SYSMON_INDEX}/_count", timeout=2.0)
        return r.status_code == 200 and r.json().get("count", 0) > 0
    except (httpx.HTTPError, ValueError):
        return False


requires_sysmon = pytest.mark.skipif(
    not (_es_reachable() and _sysmon_populated()),
    reason="Elasticsearch / windows-sysmon not available",
)


def _cfg() -> ServerConfig:
    return ServerConfig(
        elastic=ElasticConfig(url=ES_URL),
        sysmon=SysmonConfig(index=SYSMON_INDEX),
        limits=LimitsConfig(max_results=50, max_result_chars=20000, query_timeout=5),
    )


# --- the evaluator: what a keyword-subfield clause matches --------------------

def _clause_matches(clause: dict, field: str, stored: str) -> bool:
    """Apply one should clause to a value stored in ``<field>.keyword``.

    Only the constructs the helper is allowed to emit are understood; an
    analyzed clause (``match``, ``match_phrase``) on the host field is the
    defect and fails the test outright.
    """
    (kind, spec), = clause.items()
    kw = f"{field}.keyword"
    assert kind in ("term", "prefix"), f"analyzed clause on a host field: {clause}"
    if kw not in spec:
        return False
    body = spec[kw]
    value, fold = (body["value"], body.get("case_insensitive", False)) if isinstance(body, dict) else (body, False)
    a, b = (stored.lower(), value.lower()) if fold else (stored, value)
    return a == b if kind == "term" else a.startswith(b)


def _bool_matches(bool_clause: dict, field: str, stored: str) -> bool:
    inner = bool_clause["bool"]
    assert inner["minimum_should_match"] == 1
    return any(_clause_matches(c, field, stored) for c in inner["should"]
               if any(k.startswith(field) for k in next(iter(c.values())).keys()))


def _host_bool(must: list[dict]) -> dict:
    """The one bool/should in ``must`` that carries a host-name clause."""
    found = [m for m in must if "bool" in m and any(
        any(k.startswith("Computer") for k in next(iter(c.values())).keys())
        for c in m["bool"]["should"])]
    assert len(found) == 1, f"expected exactly one host clause, got {found}"
    return found[0]


# --- the helper itself --------------------------------------------------------

@pytest.mark.parametrize("given", [SHORT, FQDN, SHORT.upper(), FQDN + "."])
def test_either_spelling_reaches_the_stored_fqdn(given):
    assert _bool_matches(host_name_clause(given, "Computer"), "Computer", FQDN)


@pytest.mark.parametrize("given", [SHORT, FQDN])
def test_either_spelling_reaches_the_stored_short_name(given):
    # linux-syslog stores the Linux servers' `host` as the bare label; a slice
    # that carries the FQDN must still find those records.
    assert _bool_matches(host_name_clause(given, "host"), "host", SHORT)


@pytest.mark.parametrize("given", ["wkst-1", "wkst", "wkst-13-old", "kst-13"])
def test_a_near_miss_matches_neither_spelling(given):
    # `wkst-1` is a token prefix of `wkst-13`, `wkst` is a whole shared token
    # (match_phrase on it matched 800,384 Sysmon documents live), and the
    # others are labels that merely contain the host's label. None may match.
    clause = host_name_clause(given, "Computer")
    assert not _bool_matches(clause, "Computer", FQDN)
    assert not _bool_matches(clause, "Computer", SHORT)


def test_an_fqdn_does_not_reach_a_sibling_in_another_domain():
    # The FQDN as given is matched exactly, and its label only against a
    # record that stores the bare label -- never against another FQDN.
    clause = host_name_clause(FQDN, "Computer")
    assert not _bool_matches(clause, "Computer", "wkst-13.plant.example.invalid")


def test_no_clause_is_analyzed():
    for given in (SHORT, FQDN):
        for c in host_name_clauses(given, "Computer"):
            (kind, spec), = c.items()
            assert kind in ("term", "prefix")
            assert list(spec) == ["Computer.keyword"]


def test_an_address_is_matched_whole_never_by_its_first_octet():
    # count_by_time passes an IP here for the Zeek indices. Splitting it on
    # the dot would add `term Computer.keyword = "10"` -- a clause that can
    # only widen the filter, in the code that exists to stop that.
    clauses = host_name_clauses("10.20.0.10", "Computer")
    assert clauses == [{"term": {"Computer.keyword": {"value": "10.20.0.10", "case_insensitive": True}}}]


def test_extra_clauses_ride_along():
    clause = host_name_clause("10.10.0.13", "Computer", extra=[{"term": {"id.orig_h": "10.10.0.13"}}])
    assert {"term": {"id.orig_h": "10.10.0.13"}} in clause["bool"]["should"]


# --- every host-taking tool builds a query that reaches the stored FQDN -------

def _process_events_must(tool: ElasticTool, host: str) -> list[dict]:
    return tool._build_process_events_query(host, "", "", "", 1, 240)["query"]["bool"]["must"]


def _tree_self_must(tool: ElasticTool, host: str) -> list[dict]:
    return tool._build_process_tree_self_query("{G}", host, 240)["query"]["bool"]["must"]


def _tree_children_must(tool: ElasticTool, host: str) -> list[dict]:
    return tool._build_process_tree_children_query("{G}", host, 240)["query"]["bool"]["must"]


async def _count_by_time_must(tool: ElasticTool, host: str) -> list[dict]:
    seen: dict = {}

    async def fake_agg(body, index=""):
        seen["body"] = body
        return {"aggregations": {"over_time": {"buckets": []}}}

    tool._agg = fake_agg  # type: ignore[method-assign]
    await tool.count_by_time(host=host)
    return seen["body"]["query"]["bool"]["must"]


async def _auth_must(host: str) -> list[dict]:
    tool = AuthTool(_cfg())
    seen: list[dict] = []

    async def fake_search(body):
        seen.append(body)
        return [], 0

    tool._search = fake_search  # type: ignore[method-assign]
    await tool.search_auth_events(host=host)
    return seen[0]["query"]["bool"]["must"]


@pytest.mark.parametrize("given", [SHORT, FQDN])
@pytest.mark.parametrize("build", [_process_events_must, _tree_self_must, _tree_children_must])
def test_sysmon_tools_reach_the_stored_fqdn(build, given):
    must = build(ElasticTool(_cfg()), given)
    assert _bool_matches(_host_bool(must), "Computer", FQDN)
    assert not _bool_matches(_host_bool(build(ElasticTool(_cfg()), "wkst-1")), "Computer", FQDN)


@pytest.mark.parametrize("given", [SHORT, FQDN])
async def test_count_by_time_reaches_the_stored_fqdn_and_short_name(given):
    must = await _count_by_time_must(ElasticTool(_cfg()), given)
    clause = _host_bool(must)
    assert _bool_matches(clause, "Computer", FQDN)
    assert _bool_matches(clause, "host", SHORT)
    # The address fields still ride along for the Zeek/OT indices.
    should = clause["bool"]["should"]
    assert {"term": {"id.orig_h": given}} in should and {"term": {"id.resp_h": given}} in should


@pytest.mark.parametrize("given", [SHORT, FQDN])
async def test_search_auth_events_reaches_both_substrates(given):
    clause = _host_bool(await _auth_must(given))
    assert _bool_matches(clause, "Computer", FQDN)       # windows-security
    assert _bool_matches(clause, "host", SHORT)          # linux-syslog, bare label
    assert _bool_matches(clause, "hostname", FQDN)       # linux-syslog sshd records


# --- live ---------------------------------------------------------------------

def _matched(result: str) -> int:
    import re
    m = re.search(r"matched ([\d,]+)", result)
    assert m, result[-300:]
    return int(m.group(1).replace(",", ""))


@requires_sysmon
async def test_live_short_name_and_fqdn_count_the_same():
    tool = ElasticTool(_cfg())
    short = _matched(await tool.get_process_events(host=SHORT, event_id=1, since=SINCE, until=UNTIL))
    fqdn = _matched(await tool.get_process_events(host=FQDN, event_id=1, since=SINCE, until=UNTIL))
    assert short == fqdn > 0, (short, fqdn)


@requires_sysmon
async def test_live_prefix_of_a_host_name_matches_nothing():
    # wkst-1 is not a host; it is a prefix of wkst-10..wkst-19. A filter that
    # returns anything for it is matching on tokens, not on the host.
    tool = ElasticTool(_cfg())
    out = await tool.get_process_events(host="wkst-1", event_id=1, since=SINCE, until=UNTIL)
    assert out.startswith("[]"), out[:300]
