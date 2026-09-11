"""Hostname <-> IP resolution for slice scoping.

Unit path: a stubbed ``_agg`` returns fixed aggregation responses, so the
source order, the ``.keyword`` field names, the window filter and the cache are
all verified without ES. Live path: when ES is up, the one join the whole
feature rests on -- wkst-03's FQDN to 10.10.0.13 and back.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from blue_bench_client.fanout.host_resolve import (
    DHCP_INDEX,
    EDR_INDEX,
    SYSMON_INDEX,
    HostResolver,
    complete_slice_scope,
)
from blue_bench_client.fanout.schema import Slice, SliceFilters

ES_URL = "http://localhost:9200"
HOST = "wkst-03.corp.example.invalid"
HOST_IP = "10.10.0.13"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


def _dhcp_populated() -> bool:
    import httpx
    try:
        r = httpx.get(f"{ES_URL}/{DHCP_INDEX}/_count", timeout=2.0)
        return r.status_code == 200 and r.json().get("count", 0) > 0
    except (httpx.HTTPError, ValueError):
        return False


requires_corpus = pytest.mark.skipif(
    not (_es_reachable() and _dhcp_populated()),
    reason="Elasticsearch / zeek-dhcp not available",
)


def _terms_agg(*values: str) -> dict:
    return {"aggregations": {"values": {"buckets": [{"key": v, "doc_count": 1} for v in values]}}}


def _dhcp_names_agg(*pairs: tuple[str, str]) -> dict:
    """A host_name terms agg with the domain sub-agg the IP->host lookup reads."""
    return {"aggregations": {"values": {"buckets": [
        {"key": n, "doc_count": 1,
         "domain": {"buckets": [{"key": d, "doc_count": 1}] if d else []}}
        for n, d in pairs
    ]}}}


class StubResolver(HostResolver):
    """A resolver whose ES round trip is a lookup table.

    ``replies`` maps an index name to a list of responses served in order, so a
    test can say what the first source answers and what the next one does. Every
    request body is recorded, which is how the cache test proves a second call
    issued nothing.
    """

    def __init__(self, replies: dict[str, list[dict]]) -> None:
        super().__init__(ES_URL)
        self.replies = {k: list(v) for k, v in replies.items()}
        self.calls: list[tuple[str, dict]] = []

    async def _agg(self, index: str, body: dict) -> dict:
        self.calls.append((index, body))
        queue = self.replies.get(index) or []
        return queue.pop(0) if queue else _terms_agg()


def _run(coro):
    return asyncio.run(coro)


# --- host -> ip ---------------------------------------------------------------

def test_ips_from_dhcp_first():
    r = StubResolver({DHCP_INDEX: [_terms_agg(HOST_IP)]})
    assert _run(r.ips_for_host(HOST)) == [HOST_IP]
    # The lease answered, so no other index was asked.
    assert [c[0] for c in r.calls] == [DHCP_INDEX]


def test_ips_query_uses_keyword_fields_and_both_spellings():
    r = StubResolver({DHCP_INDEX: [_terms_agg(HOST_IP)]})
    _run(r.ips_for_host(HOST))
    _index, body = r.calls[0]
    must = body["query"]["bool"]["must"]
    assert must[0] == {"terms": {"host_name.keyword": ["wkst-03", HOST]}}
    assert body["aggs"]["values"]["terms"]["field"] == "assigned_addr.keyword"
    assert body["size"] == 0


def test_ips_fall_through_dhcp_to_sysmon():
    # dhcp answers nothing on either address field, sysmon knows the host.
    r = StubResolver({
        DHCP_INDEX: [_terms_agg(), _terms_agg()],
        SYSMON_INDEX: [_terms_agg("10.20.0.10")],
    })
    res = _run(r.resolve_ips("dc-01.corp.example.invalid"))
    assert res.values == ["10.20.0.10"]
    assert res.source == SYSMON_INDEX
    sysmon_body = [b for i, b in r.calls if i == SYSMON_INDEX][0]
    must = sysmon_body["query"]["bool"]["must"]
    assert {"term": {"EventID": 3}} in must
    assert sysmon_body["aggs"]["values"]["terms"]["field"] == "SourceIp.keyword"


def test_ips_fall_through_to_edr_for_a_linux_server():
    r = StubResolver({
        DHCP_INDEX: [_terms_agg(), _terms_agg()],
        SYSMON_INDEX: [_terms_agg()],
        EDR_INDEX: [_terms_agg("10.20.0.32")],
    })
    res = _run(r.resolve_ips("srv-app-03"))
    assert res.values == ["10.20.0.32"]
    assert res.source == EDR_INDEX
    edr_body = [b for i, b in r.calls if i == EDR_INDEX][0]
    must = edr_body["query"]["bool"]["must"]
    assert {"term": {"properties.direction.keyword": "OUTBOUND"}} in must
    assert {"terms": {"hostname.keyword": ["srv-app-03"]}} in must


def test_ips_multi_address_returns_all():
    r = StubResolver({DHCP_INDEX: [_terms_agg("10.10.0.13", "10.10.0.99")]})
    assert _run(r.ips_for_host(HOST)) == ["10.10.0.13", "10.10.0.99"]


def test_ips_placeholder_addresses_are_dropped():
    r = StubResolver({
        DHCP_INDEX: [_terms_agg("0.0.0.0"), _terms_agg(HOST_IP)],
    })
    # 0.0.0.0 is a DHCP DISCOVER, not an address the host held; the lookup
    # falls on to client_addr rather than binding the slice to it.
    assert _run(r.ips_for_host(HOST)) == [HOST_IP]


def test_ips_unknown_host_is_empty_not_an_error():
    r = StubResolver({})
    res = _run(r.resolve_ips("hmi-03.plant.example.invalid"))
    assert res.values == []
    assert res.source == ""


def test_short_and_fqdn_share_one_lookup():
    r = StubResolver({DHCP_INDEX: [_terms_agg(HOST_IP)]})

    async def both():
        return await r.ips_for_host("wkst-03"), await r.ips_for_host(HOST)

    a, b = _run(both())
    assert a == b == [HOST_IP]
    assert len(r.calls) == 1


def test_cache_is_per_window():
    r = StubResolver({DHCP_INDEX: [_terms_agg("10.10.0.13"), _terms_agg("10.10.0.99")]})

    async def two_windows():
        first = await r.ips_for_host(HOST, since="2026-08-25T00:00:00Z")
        second = await r.ips_for_host(HOST, since="2026-09-01T00:00:00Z")
        return first, second

    first, second = _run(two_windows())
    assert (first, second) == (["10.10.0.13"], ["10.10.0.99"])
    assert len(r.calls) == 2
    assert r.calls[0][1]["query"]["bool"]["must"][1] == {
        "range": {"@timestamp": {"gte": "2026-08-25T00:00:00Z"}}
    }


# --- ip -> host ---------------------------------------------------------------

def test_hosts_from_dhcp_are_qualified_with_the_domain():
    r = StubResolver({DHCP_INDEX: [_dhcp_names_agg(("wkst-03", "corp.example.invalid"))]})
    res = _run(r.resolve_hosts(HOST_IP))
    assert res.values == [HOST]
    assert res.source == DHCP_INDEX


def test_hosts_from_sysmon_are_already_fqdns():
    r = StubResolver({
        DHCP_INDEX: [_dhcp_names_agg()],
        SYSMON_INDEX: [_terms_agg("dc-01.corp.example.invalid")],
    })
    assert _run(r.hosts_for_ip("10.20.0.10")) == ["dc-01.corp.example.invalid"]


def test_hosts_from_edr_stay_short_because_no_domain_is_known():
    r = StubResolver({
        DHCP_INDEX: [_dhcp_names_agg()],
        SYSMON_INDEX: [_terms_agg()],
        EDR_INDEX: [_terms_agg("srv-app-03")],
    })
    res = _run(r.resolve_hosts("10.20.0.32"))
    assert res.values == ["srv-app-03"]
    assert res.source == EDR_INDEX


def test_hosts_multi_and_empty():
    r = StubResolver({DHCP_INDEX: [_dhcp_names_agg(
        ("wkst-03", "corp.example.invalid"), ("wkst-17", "corp.example.invalid"))]})
    assert _run(r.hosts_for_ip(HOST_IP)) == [HOST, "wkst-17.corp.example.invalid"]
    assert _run(StubResolver({}).hosts_for_ip("10.99.0.1")) == []


def test_hosts_cached():
    r = StubResolver({DHCP_INDEX: [_dhcp_names_agg(("wkst-03", "corp.example.invalid"))]})

    async def twice():
        return await r.hosts_for_ip(HOST_IP), await r.hosts_for_ip(HOST_IP)

    a, b = _run(twice())
    assert a == b == [HOST]
    assert len(r.calls) == 1


# --- complete_slice_scope -----------------------------------------------------

def _slice(**filters) -> Slice:
    return Slice(
        id="s03",
        question="What ran on wkst-03?",
        filters=SliceFilters(**filters),
        turn_budget=6,
        rationale="the attacked host class",
    )


def test_complete_fills_ips_and_marks_them():
    r = StubResolver({DHCP_INDEX: [_terms_agg(HOST_IP)]})
    sl = _slice(hosts=[HOST])
    done, record = _run(complete_slice_scope(sl, r))
    assert done.filters.hosts == [HOST]
    assert done.filters.host_ips == [HOST_IP]
    assert record["hosts"] == {"supplied": [HOST], "resolved": []}
    assert record["host_ips"] == {"supplied": [], "resolved": [HOST_IP]}
    assert record["sources"] == {HOST: DHCP_INDEX}
    assert done.resolved == record
    # The lead's own slice object is untouched: the judge scores what it wrote.
    assert sl.filters.host_ips == []
    assert sl.resolved == {}


def test_complete_fills_hosts_from_an_ip():
    r = StubResolver({DHCP_INDEX: [_dhcp_names_agg(("wkst-03", "corp.example.invalid"))]})
    done, record = _run(complete_slice_scope(_slice(host_ips=[HOST_IP]), r))
    assert done.filters.hosts == [HOST]
    assert record["hosts"]["resolved"] == [HOST]
    assert record["host_ips"]["supplied"] == [HOST_IP]


def test_complete_does_not_re_add_a_host_the_lead_already_named():
    # The lead named the FQDN and the address; the IP->host lookup answers with
    # the short name, which must not be appended as a second host.
    r = StubResolver({
        DHCP_INDEX: [_terms_agg(HOST_IP), _dhcp_names_agg(("wkst-03", ""))],
    })
    done, record = _run(complete_slice_scope(_slice(hosts=[HOST], host_ips=[HOST_IP]), r))
    assert done.filters.hosts == [HOST]
    assert done.filters.host_ips == [HOST_IP]
    assert record["hosts"]["resolved"] == []
    assert record["host_ips"]["resolved"] == []


def test_complete_records_what_the_corpus_cannot_resolve():
    r = StubResolver({})
    ot = "hmi-03.plant.example.invalid"
    done, record = _run(complete_slice_scope(_slice(hosts=[ot]), r))
    assert done.filters.host_ips == []
    assert record["unresolved"] == [ot]
    assert record["sources"] == {}


def test_complete_uses_the_slice_time_band():
    r = StubResolver({DHCP_INDEX: [_terms_agg(HOST_IP)]})
    sl = _slice(
        hosts=[HOST],
        time_start=datetime(2026, 8, 25, tzinfo=timezone.utc),
        time_end=datetime(2026, 8, 27, tzinfo=timezone.utc),
    )
    _done, record = _run(complete_slice_scope(sl, r))
    assert record["window"] == {"since": "2026-08-25T00:00:00Z", "until": "2026-08-27T00:00:00Z"}
    assert r.calls[0][1]["query"]["bool"]["must"][1] == {"range": {"@timestamp": {
        "gte": "2026-08-25T00:00:00Z", "lte": "2026-08-27T00:00:00Z"}}}


def test_complete_without_a_resolver_is_a_no_op():
    sl = _slice(hosts=[HOST])
    done, record = _run(complete_slice_scope(sl, None))
    assert done.filters.hosts == [HOST]
    assert done.filters.host_ips == []
    assert record["hosts"]["resolved"] == [] and record["sources"] == {}


# --- live ---------------------------------------------------------------------

@requires_corpus
def test_live_round_trip_wkst_03():
    r = HostResolver(ES_URL)
    ips = _run(r.resolve_ips(HOST))
    assert ips.values == [HOST_IP], ips
    assert ips.source == DHCP_INDEX
    back = _run(r.resolve_hosts(HOST_IP))
    assert back.values == [HOST], back
    assert back.source == DHCP_INDEX


@requires_corpus
def test_live_short_name_resolves_the_same():
    r = HostResolver(ES_URL)
    assert _run(r.ips_for_host("wkst-03")) == [HOST_IP]


@requires_corpus
def test_live_static_windows_server_comes_from_sysmon():
    # dc-01 takes no DHCP lease, so the lease record cannot answer and the
    # Sysmon network-connection records must.
    r = HostResolver(ES_URL)
    res = _run(r.resolve_ips("dc-01.corp.example.invalid"))
    assert res.values == ["10.20.0.10"], res
    assert res.source == SYSMON_INDEX
