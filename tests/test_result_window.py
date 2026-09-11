"""Issue #43 — what a capped tool response tells the model, and what it drops.

Measured 2026-09-11 against the live L corpus (11.86M docs, 1,666 injected
adversary records) through the real tool code at repo defaults
(``max_results=500``, ``max_result_chars=8000``):

* ``get_process_events(event_id=1)`` over the full window matched 192,624
  documents. The tool fetched the newest 500, showed 5, and its footer said
  ``showing 5 of those 500`` -- the model is told it is seeing 1% when it is
  seeing 0.003%. ``_query`` discards ``hits.total``. That is **defect A**: the
  footer states something false about the result set.

* Every list tool fetches ``size=max_results`` sorted by ``@timestamp``
  (``desc`` everywhere except ``get_process_tree``, whose two lists are
  ``asc`` so a tree reads parent-first) and then keeps the HEAD of that list
  until ``max_result_chars`` is spent. Injected
  adversary records that are inside the fetched set but past the byte boundary
  are dropped, always, because the cut is head-only. That is **defect B**.
  Which records SHOULD survive is a selection-policy decision that #43 leaves
  open (it must not know which records are injected), so that test is xfail
  until the policy is chosen.

* ``get_process_tree`` runs two queries whose result sets overlap: the self
  query ORs ``ParentProcessGuid == guid``, so every child is also a self hit.
  Its first footer summed the two totals (8,654 for a guid with 4,481 distinct
  matches) and said ``newest`` for an ``asc`` page. That is defect A again,
  on the tool #43 lists as affected, and the third test pins it.

No live ES: both defects are in the response-building path, so the HTTP layer
is faked and the tests always run.
"""
from __future__ import annotations

import json

import pytest

from blue_bench_mcp.config import (
    AuthConfig,
    ElasticConfig,
    LimitsConfig,
    ServerConfig,
    SysmonConfig,
    WazuhConfig,
    ZeekConfig,
)
from blue_bench_mcp.tool_classes import elastic as elastic_mod
from blue_bench_mcp.tool_classes.elastic import ElasticTool

# Repo defaults (config.yaml / LimitsConfig), not a test-sized budget: the
# claim under test is about what ships.
MAX_RESULTS = 500
MAX_CHARS = 8000
TOTAL_MATCHED = 192_624
INJECTED_HOST = "wkst-03.corp.example.invalid"
# get_process_tree, live 2026-09-11, guid {f5d9ec1b-24d8-69a1-9c00-0010167845df}:
# 4,481 distinct docs match self-or-children; 4,173 of them are children.
TREE_SELF_TOTAL = 4_481
TREE_CHILD_TOTAL = 4_173


def _cfg() -> ServerConfig:
    return ServerConfig(
        elastic=ElasticConfig(url="http://localhost:9200", index_pattern="bb-test-*"),
        zeek=ZeekConfig(index="bb-test-*", use_elastic=True),
        sysmon=SysmonConfig(index="windows-sysmon"),
        auth=AuthConfig(),
        wazuh=WazuhConfig(),
        limits=LimitsConfig(
            max_results=MAX_RESULTS, max_result_chars=MAX_CHARS, query_timeout=5
        ),
    )


def _record(i: int, host: str) -> dict:
    """A Sysmon process-create shaped like the live corpus (~580 B pretty)."""
    return {
        "EventID": 1,
        "EventRecordID": str(2814000 + i),
        "Computer": host,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -EncodedCommand " + "QQBB" * 40,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\user%02d" % (i % 24),
        "Hashes": "SHA256=" + "ab" * 32,
        # newest first, one record per minute, like a desc-sorted ES page
        "@timestamp": f"2026-09-11T{15 - i // 60:02d}:{59 - i % 60:02d}:09.271536+00:00",
    }


def _fetched_page(n: int = MAX_RESULTS, injected_at: tuple[int, ...] = ()) -> list[dict]:
    """The ``size=500 desc`` page ES hands back: benign tail, adversary deeper."""
    def benign_host(i: int) -> str:
        n = i % 20 + 1
        n = n if n < 3 else n + 1          # never the injected host
        return f"wkst-{n:02d}.corp.example.invalid"
    return [
        _record(i, INJECTED_HOST if i in injected_at else benign_host(i))
        for i in range(n)
    ]


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Stands in for ``httpx.AsyncClient`` so the REAL ``_search`` runs.

    ``pages`` queues one ``(hits, total)`` per ``post`` for tools that issue
    several queries (``get_process_tree``: self, then children); the last
    page repeats once the queue is exhausted.
    """

    last_body: dict | None = None

    def __init__(self, hits: list[dict], total: int,
                 *more: tuple[list[dict], int]) -> None:
        self._pages = [(hits, total), *more]

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, **k):
        _FakeClient.last_body = json
        hits, total = self._pages.pop(0) if len(self._pages) > 1 else self._pages[0]
        self._hits, self._total = hits, total
        return _FakeResponse({
            "hits": {
                # ES 8 reports {value: 10000, relation: "gte"} unless the query
                # sets track_total_hits; the fake mirrors that so a fix cannot
                # pass by reading a capped number.
                "total": ({"value": self._total, "relation": "eq"}
                          if (json or {}).get("track_total_hits") is True
                          else {"value": min(self._total, 10_000),
                                "relation": "eq" if self._total <= 10_000 else "gte"}),
                "hits": [{"_index": "windows-sysmon", "_id": str(i), "_source": h}
                         for i, h in enumerate(self._hits)],
            }
        })


def _body_and_footer(out: str) -> tuple[list, str]:
    body, _, footer = out.partition("\n\n---")
    return json.loads(body), footer


@pytest.mark.asyncio
async def test_footer_reports_the_true_match_total_not_the_page_size(monkeypatch):
    """Defect A. 192,624 matched; the page was 500; the model must be told 192,624.

    Today the footer reads ``showing N of those 500 (size limit)`` -- the
    ``500`` is the page size, presented as if it were the result set.
    """
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient",
                        _FakeClient(_fetched_page(), TOTAL_MATCHED))
    out = await tool.get_process_events(event_id=1, timerange_minutes=43_200)
    records, footer = _body_and_footer(out)
    assert 0 < len(records) < MAX_RESULTS, "precondition: the size limit bit"
    shown = len(records)
    assert (f"{TOTAL_MATCHED}" in footer or f"{TOTAL_MATCHED:,}" in footer), (
        f"footer must carry the true match total ({TOTAL_MATCHED}); got: {footer!r}")
    assert f"of those {MAX_RESULTS}" not in footer, (
        "footer presents the page size as the result-set size: " + footer)
    assert str(shown) in footer


@pytest.mark.asyncio
async def test_true_total_is_not_the_ten_thousand_cap(monkeypatch):
    """Defect A, the trap: without ``track_total_hits`` ES says ">=10000".

    A footer that prints ``10000`` for a 192,624-record match is wrong in a
    new and more plausible way than ``500``.
    """
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient",
                        _FakeClient(_fetched_page(), TOTAL_MATCHED))
    out = await tool.get_process_events(event_id=1, timerange_minutes=43_200)
    _, footer = _body_and_footer(out)
    assert "10000" not in footer and "10,000" not in footer, footer
    assert _FakeClient.last_body.get("track_total_hits") is True, (
        "the query must ask ES for the real total")


@pytest.mark.xfail(
    strict=True,
    reason="#43 defect B: the char cut keeps the head of a desc-sorted page, so "
           "adversary records inside the fetched set but past the byte boundary "
           "are dropped every time. Which records survive is the selection-policy "
           "decision #43 leaves to Max; unmark when it is made.",
)
@pytest.mark.asyncio
async def test_injected_records_inside_the_fetched_page_survive_the_cut(monkeypatch):
    """Defect B. Three adversary records sit at positions 40-42 of the 500-record
    page (the live measurement had them at 300-302). At repo defaults the tool
    shows ~12 of these records. At least one of the three must be in the response.

    The tool has no way to know these are the injected ones -- and must not.
    The assertion is satisfiable only by a selection that is not head-only.
    """
    tool = ElasticTool(_cfg())
    page = _fetched_page(injected_at=(40, 41, 42))
    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient",
                        _FakeClient(page, TOTAL_MATCHED))
    out = await tool.get_process_events(event_id=1, timerange_minutes=43_200)
    records, _ = _body_and_footer(out)
    assert len(records) < 40, "precondition: the byte budget cuts before position 40"
    assert any(r["Computer"] == INJECTED_HOST for r in records), (
        f"{len(records)} records shown, none from {INJECTED_HOST}; "
        "the head-only cut dropped every adversary record")


@pytest.mark.asyncio
async def test_tree_footer_reports_distinct_matches_and_the_oldest_page(monkeypatch):
    """Defect A on ``get_process_tree``: two overlapping queries, ``asc`` sort.

    Live: self 4,481 / children 4,173 (children are a subset of self). The
    footer must say 4,481, not the 8,654 sum, and ``oldest`` -- both tree
    queries sort ``@timestamp asc``, so the fetched page is the oldest 500 of
    each list, not the newest.
    """
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient",
                        _FakeClient(_fetched_page(), TREE_SELF_TOTAL,
                                    (_fetched_page(), TREE_CHILD_TOTAL)))
    out = await tool.get_process_tree(process_guid="{f5d9ec1b-24d8-69a1-9c00-0010167845df}")
    tree, footer = _body_and_footer(out)
    assert tree["self_and_parent"] and tree["children"], "precondition: both lists populated"
    assert f"{TREE_SELF_TOTAL:,}" in footer, footer
    assert f"{TREE_SELF_TOTAL + TREE_CHILD_TOTAL:,}" not in footer, (
        "footer double-counts the children: " + footer)
    assert "oldest" in footer and "newest" not in footer, footer
    assert f"{MAX_RESULTS} (self+parent) and {MAX_RESULTS} (children)" in footer, footer
