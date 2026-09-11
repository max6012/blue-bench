"""Issue #41 — JSON-returning tools must return PARSEABLE JSON when truncated.

`guardrails.truncate_results` does head+tail splicing with a marker in the
middle. That is correct for free text and corrupting for JSON: the head stops
mid-object, the marker is not JSON, and the tail resumes mid-object. The result
still *looks* fine at both ends (starts `[{"Provider": ...`, ends `}\n]`), which
is why it survived so long, and `max_result_chars` defaults to 8000, so routine
results were affected.

Every tool here promises "Returns JSON-formatted array/object" in its docstring.
These tests hold them to it. No live ES: the defect is in serialization, not
retrieval, so `_query` is mocked and the tests always run.
"""
from __future__ import annotations

import json
import pathlib

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
from blue_bench_mcp.guardrails import json_dump_within
from blue_bench_mcp.tool_classes.auth import AuthTool
from blue_bench_mcp.tool_classes.elastic import ElasticTool
from blue_bench_mcp.tool_classes.wazuh import WazuhTool

# Small enough that any realistic record set overflows it.
MAX_CHARS = 4000
N_RECORDS = 60


def _fat_records(n: int = N_RECORDS) -> list[dict]:
    """Records shaped like real Sysmon/Zeek docs and big enough to overflow."""
    return [
        {
            "EventID": 1,
            "EventRecordID": str(2814000 + i),
            "Computer": f"wkst-{i:02d}.corp.example.invalid",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand " + "QQBB" * 40,
            "Hashes": "SHA256=" + "ab" * 32,
            "@timestamp": f"2026-09-09T14:{i % 60:02d}:09.271536+00:00",
        }
        for i in range(n)
    ]


def _json_part(out: str) -> str:
    """Strip the documented non-JSON decorations these tools add.

    A `\n\n--- ... ---` footer (the existing convention, which the live sysmon
    test already strips) and a leading `[source: ...]` line from get_agent_alerts.
    Anything left must parse.
    """
    body = out.split("\n\n---")[0]
    if body.startswith("[source:"):
        body = body.split("\n", 1)[1]
    return body


def _cfg() -> ServerConfig:
    return ServerConfig(
        elastic=ElasticConfig(url="http://localhost:9200", index_pattern="bb-test-*"),
        zeek=ZeekConfig(index="bb-test-*", use_elastic=True),
        sysmon=SysmonConfig(index="windows-sysmon"),
        auth=AuthConfig(),
        wazuh=WazuhConfig(),
        limits=LimitsConfig(max_results=50, max_result_chars=MAX_CHARS, query_timeout=5),
    )


# --- the helper ---------------------------------------------------------------

def test_json_dump_within_keeps_output_parseable_and_within_budget():
    recs = _fat_records()
    text, dropped = json_dump_within(recs, MAX_CHARS)
    assert len(text) <= MAX_CHARS
    parsed = json.loads(text)                      # must not raise
    assert isinstance(parsed, list)
    assert dropped > 0, "fixture must actually overflow, or this proves nothing"
    assert len(parsed) == len(recs) - dropped


def test_json_dump_within_is_a_noop_when_everything_fits():
    recs = _fat_records(2)
    text, dropped = json_dump_within(recs, 100_000)
    assert dropped == 0
    assert json.loads(text) == json.loads(json.dumps(recs, indent=2, default=str))


def test_json_dump_within_shrinks_named_lists_and_preserves_the_rest():
    payload = {
        "process_guid": "{01f3cb34-afd6-698e-5800-00108413dbf4}",
        "self_and_parent": _fat_records(10),
        "children": _fat_records(),
    }
    text, dropped = json_dump_within(
        payload, MAX_CHARS, shrink=("self_and_parent", "children"))
    parsed = json.loads(text)
    assert len(text) <= MAX_CHARS and dropped > 0
    # the non-shrinkable scalar survives — it is what makes the response addressable
    assert parsed["process_guid"] == payload["process_guid"]
    assert set(parsed) == set(payload)


def test_json_dump_within_still_emits_valid_json_when_nothing_fits():
    """The non-shrinkable part alone can exceed the budget. Even then the model
    must get JSON it can act on, not a corrupt payload."""
    payload = {"coverage": "y" * 5000, "candidates": _fat_records()}
    text, _ = json_dump_within(payload, 500, shrink=("candidates",))
    parsed = json.loads(text)
    assert len(text) <= 500
    assert "error" in parsed and "hint" in parsed


# --- the tools ----------------------------------------------------------------

@pytest.mark.parametrize("method,kwargs", [
    ("search_alerts", {}),
    ("get_connections", {}),
    ("get_process_events", {"event_id": 1}),
])
async def test_elastic_list_tools_return_parseable_json_when_truncated(
    monkeypatch, method, kwargs
):
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await getattr(tool, method)(timerange_minutes=60, **kwargs)
    body = _json_part(out)
    records = json.loads(body)                     # the assertion that matters
    assert isinstance(records, list) and records
    assert len(records) < N_RECORDS, "fixture must overflow, or this proves nothing"


async def test_get_process_tree_returns_parseable_json_when_truncated(monkeypatch):
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await tool.get_process_tree(process_guid="{abc}", timerange_minutes=60)
    parsed = json.loads(_json_part(out))
    assert parsed["process_guid"] == "{abc}"
    assert isinstance(parsed["children"], list)


async def test_search_auth_events_returns_parseable_json_when_truncated(monkeypatch):
    tool = AuthTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await tool.search_auth_events(timerange_minutes=60)
    records = json.loads(_json_part(out))
    assert isinstance(records, list) and records


async def test_get_agent_alerts_returns_parseable_json_when_truncated(monkeypatch):
    """Covers the Wazuh API path; the `[source: ...]` prefix is part of the
    contract and is budgeted, not spliced."""
    tool = WazuhTool(_cfg())
    monkeypatch.setattr(
        tool, "_api_get",
        lambda *a, **k: _async({"data": {"affected_items": _fat_records()}}))
    out = await tool.get_agent_alerts(agent_id="001")
    assert out.startswith("[source:")
    records = json.loads(_json_part(out))
    assert isinstance(records, list) and records


def _async(value):
    """Wrap a value in an awaitable, for monkeypatching async methods."""
    async def _coro():
        return value
    return _coro()


# --- issue #37: the Sysmon event-id field name differs per ingest path --------

def test_process_events_query_matches_both_event_id_spellings():
    """EF's EVTX path writes `EventID`; the NDJSON path wrote lowercase
    `event_id`. A built L corpus carried 826k of the former and 868 of the
    latter in ONE index, and a `term: {EventID: n}` filter matched ZERO of the
    NDJSON documents -- which are exactly the injected adversary events.
    """
    tool = ElasticTool(_cfg())
    body = tool._build_process_events_query(
        host="", image="", parent_image="", command_line_contains="",
        event_id=1, timerange_minutes=60)
    flat = json.dumps(body)
    assert '"EventID"' in flat and '"event_id"' in flat, flat
    # and it must be an OR, not two ANDed terms (which would match nothing)
    assert '"minimum_should_match": 1' in flat


def _ingest_module(name="_t_ingest"):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        name, pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ingested_docs(ing, ef_dir, monkeypatch, **kw):
    """Drive the real ingest() with a stubbed _bulk; return {index: [(id, doc)]}."""
    out: dict[str, list] = {}

    def _fake_bulk(url, index, docs, **k):
        out.setdefault(index, []).extend(docs)
        return len(docs)

    monkeypatch.setattr(ing, "_bulk", _fake_bulk)
    monkeypatch.setattr(ing, "_recreate_index", lambda *a, **k: None)
    monkeypatch.setattr(ing, "httpx", type("_H", (), {"post": staticmethod(lambda *a, **k: None)})())
    ing.ingest(ef_dir, "http://es.invalid", anchor_end_to_now=False, **kw)
    return out


def test_ingest_canonicalises_event_id_on_the_written_doc(tmp_path, monkeypatch):
    """The backfill must land on the OUTGOING doc, not the hashed record."""
    ing = _ingest_module()
    inj = tmp_path / "injected"
    inj.mkdir()
    (inj / "apt.sysmon.sysmon.ndjson").write_text(
        json.dumps({"event_id": 1, "Image": "powershell.exe"}) + "\n")

    docs = _ingested_docs(ing, tmp_path, monkeypatch)
    _id, doc = docs["windows-sysmon"][0]
    assert doc["EventID"] == 1, "EventID not backfilled onto the written doc"
    assert doc["event_id"] == 1, "original spelling must be kept for compatibility"
    # ...and the record the id was computed from must be untouched by it
    rec, _w, _n = next(iter(ing.parse_ot_ndjson(inj / "apt.sysmon.sysmon.ndjson")))
    assert "EventID" not in rec, "the backfill leaked back onto the hashed record"


def test_ingest_does_not_clobber_an_existing_EventID(tmp_path, monkeypatch):
    ing = _ingest_module("_t_ingest2")
    inj = tmp_path / "injected"
    inj.mkdir()
    (inj / "x.sysmon.sysmon.ndjson").write_text(
        json.dumps({"event_id": 1, "EventID": 4624}) + "\n")
    docs = _ingested_docs(ing, tmp_path, monkeypatch)
    assert docs["windows-sysmon"][0][1]["EventID"] == 4624


def test_doc_id_is_stable_across_ingest_versions(tmp_path):
    """THE property a persisted ground-truth pointer depends on.

    `where.doc_id` is written to disk at BUILD time; `scripts/ingest_ef.py` is a
    separate, later pass over an already-built corpus. So the hash input must be
    the record exactly as the parser yields it, with no enrichment applied first.

    Enriching before hashing does not collide and does not error -- it silently
    lands every injected document at a NEW id while ground truth still names the
    old one, and the _OVERWRITTEN guard stays quiet because the ids are new
    rather than duplicated. This pins the id for one fixed record so any future
    enrichment that creeps in front of the hash fails here instead of in a
    graded run.
    """
    ing = _ingest_module("_t_ingest3")
    path = tmp_path / "apt1.sysmon.sysmon.ndjson"
    path.write_text(json.dumps(
        {"event_id": 1, "Image": "powershell.exe", "UtcTime": "2026-03-02 10:24:01.141"}) + "\n")
    rec, _w, nid = next(iter(ing.parse_ot_ndjson(path)))
    assert nid is None
    assert ing.doc_id(rec, "injected/apt1.sysmon.sysmon.ndjson", 0, nid) == (
        "61d3f171aad57f6b8bda4aa36a0b91ca")  # == pre-PR ingest, verified


# --- issue #36: OT subsampling must not decimate the IT<->OT bridge -----------

def test_bridge_legs_are_never_subsampled(tmp_path, monkeypatch):
    """Bridge legs land in ot-conn (`_BRIDGE_INDEX["ot"]`), which is in
    `_OT_SAMPLE_INDICES`. Keying the sampling decision on the index alone threw
    away 49 of every 50 bridge records -- and the IT<->OT crossing IS the RQ1
    signal. Sampling is for the benign OT protocol baseline only.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_t_ing36", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py")
    ing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ing)

    # both trees route to the SAME index, which is what made this easy to miss
    assert ing.route("bridge/ot.conn.ndjson")[0] == ing.route("ot/conn.ndjson")[0] == "ot-conn"
    assert "ot-conn" in ing._OT_SAMPLE_INDICES

    written: dict[str, list] = {}

    def _fake_bulk(url, index, docs, **kw):
        written.setdefault(index, []).extend(docs)
        return len(docs)

    monkeypatch.setattr(ing, "_bulk", _fake_bulk)
    monkeypatch.setattr(ing, "_recreate_index", lambda *a, **k: None)
    monkeypatch.setattr(ing, "httpx", type("_H", (), {
        "post": staticmethod(lambda *a, **k: None)})())

    n = 100
    for sub in ("bridge", "ot"):
        d = tmp_path / sub
        d.mkdir(parents=True, exist_ok=True)
        (d / ("ot.conn.ndjson" if sub == "bridge" else "conn.ndjson")).write_text(
            "\n".join(json.dumps({"uid": f"{sub}{i}", "ts": 1.0 + i}) for i in range(n)) + "\n")

    ing.ingest(tmp_path, "http://es.invalid", anchor_end_to_now=False, ot_sample_rate=50)

    docs = written.get("ot-conn", [])
    uids = [d[1].get("uid", "") for d in docs]
    bridge_kept = sum(1 for u in uids if u.startswith("bridge"))
    ot_kept = sum(1 for u in uids if u.startswith("ot"))
    assert bridge_kept == n, f"bridge legs were sampled: kept {bridge_kept} of {n}"
    assert ot_kept < n, f"benign OT should still be sampled, kept {ot_kept} of {n}"


# --- F5: the footer must report what was actually returned -------------------

async def test_footer_reports_the_real_count_when_the_size_limit_truncates(monkeypatch):
    """The old `if dropped and not truncated` suppressed the accurate count in
    exactly the case where the response was most truncated: it claimed
    "Showing first 50 results" while returning 7.
    """
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await tool.search_alerts(timerange_minutes=60)
    records = json.loads(_json_part(out))
    footer = out[len(_json_part(out)):]
    # 60 fetched -> 50 (max_results cap) -> 7 (size cap): BOTH must be reported,
    # and the count must be what was actually returned.
    assert "capped at first 50" in footer, footer
    assert f"showing {len(records)} of those 50" in footer, footer


async def test_no_footer_when_nothing_was_dropped(monkeypatch):
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records(2)))
    out = await tool.search_alerts(timerange_minutes=60)
    assert "---" not in out
    assert len(json.loads(out)) == 2
