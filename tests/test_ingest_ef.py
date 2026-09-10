"""Unit tests for the EvidenceForge -> ES ingest adapter (scripts/ingest_ef.py).

Pure-function coverage (no Elasticsearch): source routing, per-format parsing,
content-derived ids, and window-preserving timestamp parsing. The live
ES round-trip is exercised manually in EF-P2 (see plandb context); these
tests lock the parsing/routing contract for CI.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import timezone
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ingest_ef", Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py"
)
ingest_ef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ingest_ef)


def test_route_maps_every_ef_format():
    assert ingest_ef.route("conn.json")[0] == "zeek-conn"
    assert ingest_ef.route("dns.json")[0] == "zeek-dns"
    assert ingest_ef.route("windows_event_sysmon.xml")[0] == "windows-sysmon"
    assert ingest_ef.route("windows_event_security.xml")[0] == "windows-security"
    assert ingest_ef.route("ecar.json")[0] == "ecar-edr"
    assert ingest_ef.route("syslog.log")[0] == "linux-syslog"
    assert ingest_ef.route("snort_alert.log")[0] == "snort-alerts"
    assert ingest_ef.route("cisco_asa.log")[0] == "firewall-asa"
    # non-stream artifacts are skipped
    assert ingest_ef.route("nina.kapoor.bash_history") is None
    assert ingest_ef.route("OUTPUT_TARGET.txt") is None


def test_parse_zeek_uses_uid_id_and_epoch_ts(tmp_path: Path):
    p = tmp_path / "conn.json"
    p.write_text('{"ts":1715688020.05,"uid":"CErP1","id.orig_h":"10.44.30.10",'
                 '"id.resp_h":"10.44.20.30","id.resp_p":8080,"proto":"tcp"}\n')
    (rec, when, nid), = list(ingest_ef.parse_zeek(p))
    assert nid == "CErP1"  # native id = uid
    assert when.year == 2024 and when.tzinfo == timezone.utc
    assert rec["src_ip"] == "10.44.30.10" and rec["dest_port"] == 8080  # aliases added


def test_parse_evtx_extracts_eventdata_and_recordid(tmp_path: Path):
    p = tmp_path / "windows_event_sysmon.xml"
    p.write_text(
        '<Events>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>1</EventID>"
        '<TimeCreated SystemTime="2024-05-14T12:04:54.7260745Z"/>'
        "<EventRecordID>446901</EventRecordID><Computer>WS-1</Computer></System>"
        '<EventData><Data Name="Image">C:\\x.exe</Data>'
        '<Data Name="UtcTime">2024-05-14 12:04:54.726</Data></EventData></Event>\n</Events>'
    )
    (rec, when, nid), = list(ingest_ef.parse_evtx(p))
    assert nid == "446901"          # native id = EventRecordID
    assert rec["EventID"] == 1 and rec["Image"] == "C:\\x.exe"
    assert when.year == 2024 and when.month == 5  # 7-digit fraction trimmed, parsed


def test_parse_ecar_uses_id_and_epoch_ms(tmp_path: Path):
    p = tmp_path / "ecar.json"
    p.write_text('{"timestamp_ms":1715688007330,"id":"abc-123","action":"MODIFY",'
                 '"object":"REGISTRY","objectID":"def"}\n')
    (rec, when, nid), = list(ingest_ef.parse_ecar(p))
    assert nid == "abc-123"
    assert when.year == 2024 and rec["action"] == "MODIFY"


def test_sha_id_is_stable_and_content_derived():
    a = ingest_ef._sha_id({"x": 1, "y": 2}, "data/h/syslog.log", 0)
    b = ingest_ef._sha_id({"y": 2, "x": 1}, "data/h/syslog.log", 0)  # key order independent
    assert a == b and len(a) == 32
    # ...and still content-derived: different content -> different id
    assert a != ingest_ef._sha_id({"x": 1, "y": 3}, "data/h/syslog.log", 0)


def test_sha_id_is_scoped_by_source_position():
    """Identical records at different positions must NOT share an _id.

    A bulk index of an existing _id is an overwrite, not an error, so a bare
    content hash silently destroyed every duplicate event (issue #31).
    """
    rec = {"raw": "May 14 12:00:20 host sshd[1]: Accepted publickey for svc"}
    same_file = [ingest_ef._sha_id(rec, "data/h1/syslog.log", n) for n in range(5)]
    assert len(set(same_file)) == 5, "duplicate lines in one file collapse onto one _id"
    # and the same line in two different files is two different documents
    assert (ingest_ef._sha_id(rec, "data/h1/syslog.log", 0)
            != ingest_ef._sha_id(rec, "data/h2/syslog.log", 0))


def test_doc_id_prefers_a_real_native_id():
    rec = {"EventRecordID": 4242, "Image": "x.exe"}
    assert ingest_ef.doc_id(rec, "data/h/sysmon.xml", 0, 4242) == "4242"
    # no native id -> position-scoped content hash
    assert len(ingest_ef.doc_id(rec, "data/h/sysmon.xml", 0, None)) == 32


def test_merged_ndjson_does_not_key_id_on_the_zeek_uid(tmp_path):
    """A uid identifies a connection, not a record: one connection can carry
    several http transactions, so uid-keyed ids collapse them (issue #36).
    """
    path = tmp_path / "http.ndjson"
    path.write_text("\n".join(
        json.dumps({"uid": "CsharedUID", "ts": 1.0 + i, "uri": f"/stage{i}"})
        for i in range(3)
    ) + "\n")
    yielded = list(ingest_ef.parse_ot_ndjson(path))
    assert [n for _r, _w, n in yielded] == [None, None, None]
    ids = [ingest_ef.doc_id(r, "injected/a.zeek.http.ndjson", i, n)
           for i, (r, _w, n) in enumerate(yielded)]
    assert len(set(ids)) == 3


def test_year_inference_resolves_snort_and_asa_lines():
    ingest_ef._CORPUS_YEAR["y"] = 2024
    snort = "05/14-12:08:35.250 [**] [1:366:1] PING [**] {ICMP} 1.2.3.4 -> 5.6.7.8"
    asa = "<166>May 14 12:00:20 FW %ASA-6-302013: Built outbound TCP connection"
    ts_snort = ingest_ef._line_time_best_effort(snort)
    ts_asa = ingest_ef._line_time_best_effort(asa)
    assert ts_snort.year == 2024 and ts_snort.month == 5 and ts_snort.day == 14
    assert ts_asa.hour == 12 and ts_asa.minute == 0
