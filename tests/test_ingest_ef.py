"""Unit tests for the EvidenceForge -> ES ingest adapter (scripts/ingest_ef.py).

Pure-function coverage (no Elasticsearch): source routing, per-format parsing,
content-derived ids, and window-preserving timestamp parsing. The live
ES round-trip is exercised manually in EF-P2 (see plandb context); these
tests lock the parsing/routing contract for CI.
"""

from __future__ import annotations

import importlib.util
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
    a = ingest_ef._sha_id({"x": 1, "y": 2})
    b = ingest_ef._sha_id({"y": 2, "x": 1})  # key order independent
    assert a == b and len(a) == 32


def test_year_inference_resolves_snort_and_asa_lines():
    ingest_ef._CORPUS_YEAR["y"] = 2024
    snort = "05/14-12:08:35.250 [**] [1:366:1] PING [**] {ICMP} 1.2.3.4 -> 5.6.7.8"
    asa = "<166>May 14 12:00:20 FW %ASA-6-302013: Built outbound TCP connection"
    ts_snort = ingest_ef._line_time_best_effort(snort)
    ts_asa = ingest_ef._line_time_best_effort(asa)
    assert ts_snort.year == 2024 and ts_snort.month == 5 and ts_snort.day == 14
    assert ts_asa.hour == 12 and ts_asa.minute == 0
