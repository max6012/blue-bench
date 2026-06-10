"""Ingest unit tests for the APT injection harness.

Run without the (gitignored) binary captures: the EVTX path is exercised
via inline record XML, the Zeek path via inline TSV text — mirroring the
cybercrime_foil tests' fixture-string approach.
"""

from __future__ import annotations

from datetime import timezone

from blue_bench_generators.apt_inject.ingest import (
    parse_evtx_record_xml,
    parse_zeek_log_text,
    summarize,
)

# A real Sysmon EID 1 record shape (trimmed), as python-evtx renders it.
SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>
<EventID Qualifiers="">1</EventID>
<TimeCreated SystemTime="2026-06-09 22:23:45.899967+00:00"></TimeCreated>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>EC2AMAZ-VU9QJAP</Computer>
</System>
<EventData>
<Data Name="UtcTime">2026-06-09 22:23:45.894</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -enc ZQBjAGgAbwA=</Data>
</EventData></Event>"""

ZEEK_CONN = (
    "#separator \\x09\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
    "#types\ttime\tstring\taddr\taddr\tport\tenum\n"
    "1781045025.593\tCabc123\t10.20.1.210\t142.251.154.119\t80\ttcp\n"
)


def test_evtx_record_xml_extracts_system_and_eventdata():
    system, eventdata = parse_evtx_record_xml(SYSMON_XML)
    assert system["EventID"] == "1"
    assert system["Computer"] == "EC2AMAZ-VU9QJAP"
    assert system["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert eventdata["UtcTime"] == "2026-06-09 22:23:45.894"
    assert eventdata["Image"].endswith("powershell.exe")
    assert eventdata["CommandLine"].startswith("powershell.exe -enc")


def test_zeek_text_parses_fields_and_capture_ts():
    evs = parse_zeek_log_text(ZEEK_CONN)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["_stream"] == "zeek"
    assert ev["_log"] == "conn"
    assert ev["id.orig_h"] == "10.20.1.210"
    assert ev["id.resp_h"] == "142.251.154.119"
    # capture_ts parsed from the epoch ts, tz-aware UTC.
    assert ev["_capture_ts"] is not None
    assert ev["_capture_ts"].tzinfo == timezone.utc
    assert ev["_capture_ts"].year == 2026


def test_zeek_unset_fields_and_comments_skipped():
    text = (
        "#fields\tts\tuid\tid.orig_h\n"
        "#types\ttime\tstring\taddr\n"
        "1781045025.0\tCx\t-\n"  # id.orig_h unset
    )
    evs = parse_zeek_log_text(text)
    assert len(evs) == 1
    assert evs[0]["id.orig_h"] == "-"


def test_summarize_counts_by_stream():
    evs = parse_zeek_log_text(ZEEK_CONN)
    s = summarize(evs)
    assert s["total"] == 1
    assert s["with_ts"] == 1
    assert s["by_stream"] == {"zeek": 1}
    assert s["zeek_logs"] == {"conn": 1}
