from datetime import datetime, timezone

import pytest

from blue_bench_client.fanout.schema import Slice, WorkerReport
from blue_bench_eval import worker_score as ws

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
GT = {"apt-1": {"a1", "a2", "a3"}, "cc-1": {"c1"}}


def _case(sid, incidents=()):
    sl = Slice.model_validate({"id": sid, "question": "q", "rationale": "r", "turn_budget": 5,
                               "filters": {"hosts": ["wkst-03.corp.example.invalid"], "time_start": T0}})
    return ws.SliceCase(slice=sl, expect_incidents=list(incidents))


def _report(sid, *findings, nothing=False):
    return WorkerReport.model_validate({
        "slice_id": sid, "nothing_found": nothing,
        "nothing_found_reason": "surveyed, clean" if nothing else "",
        "findings": [{"statement": "x", "confidence": c,
                      "pointers": [{"index": "windows-sysmon", "doc_id": d} for d in ids]}
                     for c, ids in findings]})


def seen(*ids):
    return ['[' + ",".join(f'{{"_id": "{i}", "_index": "windows-sysmon"}}' for i in ids) + ']']


def test_attack_detected_only_by_a_grounded_confident_citation():
    c = _case("s1", ["apt-1"])
    ok = ws.score_case(c, _report("s1", (0.8, ["a2"])), seen("a2", "zz"), GT)
    assert ok.correct and ok.hit_ids == 1 and ok.expected_ids == 3
    # Cited but never shown to the model: invented, does not count.
    made_up = ws.score_case(c, _report("s1", (0.8, ["a2"])), seen("zz"), GT)
    assert not made_up.correct and made_up.ungrounded_citations == 1
    # Low confidence is a note, not a detection.
    assert not ws.score_case(c, _report("s1", (0.3, ["a2"])), seen("a2"), GT).correct


def test_clean_case_fails_on_a_confident_finding_outside_ground_truth():
    c = _case("s2")
    assert ws.score_case(c, _report("s2", nothing=True), [], GT).correct
    fp = ws.score_case(c, _report("s2", (0.9, ["benign-9"])), seen("benign-9"), GT)
    assert not fp.correct and fp.false_findings == 1
    # Citing another incident's record is not a false finding.
    assert ws.score_case(c, _report("s2", (0.9, ["c1"])), seen("c1"), GT).correct


def test_unparsed_report_is_incorrect_and_unknown_incident_raises():
    assert not ws.score_case(_case("s3"), None, [], GT, error="bad json").correct
    with pytest.raises(ValueError):
        ws.score_case(_case("s4", ["nope"]), None, [], GT)


def test_table_reports_percent_of_ceiling():
    a = ws.ModelScore(model="opus", cases=[ws.score_case(_case("s1", ["apt-1"]), _report("s1", (0.9, ["a1"])), seen("a1"), GT),
                                           ws.score_case(_case("s2"), _report("s2", nothing=True), [], GT)])
    b = ws.ModelScore(model="small", cases=[ws.score_case(_case("s1", ["apt-1"]), _report("s1", nothing=True), [], GT),
                                            ws.score_case(_case("s2"), _report("s2", nothing=True), [], GT)])
    t = ws.table([a, b], ceiling="opus")
    assert "| opus | 1.0 | 100% | 1/1 | 1/1 |" in t
    assert "| small | 0.5 | 50% | 0/1 | 1/1 |" in t


def test_load_ground_truth_reads_where_doc_id(tmp_path):
    (tmp_path / "x.yaml").write_text(
        "incident_id: apt-1\nevents:\n- where: {doc_id: a1}\n- where: {doc_id: a2}\n- where: {fixture_line: {line: 1}}\n")
    assert ws.load_ground_truth(tmp_path) == {"apt-1": {"a1", "a2"}}
