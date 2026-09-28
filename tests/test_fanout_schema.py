"""Fan-out schema: round-trips, tolerant report parsing, clear parse errors.

No ES, no model — pure pydantic.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from blue_bench_client.fanout.schema import (
    Finding,
    PartitionPlan,
    Pointer,
    Slice,
    SliceFilters,
    WorkerReport,
    WorkerReportParseError,
    parse_worker_report,
    render_report_schema_for_prompt,
)

T0 = datetime(2026, 8, 18, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 8, 22, 0, 0, tzinfo=timezone.utc)


def _slice(i: int, **kw) -> Slice:
    base = dict(
        id=f"s{i:02d}",
        question=f"What ran on wkst-{i:02d}?",
        filters=SliceFilters(hosts=[f"wkst-{i:02d}.corp.example.invalid"], time_start=T0, time_end=T1),
        turn_budget=8,
        rationale="one host per slice keeps process-creates readable",
    )
    base.update(kw)
    return Slice(**base)


def _plan(n: int, depth: int = 0) -> PartitionPlan:
    return PartitionPlan(
        plan_id="p1",
        survey_summary="192,624 process-creates over 30 days; 14 hosts",
        slices=[_slice(i) for i in range(1, n + 1)],
        coverage_claim="every workstation, injection days only",
        depth=depth,
    )


# ── round-trips ─────────────────────────────────────────────────────────────

def test_partition_plan_round_trip():
    plan = _plan(12)
    again = PartitionPlan.model_validate_json(plan.model_dump_json())
    assert again == plan
    assert again.slices[0].filters.time_start == T0
    assert again.slice_count_note() is None


def test_slice_count_outside_target_is_noted_not_rejected():
    assert "target is 10–20" in _plan(3).slice_count_note()
    assert "target is 10–20" in _plan(25).slice_count_note()


def test_plan_rejects_empty_and_duplicate_ids():
    with pytest.raises(ValidationError):
        PartitionPlan(plan_id="p", survey_summary="s", slices=[], coverage_claim="c")
    with pytest.raises(ValidationError, match="duplicate slice id"):
        PartitionPlan(plan_id="p", survey_summary="s", slices=[_slice(1), _slice(1)], coverage_claim="c")


def test_slice_timestamps_must_carry_timezone():
    with pytest.raises(ValidationError, match="timezone"):
        SliceFilters(time_start=datetime(2026, 8, 18))


def test_turn_budget_positive():
    with pytest.raises(ValidationError):
        _slice(1, turn_budget=0)


def test_worker_report_round_trip_with_sub_plan():
    report = WorkerReport(
        slice_id="s01",
        findings=[
            Finding(
                statement="rundll32 spawned from winword",
                pointers=[Pointer(index="windows-sysmon", event_record_id=12, process_guid="{g}")],
                confidence=0.6,
                technique_hints=["T1218.011"],
            )
        ],
        nothing_found=False,
        advice="split",
        sub_plan=_plan(2, depth=1),
    )
    again = WorkerReport.model_validate(json.loads(report.model_dump_json()))
    assert again == report
    assert again.sub_plan.depth == 1


def test_report_consistency_rules():
    with pytest.raises(ValidationError, match="nothing_found_reason"):
        WorkerReport(slice_id="s", findings=[], nothing_found=True)
    with pytest.raises(ValidationError, match="findings is non-empty"):
        WorkerReport(
            slice_id="s", nothing_found=True, nothing_found_reason="clean",
            findings=[Finding(statement="x", pointers=[Pointer(index="i", doc_id="d")], confidence=0.1)],
        )
    with pytest.raises(ValidationError, match="advice == 'split'"):
        WorkerReport(slice_id="s", findings=[], nothing_found=False, advice="keep", sub_plan=_plan(2, depth=1))


def test_finding_requires_a_pointer_and_bounded_confidence():
    with pytest.raises(ValidationError):
        Finding(statement="x", pointers=[], confidence=0.5)
    with pytest.raises(ValidationError):
        Finding(statement="x", pointers=[Pointer(index="i")], confidence=1.5)


def test_pointer_is_citable_only_with_a_concrete_handle():
    assert not Pointer(index="windows-sysmon").is_citable()
    assert not Pointer(index="windows-sysmon", host="wkst-03").is_citable()
    assert Pointer(index="zeek-conn", conn_uid="CabC1d").is_citable()
    assert Pointer(index="windows-sysmon", doc_id="abc").is_citable()


# ── parse_worker_report ──────────────────────────────────────────────────────

def _good_json(**over) -> str:
    obj = {
        "slice_id": "s03",
        "findings": [{
            "statement": "encoded powershell",
            "pointers": [{"index": "windows-sysmon", "event_record_id": 77, "host": "wkst-03.corp.example.invalid"}],
            "confidence": 0.7,
            "technique_hints": ["T1059.001"],
        }],
        "nothing_found": False,
        "nothing_found_reason": "",
        "advice": "keep",
        "sub_plan": None,
    }
    obj.update(over)
    return json.dumps(obj, indent=2)


def test_parse_prose_then_fenced_json():
    text = (
        "I surveyed the slice with count_by_field and then read the process creates.\n"
        "Here is my report:\n\n```json\n" + _good_json() + "\n```\n\nEnd of report."
    )
    r = parse_worker_report(text)
    assert r.slice_id == "s03"
    assert r.findings[0].pointers[0].event_record_id == 77


def test_parse_unfenced_json_takes_the_last_object():
    # An earlier, plan-shaped object precedes the real report; the last one wins.
    decoy = json.dumps({"slice_id": "s03", "note": "draft", "findings": []})
    text = f"Draft: {decoy}\n\nFinal: {_good_json(advice='narrow')}"
    r = parse_worker_report(text)
    assert r.advice == "narrow"


def test_parse_ignores_braces_in_prose_and_nested_pointer_objects():
    text = "ProcessGuid {b2c0e5a1-3f2d} looked odd. Report:\n" + _good_json()
    r = parse_worker_report(text)
    assert r.findings[0].statement == "encoded powershell"


def test_parse_accepts_a_wrapped_report():
    text = json.dumps({"worker_report": json.loads(_good_json(advice="widen"))})
    assert parse_worker_report("Wrapped:\n" + text).advice == "widen"


def test_parse_nothing_found_report():
    text = json.dumps({
        "slice_id": "s09", "findings": [], "nothing_found": True,
        "nothing_found_reason": "surveyed 4 event ids, read all 212 process creates, all signed vendor updaters",
        "advice": "narrow",
    })
    r = parse_worker_report("Nothing here.\n" + text)
    assert r.nothing_found and r.findings == [] and r.advice == "narrow"


def test_parse_error_names_missing_fields():
    text = "```json\n" + json.dumps({
        "findings": [{"statement": "x", "pointers": [{"index": "i", "doc_id": "d"}]}],
        "advice": "keep",
    }) + "\n```"
    with pytest.raises(WorkerReportParseError) as exc:
        parse_worker_report(text)
    msg = str(exc.value)
    assert "slice_id" in msg
    assert "findings.0.confidence" in msg


def test_parse_error_when_no_json_at_all():
    with pytest.raises(WorkerReportParseError, match="no JSON object found"):
        parse_worker_report("I could not complete the slice within budget.")
    with pytest.raises(WorkerReportParseError, match="empty"):
        parse_worker_report("   ")


def test_parse_error_on_invalid_advice_value():
    with pytest.raises(WorkerReportParseError, match="advice"):
        parse_worker_report(_good_json(advice="expand"))


def test_rendered_schema_example_round_trips_through_the_parser():
    # The prompt embeds this example; if it ever stops validating, models copy
    # a broken shape. Parsing it back is the guard.
    example = render_report_schema_for_prompt()
    r = parse_worker_report("Report:\n```json\n" + example + "\n```")
    assert r.slice_id == "s07"
    assert r.findings[0].pointers[0].is_citable()
    # Harness-only fields stay out of the example so the model does not fill them.
    assert '"turns_used"' not in example and '"error"' not in example


def test_a_sub_slice_can_never_pass_as_the_report():
    """Regression: with defaults on findings/nothing_found, a sub-slice object
    ({"slice_id": ..., "filters": ...}) inside a malformed sub_plan validated as
    an empty report and replaced the model's real one."""
    from blue_bench_client.fanout.schema import parse_worker_report
    text = json.dumps({
        "slice_id": "s01", "nothing_found": False, "advice": "split",
        "nothing_found_reason": "",
        "findings": [{"statement": "mimikatz", "confidence": 0.9,
                      "pointers": [{"index": "windows-sysmon", "doc_id": "abc"}]}],
        "sub_plan": {"slices": [{"slice_id": "s01-a", "since": "x", "until": "y",
                                 "question": "q", "turn_budget": 5, "rationale": "r"}]},
    })
    r = parse_worker_report(text)
    assert r.slice_id == "s01" and len(r.findings) == 1 and r.advice == "split"
    assert r.sub_plan is None and r.error.startswith("sub_plan dropped as invalid")


def test_the_prompt_sub_plan_example_is_valid_inside_a_report():
    from blue_bench_client.fanout.schema import PartitionPlan, render_sub_plan_example_for_prompt
    plan = PartitionPlan.model_validate(json.loads(render_sub_plan_example_for_prompt(2)))
    assert plan.depth == 2
    WorkerReport(slice_id="s", findings=[], nothing_found=False, advice="split", sub_plan=plan)
