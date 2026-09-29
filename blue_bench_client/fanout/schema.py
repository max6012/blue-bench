"""Fan-out schema — partition plans, slices, worker reports, evidence pointers.

Three roles exchange these models: the LEAD emits a ``PartitionPlan``; the
dispatcher runs one worker per ``Slice``; each worker's final answer is parsed
into a ``WorkerReport``; the reducer reads the reports. A worker may return a
``sub_plan`` of its own (recursive fan) when its slice is too large to read
within budget — the dispatcher runs it, depth-limited.

The models are deliberately plain: they are what the judge scores (slice
rationale, coverage claim, per-finding pointers), so every field here is one
the rubric can name.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

# The lead is asked for 10–20 slices. Outside that band is recorded, not
# rejected: a 6-slice plan for a small corpus or a 25-slice plan for a huge one
# may be right, and the judge scores the choice. The hard cap only stops a
# runaway lead from fanning out hundreds of workers.
TARGET_SLICE_RANGE = (10, 20)
MAX_SLICES = 64


class SliceFilters(BaseModel):
    """What a slice is bound to. Every field is optional; empty means the slice
    does not constrain that dimension.

    ``time_start`` / ``time_end`` are ABSOLUTE timestamps. The corpus is anchored
    to fixed dates, so the lead thinks in calendar time, never "the last N
    hours". The server-side binding (``blue_bench_mcp.fanout_bind.bind_args``)
    sets ``since``/``until`` from this band, and records the cases where a tool
    cannot express it.
    """
    hosts: list[str] = Field(default_factory=list)
    """Computer FQDNs, e.g. 'wkst-03.corp.example.invalid' (Sysmon / auth tools)."""
    host_ips: list[str] = Field(default_factory=list)
    """Host IPs for the network-side tools (Zeek conn, alerts)."""
    indices: list[str] = Field(default_factory=list)
    """ES index names for tools that take one (count_by_field)."""
    time_start: datetime | None = None
    time_end: datetime | None = None
    event_ids: list[int] = Field(default_factory=list)
    """Sysmon / Windows Security EventIDs."""
    notes: str = ""
    """Free text the lead wants the worker to know that no field expresses
    (e.g. 'the OT gateway sits on both subnets')."""

    @field_validator("time_start", "time_end")
    @classmethod
    def _require_tz(cls, v: datetime | None) -> datetime | None:
        # A naive timestamp is ambiguous against a corpus anchored in UTC and a
        # site timezone of America/New_York; refuse rather than guess.
        if v is not None and v.tzinfo is None:
            raise ValueError("slice timestamps must carry a timezone (use +00:00)")
        return v

    def is_empty(self) -> bool:
        return not (
            self.hosts or self.host_ips or self.indices or self.event_ids
            or self.time_start or self.time_end
        )


class Slice(BaseModel):
    id: str
    question: str
    """The scoped question the worker answers — a question, not a filter list."""
    filters: SliceFilters = Field(default_factory=SliceFilters)
    turn_budget: int = Field(..., ge=1)
    """Assigned by the lead; the harness clamps it to its own ceiling."""
    splittable: bool = True
    """False when the lead judges the slice atomic — a worker's sub_plan for it
    is still recorded but the dispatcher does not run it."""
    rationale: str
    """Why this slice exists. Scored: the judge reads it against the survey."""
    resolved: dict = Field(default_factory=dict)
    """What the HARNESS added to ``filters``, not the lead — written by
    ``blue_bench_client.fanout.host_resolve.complete_slice_scope`` when it
    completes ``hosts`` from ``host_ips`` or the reverse. Holds the supplied and
    resolved values per dimension, the index that answered for each, and what
    nothing in the corpus could resolve. Kept out of ``filters`` on purpose:
    everything in ``SliceFilters`` is a scoping dimension the server binds from,
    and scoring has to be able to tell the lead's plan from the harness's
    filling-in."""


class PartitionPlan(BaseModel):
    plan_id: str
    survey_summary: str
    """What the lead saw (counts by host / index / event type / time) before
    slicing. Scored independently of worker findings, so a lead that slices the
    attack out of every slice is not rewarded for a tidy plan."""
    slices: list[Slice] = Field(..., min_length=1, max_length=MAX_SLICES)
    coverage_claim: str
    """The lead's own statement of what the slices cover and what they leave out."""
    depth: int = Field(0, ge=0)
    """0 for the top-level plan; a worker's sub_plan is depth+1."""

    @field_validator("slices")
    @classmethod
    def _unique_ids(cls, v: list[Slice]) -> list[Slice]:
        seen: set[str] = set()
        for s in v:
            if s.id in seen:
                raise ValueError(f"duplicate slice id: {s.id!r}")
            seen.add(s.id)
        return v

    def slice_count_note(self) -> str | None:
        """Text for the trace when the plan is outside the 10–20 target; None
        when it is inside. Not an error — the judge scores the choice."""
        lo, hi = TARGET_SLICE_RANGE
        n = len(self.slices)
        if lo <= n <= hi:
            return None
        return f"plan has {n} slices; target is {lo}–{hi}"


class Pointer(BaseModel):
    """An evidence pointer — the most specific handle the worker can cite.

    ``doc_id`` is the ES ``_id`` and is what ground-truth scoring matches on.
    Every record the tools return carries it (``es_records.with_identity``),
    and the worker prompt tells the model to cite it. It stays optional here so
    a report that cites only native handles -- Sysmon ``EventRecordID`` /
    ``ProcessGuid``, Zeek ``uid``, timestamp + host -- still parses and is
    scored on what it did cite, rather than being thrown away whole.
    """
    index: str
    doc_id: str | None = None
    event_record_id: int | str | None = None
    """Integer in real Sysmon, but the injected capture's records carry hex
    record ids -- a model that copies one faithfully must not lose its report."""
    process_guid: str | None = None
    conn_uid: str | None = None
    timestamp: datetime | None = None
    host: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _lenient_timestamp(cls, v: Any) -> Any:
        """A timestamp the model wrote in a shape pydantic cannot read is a
        weak handle, not a reason to discard the report: drop it. doc_id is
        what scoring matches on."""
        if v is None or isinstance(v, datetime):
            return v
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except ValueError:
            return None

    @field_validator("doc_id", "process_guid", "conn_uid", "host", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return None if v is None else str(v)

    def is_citable(self) -> bool:
        """True when at least one concrete handle is present — a pointer with
        only an index is not evidence."""
        return any(
            v is not None
            for v in (self.doc_id, self.event_record_id, self.process_guid,
                      self.conn_uid, self.timestamp)
        )


class Finding(BaseModel):
    statement: str
    pointers: list[Pointer] = Field(..., min_length=1)
    """At least one pointer per finding. A claim with nothing to point at is
    not a finding; the prompt tells the worker to leave it out."""
    confidence: float = Field(..., ge=0.0, le=1.0)
    technique_hints: list[str] = Field(default_factory=list)
    """ATT&CK ids or plain technique names the worker suspects."""


Advice = Literal["keep", "widen", "narrow", "split"]


class WorkerReport(BaseModel):
    slice_id: str
    findings: list[Finding]
    """Required, even when empty: an object without it is not a report. With a
    default, any nested object carrying an id-like 'slice_id' -- a sub-slice of
    the model's own sub_plan -- validated as an empty report and replaced the
    real one (Opus 5.5 ceiling run, 2026-09-28)."""
    nothing_found: bool
    nothing_found_reason: str = ""
    """Required when nothing_found is true: what was checked and why it looked
    clean. 'Nothing found' with no reason is indistinguishable from 'did not
    look'."""
    advice: Advice = "keep"
    """What the worker thinks the lead should do with this slice next round:
    keep it, widen it (the slice cut through something), narrow it (mostly
    noise), or split it (too large to read within budget)."""
    sub_plan: PartitionPlan | None = None
    """Recursive fan: present only with advice == 'split'. The dispatcher runs
    it if the slice is splittable and the depth limit allows."""
    turns_used: int = 0
    """Filled by the harness from the trace, not by the model."""
    error: str | None = None

    @field_validator("nothing_found_reason")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @model_validator(mode="after")
    def _consistent(self) -> "WorkerReport":
        if self.nothing_found and not self.nothing_found_reason:
            raise ValueError("nothing_found requires nothing_found_reason")
        if self.nothing_found and self.findings:
            raise ValueError("nothing_found is true but findings is non-empty")
        if self.sub_plan is not None and self.advice != "split":
            raise ValueError("sub_plan is only meaningful with advice == 'split'")
        return self


class WorkerReportParseError(ValueError):
    """The model's final answer did not contain a valid WorkerReport.

    The message names what was wrong (no JSON object at all, or the fields the
    best candidate was missing) so the dispatcher can record a specific
    failure instead of 'parse error'.
    """


def _json_candidates(text: str) -> list[tuple[int, int, dict]]:
    """Every JSON object that decodes cleanly from some ``{`` in ``text``.

    Uses ``raw_decode`` at each brace rather than a depth scan from the end: a
    depth scan grabs the innermost trailing object (a pointer, not the report),
    and a "last fence" rule misses unfenced output. Returns (start, end, obj)
    triples in document order.
    """
    dec = json.JSONDecoder()
    out: list[tuple[int, int, dict]] = []
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            obj, end = None, i + 1
        else:
            if isinstance(obj, dict):
                out.append((i, end, obj))
        i = text.find("{", i + 1)
    return out


def _without_bad_sub_plan(obj: dict, err: Exception) -> WorkerReport | None:
    """The report with its sub_plan dropped, when the sub_plan is the only
    thing wrong with it.

    A sub_plan is advice to the dispatcher; the findings are the evidence. A
    model that got the sub-slice field names wrong still reported what it saw,
    and throwing the findings away for it scores the model on JSON spelling.
    The drop is recorded on ``error`` so the dispatcher knows not to run it.
    """
    if not isinstance(err, ValidationError) or not isinstance(obj, dict) or not obj.get("sub_plan"):
        return None
    if any((e.get("loc") or ("",))[0] != "sub_plan" for e in err.errors()):
        return None
    try:
        rep = WorkerReport.model_validate({**obj, "sub_plan": None})
    except (ValidationError, ValueError):
        return None
    first = err.errors()[0]
    rep.error = (f"sub_plan dropped as invalid ({len(err.errors())} errors, first: "
                 f"{'.'.join(str(x) for x in first['loc'])}: {first['msg']})")
    return rep


def parse_worker_report(text: str) -> WorkerReport:
    """Extract the LAST JSON object from a model's final answer and validate it.

    Models wrap the report in prose and code fences, and sometimes emit a
    plan-shaped object before the real one; the last complete object that
    validates wins. When no candidate validates, the error lists the missing
    fields of the last candidate that at least decoded, so a truncated or
    misnamed field shows up by name.
    """
    if not text or not text.strip():
        raise WorkerReportParseError("final answer is empty; expected a WorkerReport JSON object")

    candidates = _json_candidates(text)
    if not candidates:
        raise WorkerReportParseError(
            "no JSON object found in the final answer; expected a WorkerReport "
            "with fields: slice_id, findings, nothing_found, advice"
        )

    # Outermost objects only: a nested pointer decodes on its own too, and would
    # otherwise be tried (and rejected) as a report candidate.
    outermost: list[tuple[int, int, dict]] = []
    for start, end, obj in candidates:
        if outermost and start < outermost[-1][1]:
            continue
        outermost.append((start, end, obj))

    last_err: ValidationError | ValueError | None = None
    for _start, _end, obj in reversed(outermost):
        try:
            return WorkerReport.model_validate(obj)
        except (ValidationError, ValueError) as e:
            if last_err is None:
                last_err = e
            salvaged = _without_bad_sub_plan(obj, e)
            if salvaged is not None:
                return salvaged

    # No outermost object validates. A model that wrapped the report
    # (``{"worker_report": {...}}``) put the real one one level down; try the
    # nested candidates before giving up, but keep the outermost error as the
    # message — it names what the model's top-level object was missing.
    outer_spans = {(s, e) for s, e, _ in outermost}
    for _start, _end, obj in reversed(candidates):
        if (_start, _end) in outer_spans:
            continue
        try:
            return WorkerReport.model_validate(obj)
        except (ValidationError, ValueError):
            continue

    assert last_err is not None
    if isinstance(last_err, ValidationError):
        missing = sorted(
            ".".join(str(p) for p in err["loc"])
            for err in last_err.errors() if err["type"] == "missing"
        )
        other = [
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in last_err.errors() if err["type"] != "missing"
        ]
        parts = []
        if missing:
            parts.append(f"missing fields: {missing}")
        if other:
            parts.append(f"invalid fields: {other}")
        raise WorkerReportParseError(
            "last JSON object in the final answer is not a valid WorkerReport; "
            + "; ".join(parts)
        ) from last_err
    raise WorkerReportParseError(f"invalid WorkerReport: {last_err}") from last_err


def render_sub_plan_example_for_prompt(depth: int = 1) -> str:
    """A valid example ``sub_plan`` value, embedded in the worker prompt.

    Without it models invent the sub-slice shape (``slice_id``, ``since``,
    ``until``) and the whole report failed to validate. A test round-trips it
    inside a report.
    """
    example = PartitionPlan(
        plan_id="s07-split",
        survey_summary="count_by_time shows two dense bands: 08:00-09:00 and 11:40-12:20.",
        slices=[
            Slice(
                id="s07-a",
                question="What ran in the 08:00-09:00 band?",
                filters=SliceFilters(
                    hosts=["wkst-03.corp.example.invalid"],
                    time_start=datetime.fromisoformat("2026-08-19T08:00:00+00:00"),
                    time_end=datetime.fromisoformat("2026-08-19T09:00:00+00:00"),
                ),
                turn_budget=10,
                rationale="First dense band; 1,900 Sysmon events.",
            ),
        ],
        coverage_claim="Covers the two dense bands; the quiet hours between are left out.",
        depth=depth,
    )
    return json.dumps(example.model_dump(mode="json", exclude={"slices": {0: {"resolved", "splittable"}}}),
                      indent=2)


def render_report_schema_for_prompt() -> str:
    """A compact, valid example of the report the worker must emit — embedded
    in the role prompt via the ``{report_schema}`` placeholder.

    An example, not a JSON Schema: small models copy examples far more
    reliably than they read schemas. Kept valid on purpose — a test round-trips
    it through ``parse_worker_report`` so the prompt can never drift from the
    model.
    """
    example = WorkerReport(
        slice_id="s07",
        findings=[
            Finding(
                statement=(
                    "powershell.exe on wkst-03 launched by winword.exe with an "
                    "encoded command; parent chain is not a normal user session"
                ),
                pointers=[
                    Pointer(
                        index="windows-sysmon",
                        doc_id="wkst-03.corp.example.invalid:418223",
                        event_record_id=418223,
                        process_guid="{b2c0e5a1-3f2d-66e1-0a00-000000001b00}",
                        timestamp=datetime.fromisoformat("2026-08-19T14:02:11+00:00"),
                        host="wkst-03.corp.example.invalid",
                    ),
                ],
                confidence=0.8,
                technique_hints=["T1059.001"],
            ),
        ],
        nothing_found=False,
        nothing_found_reason="",
        advice="keep",
        sub_plan=None,
    )
    return json.dumps(
        example.model_dump(mode="json", exclude={"turns_used", "error"}),
        indent=2,
    )
