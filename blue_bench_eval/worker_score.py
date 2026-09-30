"""Worker-level scoring — grade a model on fixed slices, without the lead.

The range model decision needs to know which models can do a worker's job:
read one slice and report what is in it, pointing at the records. That is
measurable now, before the lead and reducer exist, by handing every model the
SAME hand-written slice set. Half the slices contain an injected incident and
half are clean controls, so a model that calls everything malicious scores no
better than one that calls nothing.

A case is scored on evidence only, against the corpus ground truth
(``ground-truth/*.yaml``, ``events[].where.doc_id`` = the ES ``_id``):

* attack case — CORRECT when at least one confident finding cites a ground
  truth record of an expected incident.
* clean case — CORRECT when no confident finding lands outside the ground
  truth (a finding that cites any incident's record is not a false one).
* a citation is GROUNDED when the cited ``_id`` appeared in a tool result the
  model received in that session; an ungrounded one was invented or copied.
  Ungrounded citations never count toward detection.

Nothing here reads prose. A report that does not parse scores as incorrect.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import BaseModel, Field

from blue_bench_client.fanout.schema import Slice, WorkerReport

CONFIDENT = 0.5
"""A finding at or above this confidence is a claim; below it, a note."""


class SliceCase(BaseModel):
    """One fixed slice and what it is known to contain."""
    slice: Slice
    expect_incidents: list[str] = Field(default_factory=list)
    """Ground-truth incident ids inside this slice. Empty = clean control."""
    anomaly: bool = False
    """The expected incident is a benign anomaly (ground-truth source_class
    'benign-anomaly'). Whether a worker should call it malicious has no rubric
    yet, so these cases are reported as flagged / not flagged in their own
    column and kept out of accuracy (Max, 2026-09-28)."""

    @property
    def is_clean(self) -> bool:
        return not self.expect_incidents


def load_cases(path: Path, anchor: dict | None = None) -> list[SliceCase]:
    """Load a slice set; place its times on the live corpus.

    A set with ``time_basis: corpus-original`` is written in the corpus's
    original window, the ground truth's basis. The live corpus has been
    shifted by ingest and re-anchoring, so every slice is moved by
    ``current_window_end - original_window_end`` from the recorded anchor
    (``bb-meta/corpus-anchor``). A set naming a ``build_hash`` is refused
    against an anchor with a different one: those slices describe another
    corpus and would score against records that are not there.
    """
    from datetime import datetime

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = [SliceCase.model_validate(c) for c in data["cases"]]
    if data.get("time_basis") != "corpus-original":
        return cases
    if anchor is None:
        raise ValueError(f"{path}: time_basis is corpus-original, so the corpus anchor is required")
    want = str(data.get("build_hash") or "")
    have = str(anchor.get("build_hash") or "")
    if want and not have.startswith(want):
        raise ValueError(f"{path} was written for build {want}; the live corpus is {have or 'unknown'}")
    delta = (datetime.fromisoformat(anchor["current_window_end"])
             - datetime.fromisoformat(anchor["original_window_end"]))
    for c in cases:
        f = c.slice.filters
        c.slice = c.slice.model_copy(update={"filters": f.model_copy(update={
            "time_start": f.time_start + delta if f.time_start else None,
            "time_end": f.time_end + delta if f.time_end else None})})
    return cases


def load_ground_truth(gt_dir: Path) -> dict[str, set[str]]:
    """incident_id -> the ES ``_id`` of every injected record of it."""
    out: dict[str, set[str]] = {}
    for p in sorted(gt_dir.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        ids = {str((e.get("where") or {}).get("doc_id")) for e in doc.get("events", [])
               if (e.get("where") or {}).get("doc_id")}
        if ids:
            out.setdefault(doc["incident_id"], set()).update(ids)
    return out


def seen_ids(tool_results: Iterable[str]) -> set[str]:
    """Every ``_id`` value that appeared in the tool results of a session."""
    pat = re.compile(r'"_id"\s*:\s*"([^"]+)"')
    return {m for text in tool_results for m in pat.findall(text or "")}


_INFRA_MARKERS = ("status code: 5", "status code: 429", "ResponseError", "TransportError",
                  "ConnectError", "ReadTimeout", "RemoteProtocolError")


def is_infra_error(error: str | None) -> bool:
    """True when a case failed because the provider did, not the model:
    HTTP 429/5xx or a dropped connection that outlived the retries."""
    return bool(error) and any(m in error for m in _INFRA_MARKERS)


class CaseScore(BaseModel):
    slice_id: str
    clean: bool
    anomaly: bool = False
    infra_error: bool = False
    """The provider failed; the case says nothing about the model. Kept out of
    accuracy and listed for a repair run."""
    parsed: bool
    correct: bool
    confident_findings: int = 0
    false_findings: int = 0
    hit_ids: int = 0
    """Grounded citations of an expected incident's records."""
    expected_ids: int = 0
    ungrounded_citations: int = 0
    alert_confidence: float = 0.0
    """The confidence this slice would alert at. Attack slice: the highest
    confidence among findings that cite an expected incident's record (0 when
    none does -- a miss). Clean slice: the highest confidence among its
    findings (0 when it reported nothing). Threshold-free input to
    :attr:`ModelScore.separation`."""
    by_threshold: dict[str, bool] = Field(default_factory=dict)
    """``correct`` recomputed at each cut-off in SWEEP, keyed by str(cut-off)."""
    turns_used: int = 0
    error: str | None = None


SWEEP = (0.3, 0.5, 0.7, 0.9)
"""Confidence cut-offs the accuracy sweep reports. A single cut-off rewards
models whose calibration happens to match it: at 0.5 Opus 4.7 scored 50%, at
0.9 it scored 92% on the same reports (2026-09-30)."""


def score_case(case: SliceCase, report: WorkerReport | None, tool_results: Iterable[str],
               gt: dict[str, set[str]], *, error: str | None = None) -> CaseScore:
    """Score one case at CONFIDENT, plus the sweep and the alert confidence."""
    main = _score_at(case, report, tool_results, gt, CONFIDENT, error=error)
    tr = list(tool_results)
    main.by_threshold = {str(t): _score_at(case, report, tr, gt, t, error=error).correct for t in SWEEP}
    main.alert_confidence = _alert_confidence(case, report, tr, gt)
    return main


def _alert_confidence(case: SliceCase, report: WorkerReport | None, tool_results: list[str],
                      gt: dict[str, set[str]]) -> float:
    if report is None:
        return 0.0
    seen = seen_ids(tool_results)
    expected = set().union(*(gt.get(i, set()) for i in case.expect_incidents)) if case.expect_incidents else set()
    best = 0.0
    for f in report.findings:
        grounded = {p.doc_id for p in f.pointers if p.doc_id} & seen
        if case.is_clean or grounded & expected:
            best = max(best, f.confidence)
    return best


def _score_at(case: SliceCase, report: WorkerReport | None, tool_results: Iterable[str],
              gt: dict[str, set[str]], threshold: float, *, error: str | None = None) -> CaseScore:
    sid = case.slice.id
    expected = set().union(*(gt.get(i, set()) for i in case.expect_incidents)) if case.expect_incidents else set()
    missing = [i for i in case.expect_incidents if i not in gt]
    if missing:
        raise ValueError(f"slice {sid}: incidents not in ground truth: {missing}")
    if report is None:
        return CaseScore(slice_id=sid, clean=case.is_clean, anomaly=case.anomaly, parsed=False,
                         correct=False, expected_ids=len(expected), error=error,
                         infra_error=is_infra_error(error))
    all_gt = set().union(*gt.values()) if gt else set()
    seen = seen_ids(tool_results)
    hits: set[str] = set()
    ungrounded: set[str] = set()
    confident = false = 0
    for f in report.findings:
        cited = {p.doc_id for p in f.pointers if p.doc_id}
        ungrounded |= cited - seen
        grounded = cited & seen
        if f.confidence < threshold:
            continue
        confident += 1
        hits |= grounded & expected
        if not grounded & all_gt:
            false += 1
    correct = (false == 0) if case.is_clean else bool(hits)
    # For an anomaly case ``correct`` means "flagged": a confident finding cited it.
    return CaseScore(slice_id=sid, clean=case.is_clean, anomaly=case.anomaly, parsed=True,
                     correct=correct,
                     confident_findings=confident, false_findings=false, hit_ids=len(hits),
                     expected_ids=len(expected), ungrounded_citations=len(ungrounded),
                     turns_used=report.turns_used)


class ModelScore(BaseModel):
    model: str
    cases: list[CaseScore]

    @property
    def scored(self) -> list[CaseScore]:
        """The cases accuracy is computed over: attacks and clean controls
        that the provider actually served."""
        return [c for c in self.cases if not c.anomaly and not c.infra_error]

    @property
    def accuracy(self) -> float:
        sc = self.scored
        return sum(c.correct for c in sc) / len(sc) if sc else 0.0

    @property
    def separation(self) -> float | None:
        """P(a random attack slice alerts higher than a random clean slice),
        ties counted half. Threshold-free: 1.0 separates perfectly, 0.5 is a
        coin flip. None when either class is empty."""
        atk = [c.alert_confidence for c in self.scored if not c.clean]
        cln = [c.alert_confidence for c in self.scored if c.clean]
        if not atk or not cln:
            return None
        wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in atk for b in cln)
        return wins / (len(atk) * len(cln))

    def accuracy_at(self, t: float) -> float:
        sc = self.scored
        return sum(c.by_threshold.get(str(t), False) for c in sc) / len(sc) if sc else 0.0

    def summary(self) -> dict:
        atk = [c for c in self.scored if not c.clean]
        cln = [c for c in self.scored if c.clean]
        anm = [c for c in self.cases if c.anomaly and not c.infra_error]
        return {
            "model": self.model,
            "accuracy": round(self.accuracy, 3),
            "separation": None if self.separation is None else round(self.separation, 3),
            "sweep": {str(t): round(self.accuracy_at(t), 3) for t in SWEEP},
            "attack_detected": f"{sum(c.correct for c in atk)}/{len(atk)}",
            "clean_correct": f"{sum(c.correct for c in cln)}/{len(cln)}",
            "anomalies_flagged": f"{sum(c.correct for c in anm)}/{len(anm)}",
            "false_findings": sum(c.false_findings for c in self.cases),
            "ungrounded_citations": sum(c.ungrounded_citations for c in self.cases),
            "unparsed_reports": sum(not c.parsed and not c.infra_error for c in self.cases),
            "infra_errors": sum(c.infra_error for c in self.cases),
        }


def table(scores: list[ModelScore], ceiling: str | None = None) -> str:
    """Markdown table. Headline is ``separation`` (threshold-free); accuracy is
    shown at every cut-off in SWEEP and its worst case. ``ceiling`` names the
    model whose separation is 100%."""
    ref = next((s.separation for s in scores if s.model == ceiling), None)
    head = (["model", "separation", "% of ceiling", "worst acc"] + [f"acc@{t}" for t in SWEEP]
            + ["attacks @0.5", "clean @0.5", "anomalies flagged (not scored)",
               "ungrounded cites", "unparsed", "provider failures (excluded)"])
    rows = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for s in sorted(scores, key=lambda s: -(s.separation or 0)):
        m = s.summary()
        sep = s.separation
        pct = f"{100 * sep / ref:.0f}%" if ref and sep is not None else "—"
        accs = [s.accuracy_at(t) for t in SWEEP]
        rows.append("| " + " | ".join(str(x) for x in (
            [m["model"], "—" if sep is None else f"{sep:.2f}", pct, f"{min(accs):.0%}"]
            + [f"{a:.0%}" for a in accs]
            + [m["attack_detected"], m["clean_correct"], m["anomalies_flagged"],
               m["ungrounded_citations"], m["unparsed_reports"], m["infra_errors"]])) + " |")
    return "\n".join(rows)
