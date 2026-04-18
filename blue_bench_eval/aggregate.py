"""Phase 2 aggregator — reads prompts/ traces + scored/ judgments, writes BLUF.md.

Pure function over filesystem. No live deps. Called by blue-bench CLI.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Literal

import yaml
from pydantic import BaseModel, Field

DIMENSIONS = ("tool_usage", "findings", "reasoning", "response_quality")
Verdict = Literal["PASS", "PARTIAL", "FAIL"]


class DimensionScore(BaseModel):
    score: int = Field(..., ge=0, le=3)
    justification: str


class PromptScore(BaseModel):
    prompt_id: str
    dimensions: dict[str, DimensionScore]
    verdict: Verdict
    hallucinations: list[str] = Field(default_factory=list)


class RubricThreshold(BaseModel):
    overall_pct: float
    tool_usage_pct: float
    findings_pct: float


@dataclass
class AggregateResult:
    run_dir: Path
    profile_name: str = ""
    model_id: str = ""
    prompt_count: int = 0
    total_duration_ms: int = 0

    # Dimension percentages (0-100) — arithmetic mean across prompts.
    dim_pct: dict[str, float] = field(default_factory=dict)
    overall_pct: float = 0.0

    # Per-category rollups.
    per_category: dict[str, dict[str, float]] = field(default_factory=dict)

    # Threshold check.
    threshold: RubricThreshold | None = None
    passes_overall: bool = False
    passes_tool_usage: bool = False
    passes_findings: bool = False

    # Per-prompt detail.
    verdicts: list[dict] = field(default_factory=list)  # [{id, category, verdict, dim_scores}]


def _score_to_pct(score: int) -> float:
    return (score / 3.0) * 100.0


def _verdict_from_rubric(dim_scores: dict[str, int]) -> Verdict:
    # Mirrors rubrics/phase2.yaml aggregation.verdict.
    if any(s == 0 for s in dim_scores.values()):
        return "FAIL"
    if dim_scores["tool_usage"] == 0 or dim_scores["findings"] == 0:
        return "FAIL"
    if all(s >= 2 for s in dim_scores.values()) and dim_scores["tool_usage"] >= 2 and dim_scores["findings"] >= 2:
        return "PASS"
    return "PARTIAL"


def _load_scored(run_dir: Path) -> list[PromptScore]:
    scored_dir = run_dir / "scored"
    if not scored_dir.exists():
        raise FileNotFoundError(f"no scored/ directory under {run_dir}")
    scores: list[PromptScore] = []
    for f in sorted(scored_dir.glob("*.json")):
        with open(f) as fh:
            scores.append(PromptScore.model_validate_json(fh.read()))
    if not scores:
        raise ValueError(f"scored/ in {run_dir} is empty")
    return scores


def _load_traces(run_dir: Path) -> dict[str, dict]:
    prompts_dir = run_dir / "prompts"
    out: dict[str, dict] = {}
    if not prompts_dir.exists():
        return out
    for f in sorted(prompts_dir.glob("*.json")):
        with open(f) as fh:
            data = json.load(fh)
        out[data["prompt_id"]] = data
    return out


def _load_rubric(rubric_path: Path) -> RubricThreshold:
    with open(rubric_path) as f:
        raw = yaml.safe_load(f)
    return RubricThreshold.model_validate(raw["threshold"])


def _load_prompt_categories(prompts_dir: Path) -> dict[str, str]:
    """Map prompt_id -> category by reading the YAML specs."""
    cats: dict[str, str] = {}
    for f in sorted(prompts_dir.glob("p2-*.yaml")):
        with open(f) as fh:
            data = yaml.safe_load(fh)
        cats[data["id"]] = data.get("category", "uncategorized")
    return cats


def aggregate(
    run_dir: Path,
    rubric_path: Path,
    prompts_dir: Path | None = None,
) -> AggregateResult:
    scores = _load_scored(run_dir)
    traces = _load_traces(run_dir)
    threshold = _load_rubric(rubric_path)
    categories = _load_prompt_categories(prompts_dir) if prompts_dir else {}

    result = AggregateResult(run_dir=run_dir, threshold=threshold, prompt_count=len(scores))

    # Pull run-level metadata from the first trace (profile is uniform per run).
    if traces:
        first = next(iter(traces.values()))
        result.profile_name = first.get("profile_name", "")
        result.model_id = first.get("model_id", "")
        result.total_duration_ms = sum(t.get("total_duration_ms", 0) for t in traces.values())

    # Dimension percentages (run-level).
    for dim in DIMENSIONS:
        dim_pcts = [_score_to_pct(s.dimensions[dim].score) for s in scores if dim in s.dimensions]
        result.dim_pct[dim] = mean(dim_pcts) if dim_pcts else 0.0
    result.overall_pct = mean(result.dim_pct.values()) if result.dim_pct else 0.0

    # Threshold check.
    result.passes_overall = result.overall_pct >= threshold.overall_pct
    result.passes_tool_usage = result.dim_pct.get("tool_usage", 0.0) >= threshold.tool_usage_pct
    result.passes_findings = result.dim_pct.get("findings", 0.0) >= threshold.findings_pct

    # Per-category rollup.
    by_cat: dict[str, list[PromptScore]] = defaultdict(list)
    for s in scores:
        by_cat[categories.get(s.prompt_id, "uncategorized")].append(s)
    for cat, cat_scores in by_cat.items():
        cat_dims = {
            dim: mean(_score_to_pct(sc.dimensions[dim].score) for sc in cat_scores if dim in sc.dimensions)
            for dim in DIMENSIONS
        }
        cat_dims["overall"] = mean(cat_dims.values())
        result.per_category[cat] = cat_dims

    # Per-prompt verdict detail.
    for s in scores:
        result.verdicts.append(
            {
                "id": s.prompt_id,
                "category": categories.get(s.prompt_id, "uncategorized"),
                "verdict": s.verdict,
                "dimensions": {dim: s.dimensions[dim].score for dim in DIMENSIONS if dim in s.dimensions},
                "hallucinations": s.hallucinations,
            }
        )

    return result


def render_bluf(result: AggregateResult) -> str:
    """Format an AggregateResult as markdown BLUF."""
    lines: list[str] = []
    lines.append(f"# Phase 2 BLUF — {result.profile_name}")
    lines.append("")
    lines.append(f"- **Run directory:** `{result.run_dir}`")
    lines.append(f"- **Model:** `{result.model_id}`")
    lines.append(f"- **Prompts:** {result.prompt_count}")
    if result.total_duration_ms:
        lines.append(f"- **Total wall time:** {result.total_duration_ms / 1000:.1f}s")
    lines.append("")

    lines.append("## Threshold check")
    lines.append("")
    lines.append("| Dimension | Score | Threshold | Pass |")
    lines.append("|-----------|-------|-----------|------|")
    t = result.threshold
    lines.append(
        f"| Overall | {result.overall_pct:.1f}% | ≥{t.overall_pct:.0f}% | "
        f"{'✓' if result.passes_overall else '✗'} |"
    )
    lines.append(
        f"| Tool usage | {result.dim_pct.get('tool_usage', 0.0):.1f}% | ≥{t.tool_usage_pct:.0f}% | "
        f"{'✓' if result.passes_tool_usage else '✗'} |"
    )
    lines.append(
        f"| Findings | {result.dim_pct.get('findings', 0.0):.1f}% | ≥{t.findings_pct:.0f}% | "
        f"{'✓' if result.passes_findings else '✗'} |"
    )
    lines.append("")

    all_pass = result.passes_overall and result.passes_tool_usage and result.passes_findings
    verdict = "**CLEARS THRESHOLD**" if all_pass else "**BELOW THRESHOLD — tuning required**"
    lines.append(f"{verdict}")
    lines.append("")

    lines.append("## All dimensions")
    lines.append("")
    lines.append("| Dimension | Score |")
    lines.append("|-----------|-------|")
    for dim in DIMENSIONS:
        lines.append(f"| {dim} | {result.dim_pct.get(dim, 0.0):.1f}% |")
    lines.append("")

    if result.per_category:
        lines.append("## Per category")
        lines.append("")
        lines.append("| Category | Overall | Tool usage | Findings | Reasoning | Response |")
        lines.append("|----------|---------|------------|----------|-----------|----------|")
        for cat, dims in sorted(result.per_category.items()):
            lines.append(
                f"| {cat} | {dims.get('overall', 0.0):.1f}% | "
                f"{dims.get('tool_usage', 0.0):.1f}% | "
                f"{dims.get('findings', 0.0):.1f}% | "
                f"{dims.get('reasoning', 0.0):.1f}% | "
                f"{dims.get('response_quality', 0.0):.1f}% |"
            )
        lines.append("")

    lines.append("## Per-prompt verdicts")
    lines.append("")
    lines.append("| ID | Category | Verdict | Tool | Find | Reas | Resp | Halluc |")
    lines.append("|----|----------|---------|------|------|------|------|--------|")
    for v in result.verdicts:
        d = v["dimensions"]
        halluc = str(len(v["hallucinations"])) if v["hallucinations"] else "-"
        lines.append(
            f"| {v['id']} | {v['category']} | {v['verdict']} | "
            f"{d.get('tool_usage', '-')} | {d.get('findings', '-')} | "
            f"{d.get('reasoning', '-')} | {d.get('response_quality', '-')} | {halluc} |"
        )
    lines.append("")

    return "\n".join(lines)


def diff_runs(result_a: AggregateResult, result_b: AggregateResult) -> str:
    """Render a markdown diff between two runs."""
    lines: list[str] = []
    lines.append("# Phase 2 Diff")
    lines.append("")
    lines.append(f"- **A:** `{result_a.run_dir}` ({result_a.profile_name})")
    lines.append(f"- **B:** `{result_b.run_dir}` ({result_b.profile_name})")
    lines.append("")

    lines.append("## Dimension deltas")
    lines.append("")
    lines.append("| Dimension | A | B | Δ |")
    lines.append("|-----------|---|---|---|")
    for dim in ("overall", *DIMENSIONS):
        a = result_a.overall_pct if dim == "overall" else result_a.dim_pct.get(dim, 0.0)
        b = result_b.overall_pct if dim == "overall" else result_b.dim_pct.get(dim, 0.0)
        delta = b - a
        arrow = "↑" if delta > 0 else "↓" if delta < 0 else "="
        lines.append(f"| {dim} | {a:.1f}% | {b:.1f}% | {arrow} {delta:+.1f} |")
    lines.append("")

    a_verdicts = {v["id"]: v for v in result_a.verdicts}
    b_verdicts = {v["id"]: v for v in result_b.verdicts}
    shared = sorted(set(a_verdicts) & set(b_verdicts))

    lines.append("## Per-prompt verdict changes")
    lines.append("")
    lines.append("| ID | Category | A | B | Change |")
    lines.append("|----|----------|---|---|--------|")
    for pid in shared:
        a = a_verdicts[pid]
        b = b_verdicts[pid]
        change = "same" if a["verdict"] == b["verdict"] else f"{a['verdict']} → {b['verdict']}"
        lines.append(f"| {pid} | {a['category']} | {a['verdict']} | {b['verdict']} | {change} |")
    lines.append("")

    return "\n".join(lines)
