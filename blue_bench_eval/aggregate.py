"""Aggregator — reads prompts/ traces + scored/ judgments, writes BLUF.md.

Pure function over filesystem. No live deps. Called by blue-bench CLI.
Supports pluggable rubrics for Phase 1 and Phase 2.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

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
    model_config = ConfigDict(extra="allow")

    def dim_thresholds(self) -> dict[str, float]:
        """Return dimension-specific threshold percentages keyed by dimension name."""
        result: dict[str, float] = {}
        for key, val in (self.model_extra or {}).items():
            if key.endswith("_pct"):
                result[key[:-4]] = float(val)
        return result


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
    passes_key_dims: dict[str, bool] = field(default_factory=dict)

    # Per-prompt detail.
    verdicts: list[dict] = field(default_factory=list)  # [{id, category, verdict, dim_scores}]

    # Ordered dimension names and key dimensions loaded from the rubric.
    dimensions: list[str] = field(default_factory=list)
    key_dimensions: list[str] = field(default_factory=list)

    @property
    def passes_tool_usage(self) -> bool:
        return self.passes_key_dims.get("tool_usage", True)

    @property
    def passes_findings(self) -> bool:
        return self.passes_key_dims.get("findings", True)


def _score_to_pct(score: int) -> float:
    return (score / 3.0) * 100.0


def _verdict_from_rubric(dim_scores: dict[str, int], key_dimensions: list[str]) -> Verdict:
    if any(s == 0 for s in dim_scores.values()):
        return "FAIL"
    for kd in key_dimensions:
        if dim_scores.get(kd, 0) == 0:
            return "FAIL"
    if all(s >= 2 for s in dim_scores.values()) and all(
        dim_scores.get(kd, 0) >= 2 for kd in key_dimensions
    ):
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


def _load_rubric(rubric_path: Path) -> tuple[RubricThreshold, list[str], list[str], str]:
    """Load rubric YAML.

    Returns:
        (threshold, dimensions, key_dimensions, prompt_prefix)
    """
    with open(rubric_path) as f:
        raw = yaml.safe_load(f)
    threshold = RubricThreshold.model_validate(raw["threshold"])
    dimensions = list(raw.get("dimensions", {}).keys())
    key_dimensions = raw.get("key_dimensions", [])
    prompt_prefix = raw.get("prompt_prefix", "p2-")
    return threshold, dimensions, key_dimensions, prompt_prefix


def _load_prompt_categories(prompts_dir: Path, prefix: str = "p2-") -> dict[str, str]:
    """Map prompt_id -> category by reading the YAML specs."""
    cats: dict[str, str] = {}
    for f in sorted(prompts_dir.glob(f"{prefix}*.yaml")):
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
    threshold, dimensions, key_dimensions, prompt_prefix = _load_rubric(rubric_path)
    categories = _load_prompt_categories(prompts_dir, prefix=prompt_prefix) if prompts_dir else {}

    result = AggregateResult(
        run_dir=run_dir,
        threshold=threshold,
        prompt_count=len(scores),
        dimensions=dimensions,
        key_dimensions=key_dimensions,
    )

    # Pull run-level metadata from the first trace (profile is uniform per run).
    if traces:
        first = next(iter(traces.values()))
        result.profile_name = first.get("profile_name", "")
        result.model_id = first.get("model_id", "")
        result.total_duration_ms = sum(t.get("total_duration_ms", 0) for t in traces.values())

    # Dimension percentages (run-level). A dimension that NO prompt scored
    # (e.g. discrimination/RQ3 on an RQ1/RQ2-only run, marked N/A by omission)
    # is excluded entirely — counting it as 0 would wrongly drag overall down.
    for dim in dimensions:
        dim_pcts = [_score_to_pct(s.dimensions[dim].score) for s in scores if dim in s.dimensions]
        if dim_pcts:
            result.dim_pct[dim] = mean(dim_pcts)
    result.overall_pct = mean(result.dim_pct.values()) if result.dim_pct else 0.0

    # Threshold check.
    result.passes_overall = result.overall_pct >= threshold.overall_pct
    dim_thresholds = threshold.dim_thresholds()
    for kd in key_dimensions:
        result.passes_key_dims[kd] = result.dim_pct.get(kd, 0.0) >= dim_thresholds.get(kd, 0.0)

    # Per-category rollup.
    by_cat: dict[str, list[PromptScore]] = defaultdict(list)
    for s in scores:
        by_cat[categories.get(s.prompt_id, "uncategorized")].append(s)
    for cat, cat_scores in by_cat.items():
        cat_dims: dict[str, float] = {}
        for dim in dimensions:
            pcts = [_score_to_pct(sc.dimensions[dim].score) for sc in cat_scores if dim in sc.dimensions]
            if pcts:
                cat_dims[dim] = mean(pcts)
        cat_dims["overall"] = mean(cat_dims.values()) if cat_dims else 0.0
        result.per_category[cat] = cat_dims

    # Per-prompt verdict detail.
    for s in scores:
        result.verdicts.append(
            {
                "id": s.prompt_id,
                "category": categories.get(s.prompt_id, "uncategorized"),
                "verdict": s.verdict,
                "dimensions": {dim: s.dimensions[dim].score for dim in dimensions if dim in s.dimensions},
                "hallucinations": s.hallucinations,
            }
        )

    return result


def render_bluf(result: AggregateResult) -> str:
    """Format an AggregateResult as markdown BLUF."""
    dimensions = result.dimensions
    key_dimensions = result.key_dimensions
    dim_thresholds = result.threshold.dim_thresholds() if result.threshold else {}

    lines: list[str] = []
    lines.append(f"# BLUF — {result.profile_name}")
    lines.append("")
    lines.append(f"- **Run directory:** `{result.run_dir}`")
    lines.append(f"- **Model:** `{result.model_id}`")
    lines.append(f"- **Prompts:** {result.prompt_count}")
    if result.total_duration_ms:
        lines.append(f"- **Total wall time:** {result.total_duration_ms / 1000:.1f}s")
    lines.append("")

    # A dimension absent from dim_pct was N/A for every prompt (e.g. RQ3
    # discrimination on an RQ1/RQ2-only run) — show N/A, not a spurious 0.0%.
    def _pct(dim: str) -> str:
        return f"{result.dim_pct[dim]:.1f}%" if dim in result.dim_pct else "N/A"

    lines.append("## Threshold check")
    lines.append("")
    lines.append("| Dimension | Score | Threshold | Pass |")
    lines.append("|-----------|-------|-----------|------|")
    t = result.threshold
    lines.append(
        f"| Overall | {result.overall_pct:.1f}% | ≥{t.overall_pct:.0f}% | "
        f"{'✓' if result.passes_overall else '✗'} |"
    )
    for kd in key_dimensions:
        kd_threshold = dim_thresholds.get(kd, 0.0)
        na = kd not in result.dim_pct
        kd_pass = result.passes_key_dims.get(kd, True)
        pass_mark = "—" if na else ("✓" if kd_pass else "✗")
        lines.append(
            f"| {kd.replace('_', ' ').title()} | {_pct(kd)} | "
            f"≥{kd_threshold:.0f}% | {pass_mark} |"
        )
    lines.append("")

    all_pass = result.passes_overall and all(result.passes_key_dims.values())
    verdict = "**CLEARS THRESHOLD**" if all_pass else "**BELOW THRESHOLD — tuning required**"
    lines.append(f"{verdict}")
    lines.append("")

    lines.append("## All dimensions")
    lines.append("")
    lines.append("| Dimension | Score |")
    lines.append("|-----------|-------|")
    for dim in dimensions:
        lines.append(f"| {dim} | {_pct(dim)} |")
    lines.append("")

    if result.per_category:
        lines.append("## Per category")
        lines.append("")
        header = "| Category | Overall | " + " | ".join(d.replace("_", " ").title() for d in dimensions) + " |"
        sep = "|----------|---------|" + "|".join("-" * max(len(d.replace("_", " ").title()) + 2, 9) for d in dimensions) + "|"
        lines.append(header)
        lines.append(sep)
        for cat, dims in sorted(result.per_category.items()):
            row = f"| {cat} | {dims.get('overall', 0.0):.1f}% | "
            row += " | ".join(f"{dims[d]:.1f}%" if d in dims else "N/A" for d in dimensions)
            row += " |"
            lines.append(row)
        lines.append("")

    lines.append("## Per-prompt verdicts")
    lines.append("")
    dim_abbrevs = [d[:4].title() for d in dimensions]
    header = "| ID | Category | Verdict | " + " | ".join(dim_abbrevs) + " | Halluc |"
    sep = "|----|----------|---------|" + "|".join("------" for _ in dimensions) + "|--------|"
    lines.append(header)
    lines.append(sep)
    for v in result.verdicts:
        d = v["dimensions"]
        halluc = str(len(v["hallucinations"])) if v["hallucinations"] else "-"
        dim_cols = " | ".join(str(d.get(dim, "-")) for dim in dimensions)
        lines.append(f"| {v['id']} | {v['category']} | {v['verdict']} | {dim_cols} | {halluc} |")
    lines.append("")

    return "\n".join(lines)


def diff_runs(result_a: AggregateResult, result_b: AggregateResult) -> str:
    """Render a markdown diff between two runs."""
    # Use the union of both results' dimensions for the diff table.
    seen: set[str] = set()
    all_dims: list[str] = []
    for d in result_a.dimensions + result_b.dimensions:
        if d not in seen:
            all_dims.append(d)
            seen.add(d)

    lines: list[str] = []
    lines.append("# Diff")
    lines.append("")
    lines.append(f"- **A:** `{result_a.run_dir}` ({result_a.profile_name})")
    lines.append(f"- **B:** `{result_b.run_dir}` ({result_b.profile_name})")
    lines.append("")

    lines.append("## Dimension deltas")
    lines.append("")
    lines.append("| Dimension | A | B | Δ |")
    lines.append("|-----------|---|---|---|")
    for dim in ("overall", *all_dims):
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
