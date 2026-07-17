"""LLM-as-judge — score a run's traces against a phase rubric.

The model under test is run via Ollama (blue_bench_eval.qualify) and leaves one
trace per prompt in ``<run-dir>/prompts/``. This module is the second leg: an
INDEPENDENT grader (Claude, the latest Opus family, per the rubric's ``judge:``
block) reads each trace and emits a ``scored/<id>.json`` that
``blue_bench_eval.aggregate`` rolls into a BLUF.

Contract (mirrors the rubric):
  - The judge is never the model under test — it's a separate Anthropic call.
  - It scores each rubric dimension 0-3 with a justification, lists any
    hallucinations, and emits 1-5 concrete tuning_recommendations (rubric's
    tuning_recommendations item) — bench/profile changes, not model fixes.
  - ``discrimination`` (RQ3) is OMITTED for RQ1/RQ2-only prompts (N/A), which
    the aggregator already treats as not-scored.
  - The PASS/PARTIAL/FAIL verdict is computed mechanically from the scores
    (aggregate._verdict_from_rubric) — not left to the judge — so the verdict
    is a deterministic function of the rubric, not grader mood.

The single Anthropic call is isolated behind ``_call_judge`` so tests can mock
it without network access.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from blue_bench_eval.aggregate import DimensionScore, PromptScore, _verdict_from_rubric
from blue_bench_eval.prompts._schema import PromptSpec, load_all

# reasoning_effort -> extended-thinking token budget. "none"/0 disables thinking
# (and lets us use temperature 0 for max determinism); any positive budget
# requires temperature 1 per the Anthropic API.
_EFFORT_BUDGET = {"high": 10000, "medium": 4000, "low": 1024, "none": 0, "off": 0}
_MAX_TOKENS = 4096


@dataclass(frozen=True)
class JudgeConfig:
    model: str
    reasoning_effort: str = "high"

    @property
    def thinking_budget(self) -> int:
        return _EFFORT_BUDGET.get(self.reasoning_effort.lower(), 10000)


@dataclass(frozen=True)
class Rubric:
    name: str
    prompt_prefix: str
    key_dimensions: list[str]
    dimensions: dict[str, dict]          # name -> {description, scale:{0..3}}
    threshold: dict[str, float]
    judge: JudgeConfig
    tuning: dict                          # tuning_recommendations item (min/max/guidance)
    raw: dict


def load_rubric(path: Path) -> Rubric:
    d = yaml.safe_load(path.read_text())
    j = d.get("judge") or {}
    return Rubric(
        name=d.get("name", path.stem),
        prompt_prefix=d.get("prompt_prefix", "p3-"),
        key_dimensions=list(d.get("key_dimensions", [])),
        dimensions=d.get("dimensions", {}),
        threshold=d.get("threshold", {}),
        judge=JudgeConfig(
            model=j.get("model", "claude-opus-4-8"),
            reasoning_effort=str(j.get("reasoning_effort", "high")),
        ),
        tuning=d.get("tuning_recommendations", {"min": 1, "max": 5}),
        raw=d,
    )


# --- prompt construction -----------------------------------------------------


def _is_rq3(spec: PromptSpec | None) -> bool:
    if spec is None:
        return False
    return any(t.upper() == "RQ3" for t in spec.tags) or "discrimination" in spec.category


def _tool_ledger(trace: dict, max_result_chars: int = 1200) -> str:
    """Flatten the trace into a compact call -> result ledger for the judge."""
    lines: list[str] = []
    n = 0
    turns = trace.get("turns", [])
    pending: list[str] = []
    for tu in turns:
        if tu.get("role") == "assistant":
            for c in tu.get("tool_calls") or []:
                n += 1
                pending.append(f"{n}. CALL {c.get('name')}({json.dumps(c.get('args', {}), ensure_ascii=False)})")
            txt = (tu.get("content") or "").strip()
            if txt:
                pending.append(f"   (assistant: {txt[:300]})")
        elif tu.get("role") == "tool":
            res = str(tu.get("content", ""))
            if len(res) > max_result_chars:
                res = res[:max_result_chars] + f"… [+{len(res) - max_result_chars} chars]"
            pending.append(f"   -> {tu.get('tool_name') or ''}: {res}")
        if pending:
            lines.extend(pending)
            pending = []
    return "\n".join(lines) if lines else "(no tool calls recorded)"


def _dimensions_for(spec: PromptSpec | None) -> list[str]:
    return ["tool_usage", "findings", "attribution"] + (["discrimination"] if _is_rq3(spec) else [])


def build_system_prompt(rubric: Rubric) -> str:
    return (
        "You are an independent grader for Blue-Bench, a blue-team LLM benchmark. "
        "You score the trace of a MODEL UNDER TEST that hunted a security corpus "
        "through bounded MCP tools. You are NOT that model and you must not defer "
        "to its conclusions — verify them against the tool results in the trace and "
        "the provided ground truth.\n\n"
        f"RUBRIC: {rubric.name}. Score each applicable dimension 0-3 using these scales:\n"
        + _render_scales(rubric)
        + "\n\nRULES:\n"
        "- Score ONLY the dimensions listed as applicable in the user message. If "
        "'discrimination' is not listed, the prompt is RQ1/RQ2 — omit it entirely.\n"
        "- 'findings' is scored against the expected_findings synonym sets: a synonym "
        "set counts as matched only if the final answer surfaces it as a real finding. "
        "Naming the WRONG victim host, or presenting benign activity as an intrusion, "
        "is a material hallucination (findings <= 0 / list it under hallucinations).\n"
        "- Do not reward fluent narrative that is not supported by the tool results.\n"
        f"- tuning_recommendations: emit {rubric.tuning.get('min', 1)}-{rubric.tuning.get('max', 5)} "
        "concrete, verifiable changes to the BENCH/profile (coaching hints, tool-arg "
        "defaults, max_turns, prompt wording, corpus gaps) that would lift the "
        "lowest-scoring dimensions. Each names the dimension it targets and the specific "
        "change. These tune the harness, NOT the model under test. If the trace clears "
        "threshold, this may be empty.\n\n"
        "Respond with ONLY a single JSON object, no prose, no code fences:\n"
        '{"dimensions": {"<dim>": {"score": <0-3>, "justification": "<text>"}, ...}, '
        '"hallucinations": ["<text>", ...], "tuning_recommendations": ["<text>", ...]}'
    )


def _render_scales(rubric: Rubric) -> str:
    out: list[str] = []
    for dim, body in rubric.dimensions.items():
        out.append(f"\n[{dim}] {body.get('description', '')}")
        for score in (0, 1, 2, 3):
            desc = (body.get("scale") or {}).get(score)
            if desc is not None:
                out.append(f"  {score}: {desc}")
    return "\n".join(out)


def build_user_prompt(spec: PromptSpec | None, trace: dict) -> str:
    applicable = _dimensions_for(spec)
    parts: list[str] = []
    parts.append(f"PROMPT ID: {trace.get('prompt_id')}")
    if spec is not None:
        parts.append(f"CATEGORY: {spec.category}   TAGS: {', '.join(spec.tags)}")
    parts.append(f"APPLICABLE DIMENSIONS (score exactly these): {', '.join(applicable)}")
    parts.append("")
    parts.append("QUESTION POSED TO THE MODEL:")
    parts.append(trace.get("question", "").strip())
    parts.append("")
    if spec is not None and spec.expected_findings:
        parts.append("GROUND TRUTH — expected finding synonym sets (each set = one required finding):")
        for i, fs in enumerate(spec.expected_findings, 1):
            parts.append(f"  {i}. {fs.synonyms}")
        if spec.pass_criteria:
            parts.append(f"PASS CRITERIA: {spec.pass_criteria}")
        if spec.expected_tools:
            parts.append(f"EXPECTED TOOLS: {', '.join(spec.expected_tools)}")
        parts.append("")
    # Surface mechanical grounding if present (ungrounded = fabricated entities).
    g = trace.get("grounding")
    if g and g.get("ungrounded"):
        vals = [c.get("value") for c in g["ungrounded"]][:20]
        parts.append(f"MECHANICAL GROUNDING — entities in the answer NOT found in any tool result: {vals}")
        parts.append("")
    parts.append("TOOL-CALL LEDGER (call -> bounded result):")
    parts.append(_tool_ledger(trace))
    parts.append("")
    parts.append("MODEL'S FINAL ANSWER:")
    parts.append(trace.get("final_answer", "").strip() or "(empty)")
    return "\n".join(parts)


# --- the one networked call (mocked in tests) --------------------------------


def _call_judge(cfg: JudgeConfig, system: str, user: str) -> str:
    """Single Anthropic call. Returns the raw assistant text (JSON expected).

    Isolated so tests monkeypatch it. Uses extended thinking for high effort
    (temperature pinned to 1 as the API requires); falls back to temperature 0
    when thinking is disabled for maximum determinism.
    """
    import anthropic

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("judge needs ANTHROPIC_API_KEY in the environment (.env)")
    client = anthropic.Anthropic()
    effort = (cfg.reasoning_effort or "high").lower()
    kwargs: dict = {
        "model": cfg.model,
        "max_tokens": _MAX_TOKENS + cfg.thinking_budget,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    if effort in ("high", "medium", "low"):
        # opus-4.8+ uses ADAPTIVE thinking with effort in output_config
        # (the old thinking.type=enabled + budget_tokens form is rejected).
        kwargs["thinking"] = {"type": "adaptive"}
        kwargs["output_config"] = {"effort": effort}
    else:
        kwargs["temperature"] = 0.0
    try:
        resp = client.messages.create(**kwargs)
    except anthropic.BadRequestError:
        # Older/other models: retry as a plain deterministic call.
        for k in ("thinking", "output_config"):
            kwargs.pop(k, None)
        kwargs["temperature"] = 0.0
        resp = client.messages.create(**kwargs)
    # Concatenate text blocks, skipping thinking blocks.
    return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")


def _parse_judge_json(raw: str) -> dict:
    """Extract the JSON object from the judge's reply (tolerates stray fences)."""
    s = raw.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\n?", "", s).rstrip("`").rstrip()
    # Grab the outermost {...} if there is surrounding prose.
    start, end = s.find("{"), s.rfind("}")
    if start != -1 and end != -1 and end > start:
        s = s[start : end + 1]
    return json.loads(s)


def score_trace(
    trace: dict,
    spec: PromptSpec | None,
    rubric: Rubric,
    *,
    call=_call_judge,
) -> PromptScore:
    """Judge one trace -> PromptScore (verdict computed mechanically)."""
    system = build_system_prompt(rubric)
    user = build_user_prompt(spec, trace)
    raw = call(rubric.judge, system, user)
    data = _parse_judge_json(raw)

    applicable = set(_dimensions_for(spec))
    dims: dict[str, DimensionScore] = {}
    for name, body in (data.get("dimensions") or {}).items():
        if name not in applicable:
            continue  # judge over-scored (e.g. discrimination on RQ2) — drop it
        dims[name] = DimensionScore(score=int(body["score"]), justification=str(body.get("justification", "")))
    if not dims:
        raise ValueError(f"judge returned no applicable dimension scores for {trace.get('prompt_id')}")

    verdict = _verdict_from_rubric({k: v.score for k, v in dims.items()}, rubric.key_dimensions)
    return PromptScore(
        prompt_id=trace.get("prompt_id", "unknown"),
        dimensions=dims,
        verdict=verdict,
        hallucinations=[str(h) for h in (data.get("hallucinations") or [])],
        tuning_recommendations=[str(t) for t in (data.get("tuning_recommendations") or [])],
    )


def judge_run(
    run_dir: Path,
    rubric_path: Path,
    *,
    prompts_dir: Path | None = None,
    overwrite: bool = False,
    model_override: str | None = None,
    call=_call_judge,
) -> list[PromptScore]:
    """Judge every trace in ``run_dir/prompts/`` and write ``run_dir/scored/``."""
    rubric = load_rubric(rubric_path)
    if model_override:
        rubric = Rubric(**{**rubric.__dict__, "judge": JudgeConfig(model_override, rubric.judge.reasoning_effort)})

    specs: dict[str, PromptSpec] = {}
    if prompts_dir is not None:
        specs = {s.id: s for s in load_all(prompts_dir, prefix=rubric.prompt_prefix)}

    prompts = run_dir / "prompts"
    scored_dir = run_dir / "scored"
    scored_dir.mkdir(parents=True, exist_ok=True)

    out: list[PromptScore] = []
    for tf in sorted(prompts.glob("*.json")):
        if tf.name.endswith(".error.json"):
            continue
        trace = json.loads(tf.read_text())
        pid = trace.get("prompt_id", tf.stem)
        dest = scored_dir / f"{pid}.json"
        if dest.exists() and not overwrite:
            out.append(PromptScore.model_validate_json(dest.read_text()))
            continue
        score = score_trace(trace, specs.get(pid), rubric, call=call)
        dest.write_text(score.model_dump_json(indent=2))
        out.append(score)
    return out
