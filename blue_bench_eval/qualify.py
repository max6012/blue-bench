"""Phase 2 run harness — execute the prompt corpus under a profile, persist traces.

Produces results/<YYYYMMDD-HHMMSS>-<profile>[-<tag>]/
  prompts/{id}.json   # one trace per prompt (from blue_bench_client.runner)
  run_meta.json       # profile, model, git HEAD, wall time, counts
  scored/             # (empty — populated later by the judging loop)

Consumed by blue_bench_eval.aggregate.aggregate().
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from blue_bench_client.runner import run
from blue_bench_client.trace import Trace
from blue_bench_eval.prompts._schema import PromptSpec, load_all
from blue_bench_mcp.profiles import ModelProfile, load_profile

REPO = Path(__file__).parent.parent
PROFILES_DIR = REPO / "blue_bench_mcp" / "profiles"
PROMPTS_DIR = REPO / "blue_bench_eval" / "prompts"
RESULTS_DIR = REPO / "results"


@dataclass
class RunMeta:
    run_id: str
    profile_name: str
    model_id: str
    tool_protocol: str
    prompt_count: int
    prompts_completed: int = 0
    prompts_errored: int = 0
    total_duration_ms: int = 0
    tag: str = ""
    git_head: str = ""
    started_at: str = ""
    finished_at: str = ""
    prompt_ids: list[str] = field(default_factory=list)


def _git_head() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO), stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _select(specs: list[PromptSpec], tag: str, limit: int | None) -> list[PromptSpec]:
    if tag:
        specs = [s for s in specs if tag in s.tags or s.category == tag]
    if limit:
        specs = specs[:limit]
    return specs


def _run_dir(run_id: str, profile_name: str, tag: str) -> Path:
    suffix = f"-{tag}" if tag else ""
    return RESULTS_DIR / f"{run_id}-{profile_name}{suffix}"


async def _run_one(
    profile: ModelProfile,
    spec: PromptSpec,
    config_path: Path | None,
    out_dir: Path,
) -> Trace:
    """Run one prompt through the runner and persist its trace."""
    trace = await run(
        profile,
        question=spec.question,
        prompt_id=spec.id,
        config_path=config_path,
        max_turns=spec.max_turns,
    )
    (out_dir / "prompts").mkdir(parents=True, exist_ok=True)
    (out_dir / "prompts" / f"{spec.id}.json").write_text(trace.model_dump_json(indent=2))
    return trace


async def run_corpus(
    profile_name: str,
    *,
    tag: str = "",
    limit: int | None = None,
    config_path: Path | None = None,
    prompts_dir: Path = PROMPTS_DIR,
    profiles_dir: Path = PROFILES_DIR,
    results_dir: Path = RESULTS_DIR,
) -> Path:
    """Execute the prompt corpus under `profile_name` and return the run dir."""
    profile = load_profile(profiles_dir / f"{profile_name}.yaml")
    specs = _select(load_all(prompts_dir), tag=tag, limit=limit)
    if not specs:
        raise ValueError(
            f"no prompts matched (tag={tag!r}, limit={limit}, dir={prompts_dir})"
        )

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = _run_dir(run_id, profile_name, tag)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scored").mkdir(exist_ok=True)

    meta = RunMeta(
        run_id=run_id,
        profile_name=profile.name,
        model_id=profile.model_id,
        tool_protocol=profile.tool_protocol,
        prompt_count=len(specs),
        tag=tag,
        git_head=_git_head(),
        started_at=datetime.now().isoformat(),
        prompt_ids=[s.id for s in specs],
    )

    print(
        f"\n=== Blue-Bench Phase 2 — profile={profile.name} protocol={profile.tool_protocol} "
        f"prompts={len(specs)}{f' tag={tag}' if tag else ''} ==="
    )
    print(f"run_dir: {out_dir}\n")

    overall_start = time.monotonic()
    for idx, spec in enumerate(specs, start=1):
        print(f"[{idx:2d}/{len(specs)}] {spec.id} ({spec.category}) ...", flush=True)
        t0 = time.monotonic()
        try:
            trace = await _run_one(profile, spec, config_path, out_dir)
            dur = int((time.monotonic() - t0) * 1000)
            tool_calls = sum(1 for t in trace.turns if t.role == "tool")
            tag_suffix = f" ERROR: {trace.error}" if trace.error else ""
            print(
                f"           {dur/1000:5.1f}s  turns={trace.turns_used:2d}  "
                f"tool_calls={tool_calls:2d}  answer={len(trace.final_answer)}c{tag_suffix}"
            )
            if trace.error:
                meta.prompts_errored += 1
            else:
                meta.prompts_completed += 1
        except Exception as e:
            # Catastrophic failure — don't let one bad prompt kill the corpus.
            dur = int((time.monotonic() - t0) * 1000)
            print(f"           {dur/1000:5.1f}s  CRASHED: {type(e).__name__}: {e}")
            meta.prompts_errored += 1
            err_path = out_dir / "prompts" / f"{spec.id}.error.json"
            err_path.parent.mkdir(parents=True, exist_ok=True)
            err_path.write_text(
                json.dumps({"prompt_id": spec.id, "error": f"{type(e).__name__}: {e}"}, indent=2)
            )
    meta.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
    meta.finished_at = datetime.now().isoformat()
    (out_dir / "run_meta.json").write_text(json.dumps(asdict(meta), indent=2))

    print(
        f"\nDone — {meta.prompts_completed}/{meta.prompt_count} completed, "
        f"{meta.prompts_errored} errored, "
        f"total {meta.total_duration_ms/1000:.1f}s"
    )
    print(f"Run dir: {out_dir}")
    return out_dir


def main() -> None:
    p = argparse.ArgumentParser(description="Run Blue-Bench Phase 2 prompts under a profile")
    p.add_argument("--profile", required=True, help="Profile YAML stem (e.g., gemma4-e4b)")
    p.add_argument("--tag", default="", help="Filter prompts by tag or category")
    p.add_argument("--limit", type=int, default=None, help="Stop after N prompts")
    p.add_argument("--config", type=Path, default=REPO / "config.yaml", help="MCP server config.yaml")
    args = p.parse_args()
    asyncio.run(
        run_corpus(
            args.profile,
            tag=args.tag,
            limit=args.limit,
            config_path=args.config,
        )
    )


if __name__ == "__main__":
    main()
