"""Run a fixed worker slice set against one model, then score it.

    python scripts/run_worker_slices.py run --cases eval/worker_slices.yaml \
        --profile blue_bench_mcp/profiles/claude-opus-5.yaml \
        --ground-truth ~/Blue-Bench-work/corpus-l/ground-truth --out results/worker/opus5
    python scripts/run_worker_slices.py run ... --profile cloud:glm-5.2 ...
    python scripts/run_worker_slices.py table results/worker/* --ceiling claude-opus-5

Each slice runs as a real fan-out worker (``run_worker``): role-only prompt,
MCP server launched with ``--slice``. Per slice the trace and parsed report are
saved; ``score.json`` holds the per-case scores. Every model gets the same
slices, so the table compares like with like.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from blue_bench_client.fanout.host_resolve import HostResolver  # noqa: E402
from blue_bench_client.fanout.worker import run_worker  # noqa: E402
from blue_bench_eval import worker_score as ws  # noqa: E402


def _profile(spec: str):
    if spec.startswith("cloud:"):
        from blue_bench_client.cloud_models import generic_cloud_profile
        return generic_cloud_profile(spec.removeprefix("cloud:"), coached=False)
    from blue_bench_mcp.profiles import load_profile
    return load_profile(Path(spec))


async def _run(args) -> None:
    import httpx
    r = httpx.get(f"{args.es_url}/bb-meta/_doc/corpus-anchor", timeout=10)
    anchor = r.json().get("_source") if r.status_code == 200 else None
    cases = ws.load_cases(Path(args.cases).expanduser(), anchor)
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c.slice.id in wanted]
    gt = ws.load_ground_truth(Path(args.ground_truth).expanduser())
    profile = _profile(args.profile)
    if args.context_size:
        # The in-memory cloud profiles default to 32k; fifteen tool results can
        # exceed that and push the earliest ones out of an open-weight worker's
        # window while Opus keeps them. One uniform size for every candidate.
        profile = profile.model_copy(update={"context_size": args.context_size})
    if args.tool_protocol:
        # Every Opus runs through the same transport, whatever its profile says.
        profile = profile.model_copy(update={"tool_protocol": args.tool_protocol})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    resolver = HostResolver(args.es_url)
    sem = asyncio.Semaphore(args.concurrency)

    async def one(case: ws.SliceCase) -> ws.CaseScore:
        async with sem:
            trace, report = await run_worker(
                profile, case.slice, depth=0, config_path=None, server_cmd=None,
                max_turns_ceiling=args.max_turns, resolver=resolver)
        sid = case.slice.id
        (out / f"{sid}.trace.json").write_text(trace.model_dump_json(indent=1), encoding="utf-8")
        if report is not None:
            (out / f"{sid}.report.json").write_text(report.model_dump_json(indent=1), encoding="utf-8")
        results = [t.content for t in trace.turns if t.role == "tool"]
        wrong = [m for m in trace.served_models if not m.startswith(profile.model_id)]
        if wrong:
            # Graded as model X but answered by model Y: not X's score.
            report, trace.error = None, f"served by {wrong}, not {profile.model_id}"
        s = ws.score_case(case, report, results, gt, error=trace.error)
        print(f"{sid}: {'CORRECT' if s.correct else 'wrong'} "
              f"({'clean' if s.clean else 'attack'}; turns {trace.turns_used}; {trace.error or 'ok'})",
              flush=True)
        return s

    scores = list(await asyncio.gather(*(one(c) for c in cases)))
    prior = out / "score.json"
    if args.only and prior.exists():
        # A repair run replaces just the cases it re-ran.
        old = ws.ModelScore.model_validate_json(prior.read_text())
        redone = {c.slice_id for c in scores}
        scores = [c for c in old.cases if c.slice_id not in redone] + scores
    ms = ws.ModelScore(model=profile.name, cases=scores)
    (out / "score.json").write_text(ms.model_dump_json(indent=1), encoding="utf-8")
    print(json.dumps(ms.summary(), indent=1))


def _rescore(args) -> None:
    """Re-parse every saved final answer with the current parser and score it
    again, so a parser fix reaches runs that already finished. Model output
    is not re-generated; only how we read it changes."""
    import httpx

    from blue_bench_client.fanout.schema import WorkerReportParseError, parse_worker_report
    from blue_bench_client.trace import Trace

    r = httpx.get(f"{args.es_url}/bb-meta/_doc/corpus-anchor", timeout=10)
    anchor = r.json().get("_source") if r.status_code == 200 else None
    cases = {c.slice.id: c for c in ws.load_cases(Path(args.cases).expanduser(), anchor)}
    gt = ws.load_ground_truth(Path(args.ground_truth).expanduser())
    for d in map(Path, args.dirs):
        prior = ws.ModelScore.model_validate_json((d / "score.json").read_text())
        rescored = []
        for old in prior.cases:
            tp = d / f"{old.slice_id}.trace.json"
            if not tp.exists() or old.slice_id not in cases:
                rescored.append(old)
                continue
            trace = Trace.model_validate_json(tp.read_text())
            wrong = [m for m in trace.served_models if not m.startswith(trace.model_id)]
            report, err = None, trace.error
            if trace.final_answer and not wrong:
                try:
                    report = parse_worker_report(trace.final_answer)
                    report.turns_used = trace.turns_used
                except WorkerReportParseError as e:
                    err = f"{err + '; ' if err else ''}WorkerReportParseError: {e}"
            elif wrong:
                err = f"served by {wrong}, not {trace.model_id}"
            results = [t.content for t in trace.turns if t.role == "tool"]
            rescored.append(ws.score_case(cases[old.slice_id], report, results, gt, error=err))
        ms = ws.ModelScore(model=prior.model, cases=rescored)
        (d / "score.json").write_text(ms.model_dump_json(indent=1), encoding="utf-8")
        print(json.dumps(ms.summary()))


def _table(args) -> None:
    scores = [ws.ModelScore.model_validate_json((Path(d) / "score.json").read_text())
              for d in args.dirs if (Path(d) / "score.json").exists()]
    print(ws.table(scores, ceiling=args.ceiling))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--cases", required=True)
    r.add_argument("--profile", required=True, help="profile YAML path, or cloud:<ollama-model>")
    r.add_argument("--ground-truth", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--es-url", default="http://localhost:9200")
    r.add_argument("--max-turns", type=int, default=20, help="harness ceiling on each slice's budget")
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument("--context-size", type=int, default=None, help="override the profile's context window (tokens)")
    r.add_argument("--tool-protocol", default=None, help="override the profile's transport, e.g. anthropic-cli")
    r.add_argument("--only", default="", help="comma list of slice ids to (re)run; merges into score.json")
    rs = sub.add_parser("rescore")
    rs.add_argument("dirs", nargs="+")
    rs.add_argument("--cases", required=True)
    rs.add_argument("--ground-truth", required=True)
    rs.add_argument("--es-url", default="http://localhost:9200")
    t = sub.add_parser("table")
    t.add_argument("dirs", nargs="+")
    t.add_argument("--ceiling", default=None)
    a = ap.parse_args()
    if a.cmd == "run":
        asyncio.run(_run(a))
    elif a.cmd == "rescore":
        _rescore(a)
    else:
        _table(a)


if __name__ == "__main__":
    main()
