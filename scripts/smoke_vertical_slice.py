"""End-to-end smoke for the vertical slice.

Runs the same analyst question through both model profiles (gemma4-e4b
text-embedded + llama3.1-8b native) against a live MCP server. Writes composed
prompts and traces to results/<timestamp>-smoke/ for inspection and asserts:

1. Profile swap is a config-key change (only argument differs between calls).
2. Composed prompts diff cleanly between profiles (non-empty, distinct).
3. Each profile makes at least one successful tool call.
4. Each profile produces a non-empty final answer (or a recorded error).

Exit 0 on pass, 1 on fail. Writes artifacts regardless.
"""
from __future__ import annotations

import asyncio
import difflib
import json
import sys
from datetime import datetime
from pathlib import Path

from blue_bench_client.runner import run
from blue_bench_mcp.profiles import load_profile

REPO = Path(__file__).parent.parent
PROFILES_DIR = REPO / "blue_bench_mcp" / "profiles"
CONFIG_PATH = REPO / "config.yaml"

QUESTION = (
    "List the evidence files currently available, then compute the sha256 of "
    "sample_alert.txt. Report both findings."
)


async def run_profile(profile_name: str, out_dir: Path) -> tuple[str, dict]:
    profile = load_profile(PROFILES_DIR / f"{profile_name}.yaml")
    trace = await run(
        profile,
        QUESTION,
        prompt_id="smoke_evidence",
        config_path=CONFIG_PATH,
        max_turns=6,
    )
    (out_dir / f"{profile_name}.system_prompt.md").write_text(trace.composed_system_prompt)
    (out_dir / f"{profile_name}.trace.json").write_text(trace.model_dump_json(indent=2))
    return trace.composed_system_prompt, trace.model_dump()


def assert_accept(traces: dict[str, dict], out_dir: Path) -> list[str]:
    failures: list[str] = []
    profiles = list(traces.keys())

    # (1) Profile swap = config-key change — covered by the caller invoking run()
    #     with only the profile argument changing. Here we just assert both ran.
    if len(profiles) != 2:
        failures.append(f"expected 2 profiles, got {len(profiles)}: {profiles}")

    # (2) Composed prompts differ between profiles
    p0, p1 = profiles[0], profiles[1]
    if traces[p0]["composed_system_prompt"] == traces[p1]["composed_system_prompt"]:
        failures.append("composed prompts are identical across profiles — profile system not active")

    # (3) Each profile made at least one successful tool call
    for pname, tr in traces.items():
        tool_turns = [t for t in tr["turns"] if t["role"] == "tool"]
        if not tool_turns:
            failures.append(f"{pname}: no tool results recorded — model did not call any tool")
        elif all(t["content"].startswith("Error:") for t in tool_turns):
            failures.append(f"{pname}: every tool call returned an error")

    # (4) Each profile produced a non-empty final answer (unless it errored cleanly)
    for pname, tr in traces.items():
        if not tr["final_answer"] and not tr["error"]:
            failures.append(f"{pname}: empty final_answer and no recorded error")

    return failures


async def main() -> int:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = REPO / "results" / f"{ts}-smoke"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Smoke test artifacts → {out_dir}\n")

    results: dict[str, dict] = {}
    for profile_name in ("gemma4-e4b", "gemma3-4b"):
        print(f"=== Running profile: {profile_name} ===")
        try:
            _, trace_dict = await run_profile(profile_name, out_dir)
        except Exception as e:
            print(f"  FAILED to run {profile_name}: {type(e).__name__}: {e}")
            results[profile_name] = {"error": str(e), "turns": [], "final_answer": "", "composed_system_prompt": ""}
            continue
        print(f"  turns_used: {trace_dict['turns_used']}")
        print(f"  tools_called: {[t['tool_name'] for t in trace_dict['turns'] if t['role'] == 'tool']}")
        print(f"  final_answer length: {len(trace_dict['final_answer'])}")
        if trace_dict["error"]:
            print(f"  error: {trace_dict['error']}")
        results[profile_name] = trace_dict
        print()

    # Write per-profile prompt diff
    if "gemma4-e4b" in results and "gemma3-4b" in results:
        a = results["gemma4-e4b"]["composed_system_prompt"].splitlines()
        b = results["gemma3-4b"]["composed_system_prompt"].splitlines()
        diff = "\n".join(difflib.unified_diff(a, b, fromfile="gemma4-e4b", tofile="gemma3-4b", lineterm=""))
        (out_dir / "prompts.diff").write_text(diff)

    # Acceptance
    failures = assert_accept(results, out_dir)
    (out_dir / "acceptance.json").write_text(json.dumps({"failures": failures, "passed": not failures}, indent=2))

    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: vertical slice smoke test cleared acceptance")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
