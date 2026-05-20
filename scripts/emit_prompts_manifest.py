#!/usr/bin/env python3
"""Emit blue_bench_frontend/prompts.json from blue_bench_eval/prompts/p2-*.yaml.

Static manifest consumed by the browser UI to render suggested prompts. Each
entry mirrors the eval YAML minus rubric/pass-criteria fields the UI does not
need at runtime.

Run:
    python scripts/emit_prompts_manifest.py

Output: blue_bench_frontend/prompts.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
PROMPTS_DIR = REPO / "blue_bench_eval" / "prompts"
OUTPUT = REPO / "blue_bench_frontend" / "prompts.json"

FIELDS = ("id", "category", "title", "question", "expected_tools", "tags")


def main() -> int:
    yaml_paths = sorted(PROMPTS_DIR.glob("p2-*.yaml"))
    if not yaml_paths:
        print(f"no prompts found under {PROMPTS_DIR}", file=sys.stderr)
        return 1

    entries = []
    for p in yaml_paths:
        data = yaml.safe_load(p.read_text()) or {}
        entry = {k: data.get(k) for k in FIELDS if k in data}
        entry["question"] = (entry.get("question") or "").strip()
        entries.append(entry)

    manifest = {"version": 1, "prompts": entries}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {OUTPUT} ({len(entries)} prompt(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
