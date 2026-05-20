"""Emit frontend + CLI tool-category modules from tool_categories.yaml.

Run:
    python scripts/emit_tool_categories.py

Writes:
    blue_bench_frontend/_tool_categories_data.js  (ESM, just the array)
    blue_bench_cli/_tool_categories.py            (Python module)

Both consumers (frontend and CLI) share this single YAML source of
truth. Edit the YAML, run this script, commit the generated files.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from textwrap import dedent

import yaml

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "tool_categories.yaml"
JS_OUT = REPO / "blue_bench_frontend" / "_tool_categories_data.js"
PY_OUT = REPO / "blue_bench_cli" / "_tool_categories.py"

GENERATED_HEADER = (
    "// AUTO-GENERATED from tool_categories.yaml — do not edit by hand.\n"
    "// Re-run: python scripts/emit_tool_categories.py\n"
)
PY_HEADER = (
    '"""AUTO-GENERATED from tool_categories.yaml — do not edit by hand.\n\n'
    "Re-run: python scripts/emit_tool_categories.py\n"
    '"""\n'
)


def main() -> int:
    data = yaml.safe_load(SRC.read_text())
    cats = data.get("categories", [])
    if not cats:
        print(f"error: no categories in {SRC}", file=sys.stderr)
        return 1

    # JS — pretty-printed JSON inside a `const` export.
    js_array = json.dumps(cats, indent=4)
    js_body = (
        GENERATED_HEADER
        + "\n"
        + "/** @type {Array<{id:string,label:string,description:string,tools:string[]}>} */\n"
        + f"export const TOOL_CATEGORIES = {js_array};\n"
    )
    JS_OUT.write_text(js_body)
    print(f"wrote {JS_OUT.relative_to(REPO)} ({len(cats)} categories)")

    # Python — a list of dicts with TypedDict typing.
    py_body = dedent(
        """\
        from __future__ import annotations

        from typing import Any

        TOOL_CATEGORIES: list[dict[str, Any]] = {data}


        TOOL_TO_CATEGORY: dict[str, str] = {{
            tool: cat["id"]
            for cat in TOOL_CATEGORIES
            for tool in cat["tools"]
        }}
        """
    ).format(data=repr(cats))
    PY_OUT.write_text(PY_HEADER + "\n" + py_body)
    print(f"wrote {PY_OUT.relative_to(REPO)} ({len(cats)} categories)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
