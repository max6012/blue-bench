"""Blue-Bench operator CLI.

Commands:
    blue-bench qualify  --profile <name> [--tag T] [--limit N] [--config PATH]
    blue-bench aggregate <run-dir>
    blue-bench diff <run-a> <run-b>
    blue-bench server [--config PATH]   # shortcut for `python -m blue_bench_mcp.server`

Keep this file thin — logic lives in blue_bench_eval.qualify, aggregate; this
module just shells commands through typer for a consistent operator surface.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer

from blue_bench_eval.aggregate import aggregate, diff_runs, render_bluf
from blue_bench_eval.qualify import run_corpus

REPO = Path(__file__).parent.parent
DEFAULT_RUBRIC = REPO / "blue_bench_eval" / "rubrics" / "phase2.yaml"
DEFAULT_PROMPTS = REPO / "blue_bench_eval" / "prompts"
DEFAULT_CONFIG = REPO / "config.yaml"

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Blue-Bench operator CLI.")


@app.command()
def qualify(
    profile: str = typer.Option(..., "--profile", "-p", help="Profile YAML stem, e.g. gemma4-e4b"),
    tag: str = typer.Option("", "--tag", "-t", help="Filter prompts by tag or category"),
    limit: int = typer.Option(None, "--limit", "-n", help="Stop after N prompts"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="MCP server config.yaml"),
) -> None:
    """Run the Phase 2 prompt corpus under PROFILE and write traces."""
    run_dir = asyncio.run(
        run_corpus(profile, tag=tag, limit=limit, config_path=config)
    )
    typer.echo(f"\nRun dir: {run_dir}")


@app.command("aggregate")
def aggregate_cmd(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    rubric: Path = typer.Option(DEFAULT_RUBRIC, "--rubric", "-r", help="Rubric YAML"),
    prompts: Path = typer.Option(DEFAULT_PROMPTS, "--prompts", help="Prompts directory"),
    write_bluf: bool = typer.Option(True, "--write/--no-write", help="Write BLUF.md to run dir"),
) -> None:
    """Aggregate a scored run into BLUF.md (expects scored/ + prompts/ inside RUN_DIR)."""
    result = aggregate(run_dir, rubric, prompts_dir=prompts)
    md = render_bluf(result)
    if write_bluf:
        bluf_path = run_dir / "BLUF.md"
        bluf_path.write_text(md)
        typer.echo(f"BLUF written: {bluf_path}")
    else:
        typer.echo(md)
    # Summary line to stderr so --no-write stdout stays clean.
    line = (
        f"overall={result.overall_pct:.1f}% "
        f"tool={result.dim_pct.get('tool_usage', 0):.1f}% "
        f"find={result.dim_pct.get('findings', 0):.1f}% "
        f"pass={result.passes_overall and result.passes_tool_usage and result.passes_findings}"
    )
    typer.echo(line, err=True)


@app.command()
def diff(
    run_a: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    run_b: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    rubric: Path = typer.Option(DEFAULT_RUBRIC, "--rubric", "-r", help="Rubric YAML"),
    prompts: Path = typer.Option(DEFAULT_PROMPTS, "--prompts", help="Prompts directory"),
    out: Path = typer.Option(None, "--out", "-o", help="Write diff to file instead of stdout"),
) -> None:
    """Render the per-dimension + per-prompt delta between two aggregated runs."""
    a = aggregate(run_a, rubric, prompts_dir=prompts)
    b = aggregate(run_b, rubric, prompts_dir=prompts)
    md = diff_runs(a, b)
    if out:
        out.write_text(md)
        typer.echo(f"Diff written: {out}")
    else:
        typer.echo(md)


@app.command()
def server(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="MCP server config.yaml"),
    transport: str = typer.Option("stdio", "--transport", help="stdio|sse (sse not yet implemented)"),
) -> None:
    """Start the Blue-Bench MCP server. Shortcut for `python -m blue_bench_mcp.server`."""
    if transport != "stdio":
        typer.echo(f"Error: transport {transport!r} not yet implemented — see t-sse-transport.", err=True)
        raise typer.Exit(code=2)
    # Dispatch by importing and calling main() — preserves signal handling + args.
    import argparse
    from blue_bench_mcp.server import main as server_main
    sys.argv = ["blue-bench-server", "--config", str(config)]
    server_main()


if __name__ == "__main__":
    app()
