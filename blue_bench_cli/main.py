"""Blue-Bench operator CLI.

Commands:
    blue-bench qualify  --profile <name> [--tag T] [--limit N] [--config PATH]
    blue-bench aggregate <run-dir>
    blue-bench diff <run-a> <run-b>
    blue-bench analyst  --profile <name> [--tools cat,cat] [--prompt "..."] ...
    blue-bench server [--config PATH]   # shortcut for `python -m blue_bench_mcp.server`

Keep this file thin — logic lives in blue_bench_eval.qualify, aggregate, and
blue_bench_cli.analyst; this module just shells commands through typer for
a consistent operator surface.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer

from blue_bench_cli.analyst import cli as analyst_cli
from blue_bench_eval.aggregate import aggregate, diff_runs, render_bluf
from blue_bench_eval.qualify import run_corpus

REPO = Path(__file__).parent.parent
DEFAULT_RUBRIC = REPO / "blue_bench_eval" / "rubrics" / "phase2.yaml"
DEFAULT_PROMPTS = REPO / "blue_bench_eval" / "prompts"
DEFAULT_CONFIG = REPO / "config.yaml"

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Blue-Bench operator CLI.")


@app.command()
def qualify(
    profile: str = typer.Option(..., "--profile", "-p", help="Profile stem (local), OR with --cloud the Ollama Cloud model id, e.g. gpt-oss:120b"),
    phase: str = typer.Option("2", "--phase", help="Eval phase: 1 or 2 (default: 2)"),
    tag: str = typer.Option("", "--tag", "-t", help="Filter prompts by tag or category"),
    limit: int = typer.Option(None, "--limit", "-n", help="Stop after N prompts"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="MCP server config.yaml"),
    cloud: bool = typer.Option(False, "--cloud", help="Run --profile as an Ollama Cloud model id via a generic cloud profile (needs OLLAMA_API_KEY in .env)"),
) -> None:
    """Run the prompt corpus under PROFILE and write traces.

    Local (default): PROFILE is a profiles/<stem>.yaml. With --cloud, PROFILE is
    an Ollama Cloud model id (see `blue-bench models --cloud`) run via a generic
    cloud profile — no per-model file needed.
    """
    override = None
    if cloud:
        import os
        os.environ.setdefault("OLLAMA_HOST", "https://ollama.com")
        if not os.environ.get("OLLAMA_API_KEY"):
            typer.echo("ERROR: --cloud needs OLLAMA_API_KEY (put it in .env).", err=True)
            raise typer.Exit(1)
        from blue_bench_client.cloud_models import generic_cloud_profile
        override = generic_cloud_profile(profile)
        profile = override.name  # for the run-dir label
    run_dir = asyncio.run(
        run_corpus(profile, tag=tag, limit=limit, config_path=config, phase=phase,
                   profile_override=override)
    )
    typer.echo(f"\nRun dir: {run_dir}")


@app.command()
def models(
    cloud: bool = typer.Option(True, "--cloud/--local", help="List Ollama Cloud catalogue (default) or local profiles"),
    since_months: float = typer.Option(6.0, "--since-months", help="Cloud: only models modified within N months (0 = all)"),
    size: str = typer.Option(None, "--size", help="Cloud size band: small (<=100GB) | mid (100-500GB) | large (>500GB)"),
) -> None:
    """List the models you can run. Cloud defaults to a recency+size shortlist
    (the full catalogue is too long); pass to --profile with --cloud."""
    if not cloud:
        for p in sorted((REPO / "blue_bench_mcp" / "profiles").glob("*.yaml")):
            typer.echo(f"  {p.stem}")
        return
    from blue_bench_client.cloud_models import list_cloud_models
    rows = list_cloud_models(since_months=since_months or None, size=size)
    typer.echo(f"Ollama Cloud — {len(rows)} models"
               + (f", last {since_months:g}mo" if since_months else "")
               + (f", size={size}" if size else "") + " (newest first):")
    for m in rows:
        sz = f"{m.size_gb:6.0f} GB" if m.size_gb else "  hosted "
        typer.echo(f"  {m.model:24s} {m.modified.date()}  {sz}  ({m.age_months:.1f}mo)")
    typer.echo("\nRun one:  blue-bench qualify --cloud --profile <model> --phase 3")


@app.command("aggregate")
def aggregate_cmd(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    phase: str = typer.Option("2", "--phase", help="Eval phase: 1 or 2 (selects default rubric)"),
    rubric: Path = typer.Option(None, "--rubric", "-r", help="Rubric YAML (overrides --phase default)"),
    prompts: Path = typer.Option(DEFAULT_PROMPTS, "--prompts", help="Prompts directory"),
    write_bluf: bool = typer.Option(True, "--write/--no-write", help="Write BLUF.md to run dir"),
) -> None:
    """Aggregate a scored run into BLUF.md (expects scored/ + prompts/ inside RUN_DIR)."""
    if rubric is None:
        rubric = REPO / "blue_bench_eval" / "rubrics" / f"phase{phase}.yaml"
    result = aggregate(run_dir, rubric, prompts_dir=prompts)
    md = render_bluf(result)
    if write_bluf:
        bluf_path = run_dir / "BLUF.md"
        bluf_path.write_text(md)
        typer.echo(f"BLUF written: {bluf_path}")
    else:
        typer.echo(md)
    # Summary line to stderr so --no-write stdout stays clean.
    all_pass = result.passes_overall and all(result.passes_key_dims.values())
    key_dim_parts = " ".join(
        f"{kd}={result.dim_pct.get(kd, 0):.1f}%" for kd in result.key_dimensions
    )
    line = f"overall={result.overall_pct:.1f}% {key_dim_parts} pass={all_pass}"
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


app.command("analyst", help="Interactive analyst console — same controls as the browser frontend.")(analyst_cli)


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
