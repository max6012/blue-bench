"""Suricata replay wrapper.

Mirrors ``zeek_replay.py``: subprocess invocation is separate from JSON
parsing so tests can feed fixture eve.json content without Suricata
installed.

Runs::

    suricata -r <pcap> --runmode=single -k none -l <out>

Optional ruleset path via ``ruleset_dir`` argument or the
``BLUE_BENCH_SURICATA_RULES`` env var. Default is to run without
rules — Suricata still emits ``flow`` / ``dns`` / ``http`` / ``tls`` /
``fileinfo`` events without any alert rules loaded.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


class SuricataError(RuntimeError):
    """Raised when ``suricata`` is missing or its replay fails."""


def run_suricata(
    pcap: Path,
    out_dir: Path,
    *,
    suricata_binary: str = "suricata",
    ruleset_dir: Path | None = None,
) -> Path:
    """Run Suricata against a PCAP, return path to the produced ``eve.json``.

    Args:
        pcap: absolute path to the PCAP file (must exist).
        out_dir: directory Suricata writes ``eve.json`` and rotated logs into.
        suricata_binary: override path to the ``suricata`` binary.
        ruleset_dir: optional path to a ruleset directory; if None, falls
            back to ``BLUE_BENCH_SURICATA_RULES`` env var; if still unset,
            runs alert-less.

    Raises:
        SuricataError: binary missing or replay non-zero exit.
    """
    if not pcap.is_file():
        raise SuricataError(f"pcap not found: {pcap}")
    out_dir.mkdir(parents=True, exist_ok=True)
    rules = ruleset_dir or (
        Path(os.environ["BLUE_BENCH_SURICATA_RULES"])
        if "BLUE_BENCH_SURICATA_RULES" in os.environ
        else None
    )
    cmd = [
        suricata_binary,
        "-r",
        str(pcap),
        "--runmode=single",
        "-k",
        "none",
        "-l",
        str(out_dir),
    ]
    if rules is not None:
        cmd.extend(["-S", str(rules)])
    log.info("suricata %s", " ".join(cmd))
    try:
        result = subprocess.run(  # noqa: S603 — args validated.
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SuricataError(
            f"`{suricata_binary}` not found on PATH; install Suricata to run this step"
        ) from exc
    if result.returncode != 0:
        raise SuricataError(
            f"suricata failed (rc={result.returncode}) on {pcap.name}:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    eve = out_dir / "eve.json"
    if not eve.is_file():
        raise SuricataError(f"suricata produced no eve.json under {out_dir}")
    return eve


# --- pure parsers ------------------------------------------------------------


def parse_eve(path: Path) -> list[dict]:
    """Parse a Suricata ``eve.json`` file (one JSON object per line)."""
    return parse_eve_text(path.read_text(encoding="utf-8"))


def parse_eve_text(text: str) -> list[dict]:
    """Parse ``eve.json``-shaped text. Stable, no subprocess.

    Lines that fail to parse are logged and skipped — Suricata sometimes
    emits partial lines on truncation, and we prefer skipping to crashing.
    """
    records: list[dict] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("eve.json parse error on line %d: %s", i, exc)
            continue
        obj["_log"] = "eve"
        records.append(obj)
    return records
