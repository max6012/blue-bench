"""Zeek replay wrapper.

Two layers, deliberately separated so tests can exercise the parser without
needing Zeek installed:

    run_zeek(pcap, out_dir)            -- subprocess invocation
    parse_zeek_log(log_path)           -- pure TSV parser
    parse_zeek_log_text(text, name)    -- pure TSV parser on in-memory text

Zeek emits one TSV per protocol with a ``#fields`` header line. We collect
``conn dns http ssl files x509`` by convention; missing logs are skipped
silently (some PCAPs have no x509 etc.).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)


ZEEK_LOGS = ("conn", "dns", "http", "ssl", "files", "x509")


class ZeekError(RuntimeError):
    """Raised when ``zeek`` is missing or its replay fails."""


def run_zeek(pcap: Path, out_dir: Path, *, zeek_binary: str = "zeek") -> dict[str, Path]:
    """Run ``zeek -r <pcap>`` and return a mapping of log-name -> file path.

    Zeek writes logs into the current working directory of the invocation;
    we set ``cwd=out_dir`` so they land where we want without post-move.

    Args:
        pcap: absolute path to the PCAP file (must exist).
        out_dir: directory Zeek writes logs into. Created if absent.
        zeek_binary: override path to the ``zeek`` binary.

    Raises:
        ZeekError: binary missing or replay non-zero exit.
    """
    if not pcap.is_file():
        raise ZeekError(f"pcap not found: {pcap}")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [zeek_binary, "-r", str(pcap)]
    log.info("zeek %s (cwd=%s)", " ".join(cmd), out_dir)
    try:
        result = subprocess.run(  # noqa: S603 — args validated.
            cmd,
            check=False,
            cwd=out_dir,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ZeekError(
            f"`{zeek_binary}` not found on PATH; install Zeek to run this step"
        ) from exc
    if result.returncode != 0:
        raise ZeekError(
            f"zeek failed (rc={result.returncode}) on {pcap.name}:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    found: dict[str, Path] = {}
    for name in ZEEK_LOGS:
        candidate = out_dir / f"{name}.log"
        if candidate.is_file():
            found[name] = candidate
    return found


# --- pure parsers (no subprocess, test-friendly) ----------------------------


def parse_zeek_log(path: Path) -> list[dict[str, str]]:
    """Parse a Zeek TSV log file from disk."""
    return parse_zeek_log_text(path.read_text(encoding="utf-8"), path.stem)


def parse_zeek_log_text(text: str, log_name: str) -> list[dict[str, str]]:
    """Parse Zeek TSV text. Stable, no subprocess.

    Returns a list of dicts keyed by the ``#fields`` line. Each record has
    ``_log`` injected so downstream code can tell conn from dns from http
    without carrying source-path metadata.
    """
    fields: list[str] | None = None
    separator = "\t"
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("#separator"):
            # e.g. "#separator \x09" — interpret if present.
            spec = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
            if spec.startswith("\\x"):
                separator = chr(int(spec[2:], 16))
            else:
                separator = spec
            continue
        if line.startswith("#fields"):
            fields = line.split(separator)[1:]
            continue
        if line.startswith("#"):
            continue
        if fields is None:
            continue
        values = line.split(separator)
        record: dict[str, str] = {"_log": log_name}
        for i, name in enumerate(fields):
            record[name] = values[i] if i < len(values) else "-"
        records.append(record)
    return records


def parse_all(zeek_out_dir: Path, log_names: Iterable[str] = ZEEK_LOGS) -> list[dict[str, str]]:
    """Parse every requested Zeek log under ``zeek_out_dir``, in field-coverage order.

    Missing logs are skipped silently. Records are returned in the order
    (conn first, then dns, http, ssl, files, x509) so the caller's downstream
    event-id assignment is stable across runs.
    """
    out: list[dict[str, str]] = []
    for name in log_names:
        path = zeek_out_dir / f"{name}.log"
        if path.is_file():
            out.extend(parse_zeek_log(path))
    return out
