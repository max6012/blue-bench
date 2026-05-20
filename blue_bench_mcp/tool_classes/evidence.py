"""EvidenceTool — filesystem-backed forensic triage.

Four commands: list_evidence, file_hash, file_metadata, strings_extract.
All operate under cfg.evidence.evidence_dir; path traversal is rejected.
"""
from __future__ import annotations

import datetime
import hashlib
import struct
from pathlib import Path

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_results, validate_path_under

SUPPORTED_HASHES = ("md5", "sha1", "sha256", "sha512")
STRINGS_MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB cap


class EvidenceTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.evidence_dir = Path(cfg.evidence.evidence_dir).resolve()
        self.max_chars = cfg.limits.max_result_chars

    def _resolve(self, filename: str) -> tuple[Path | None, str | None]:
        """Resolve filename under evidence_dir, returning (path, error_str)."""
        try:
            target = validate_path_under(self.evidence_dir / filename, self.evidence_dir)
        except ValueError:
            return None, f"Error: path traversal rejected for '{filename}'"
        if not target.exists() or not target.is_file():
            return None, f"Error: file not found: {filename}"
        return target, None

    async def list_evidence(self) -> str:
        """List evidence files with size, mtime, and detected file type."""
        if not self.evidence_dir.exists():
            return f"Error: evidence_dir does not exist: {self.evidence_dir}"
        rows: list[str] = []
        for p in sorted(self.evidence_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(self.evidence_dir)
            size = p.stat().st_size
            ftype = _detect_file_type(p)
            rows.append(f"{rel}\t{size}\t{int(p.stat().st_mtime)}\t{ftype}")
        if not rows:
            return f"No evidence files in {self.evidence_dir}"
        header = "name\tsize\tmtime\ttype"
        return truncate_results("\n".join([header, *rows]), self.max_chars)

    async def file_hash(self, filename: str, algorithm: str = "sha256") -> str:
        """Compute a cryptographic hash of an evidence file.

        Args:
            filename: Path relative to evidence_dir.
            algorithm: md5, sha1, sha256, sha512, or 'all' for md5+sha1+sha256.
        """
        target, err = self._resolve(filename)
        if err:
            return err
        algos = ("md5", "sha1", "sha256") if algorithm == "all" else (algorithm,)
        for a in algos:
            if a not in SUPPORTED_HASHES:
                return f"Error: unsupported algorithm '{a}'. Supported: {list(SUPPORTED_HASHES)}"
        lines = [f"File: {filename} ({target.stat().st_size:,} bytes)"]
        for algo in algos:
            h = hashlib.new(algo)
            with open(target, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            lines.append(f"  {algo.upper()}: {h.hexdigest()}")
        return truncate_results("\n".join(lines), self.max_chars)

    async def file_metadata(self, filename: str) -> str:
        """Identify file type via magic bytes + stat. First step on unknown files.

        Args:
            filename: Path relative to evidence_dir.
        """
        target, err = self._resolve(filename)
        if err:
            return err
        st = target.stat()
        lines = [
            f"File: {filename}",
            f"  Path: {target}",
            f"  Size: {st.st_size:,} bytes ({st.st_size / 1024:.1f} KB)",
            f"  Modified: {datetime.datetime.fromtimestamp(st.st_mtime).isoformat()}",
        ]
        if hasattr(st, "st_birthtime"):
            lines.append(
                f"  Created:  {datetime.datetime.fromtimestamp(st.st_birthtime).isoformat()}"
            )
        with open(target, "rb") as f:
            magic = f.read(512)
        lines.append(
            f"  Magic (first 16): {' '.join(f'{b:02x}' for b in magic[:16])}"
        )
        file_type, details = _detect_file_type_detailed(magic)
        lines.append(f"  Type: {file_type}")
        for d in details:
            lines.append(f"    {d}")
        return truncate_results("\n".join(lines), self.max_chars)

    async def strings_extract(
        self,
        filename: str,
        min_length: int = 4,
        max_strings: int = 200,
    ) -> str:
        """Extract readable ASCII strings from a binary. Useful for IOC hunting.

        Args:
            filename: Path relative to evidence_dir.
            min_length: Minimum run length to count as a string (default 4).
            max_strings: Max strings returned (default 200).
        """
        target, err = self._resolve(filename)
        if err:
            return err
        read_cap = min(target.stat().st_size, STRINGS_MAX_READ_BYTES)
        with open(target, "rb") as f:
            data = f.read(read_cap)
        strings: list[str] = []
        current: list[str] = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
                if len(strings) >= max_strings:
                    break
        if len(current) >= min_length and len(strings) < max_strings:
            strings.append("".join(current))
        if not strings:
            return f"No readable strings found in {filename} (min length={min_length})."
        body = "\n".join(f"  {s}" for s in strings[:max_strings])
        header = (
            f"Extracted {len(strings)} strings from {filename} "
            f"(read {read_cap:,} of {target.stat().st_size:,} bytes):"
        )
        return truncate_results(f"{header}\n{body}", self.max_chars)


# ---------------- file-type detection helpers ----------------

def _detect_file_type(path: Path) -> str:
    """Quick file-type guess used in list_evidence."""
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
    except OSError:
        return "unreadable"
    t, _ = _detect_file_type_detailed(magic)
    return t


def _detect_file_type_detailed(magic: bytes) -> tuple[str, list[str]]:
    """Return (type, details) for a file given its first 512 bytes."""
    details: list[str] = []
    if magic[:2] == b"MZ":
        ftype = "PE executable (Windows)"
        if len(magic) > 64:
            pe_offset = struct.unpack("<I", magic[60:64])[0]
            if 0 < pe_offset < len(magic) - 8 and magic[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = struct.unpack("<H", magic[pe_offset + 4:pe_offset + 6])[0]
                arch = {0x14c: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)", 0x1c0: "ARM"}.get(
                    machine, f"0x{machine:x}"
                )
                details.append(f"Architecture: {arch}")
                num_sections = struct.unpack("<H", magic[pe_offset + 6:pe_offset + 8])[0]
                details.append(f"Sections: {num_sections}")
        return ftype, details
    if magic[:4] == b"\x7fELF":
        ftype = "ELF binary (Linux/Unix)"
        bits = {1: "32-bit", 2: "64-bit"}.get(magic[4], "unknown") if len(magic) > 4 else "unknown"
        details.append(f"Class: {bits}")
        return ftype, details
    if magic[:3] == b"EVF" or magic[:5] == b"\x45\x56\x46\x09\x0d":
        return "EnCase evidence (E01)", details
    if magic[:6] == b"7z\xbc\xaf'\x1c":
        return "7-Zip archive", details
    if magic[:4] == b"%PDF":
        return "PDF document", details
    if magic[:5] == b"<?php" or b"<?php" in magic[:100]:
        details.append("WARNING: possible webshell — inspect for shell_exec, system, eval, passthru")
        return "PHP script", details
    if magic[:4] == b"\xd0\xcf\x11\xe0":
        return "OLE2 compound document", details
    if magic[:2] == b"\x1f\x8b":
        return "gzip compressed", details
    if magic and all(32 <= b < 127 or b in (9, 10, 13) for b in magic[: min(len(magic), 200)] if b):
        return "text/config file", details
    return "unknown binary", details
