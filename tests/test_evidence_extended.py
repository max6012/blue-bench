"""Tests for the extended EvidenceTool (file_metadata + strings_extract)."""
import pytest

from blue_bench_mcp.config import EvidenceConfig, ServerConfig
from blue_bench_mcp.tool_classes.evidence import EvidenceTool


@pytest.fixture
def tool(tmp_path):
    # Seed a mix of files: text, PE-like, PHP-like, ELF-like.
    (tmp_path / "note.txt").write_bytes(b"Analyst note: suspect 203.0.113.45 is a beacon C2.\n")

    pe_bytes = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        + b"\x00" * 44
        + (0x80).to_bytes(4, "little")  # PE offset at 0x3c
        + b"\x00" * 64
    )
    # Place 'PE\0\0' + machine x86-64 + 3 sections at pe_offset 0x80.
    pe_header = b"PE\x00\x00" + (0x8664).to_bytes(2, "little") + (3).to_bytes(2, "little") + b"\x00" * 16
    pe_data = pe_bytes + pe_header + b"Cobalt Strike beacon_init\x00http://203.0.113.45/\x00"
    (tmp_path / "sample.exe").write_bytes(pe_data)

    (tmp_path / "shell.php").write_bytes(
        b"<?php\nif(isset($_GET['c'])){shell_exec($_GET['c']);}\n"
        b"# callback 203.0.113.45\n"
    )
    (tmp_path / "elf.bin").write_bytes(b"\x7fELF\x02" + b"\x00" * 64)

    cfg = ServerConfig(evidence=EvidenceConfig(evidence_dir=str(tmp_path)))
    return EvidenceTool(cfg)


async def test_list_evidence_reports_types(tool):
    out = await tool.list_evidence()
    assert "PE executable" in out
    assert "PHP script" in out
    assert "ELF" in out


async def test_file_metadata_pe(tool):
    out = await tool.file_metadata("sample.exe")
    assert "PE executable" in out
    assert "Architecture" in out
    assert "x86-64" in out or "x86_64" in out


async def test_file_metadata_php_warns_webshell(tool):
    out = await tool.file_metadata("shell.php")
    assert "PHP" in out
    assert "webshell" in out.lower()


async def test_file_metadata_missing(tool):
    out = await tool.file_metadata("does-not-exist.bin")
    assert out.startswith("Error:")


async def test_file_metadata_traversal(tool):
    out = await tool.file_metadata("../secret.key")
    assert out.startswith("Error:")


async def test_strings_extract_finds_ioc(tool):
    out = await tool.strings_extract("sample.exe", min_length=5)
    assert "Cobalt Strike" in out
    assert "203.0.113.45" in out


async def test_strings_extract_min_length_honored(tool):
    out = await tool.strings_extract("note.txt", min_length=10, max_strings=100)
    # Every line should be >= 10 chars.
    body_lines = [l.strip() for l in out.splitlines() if l.startswith("  ")]
    for line in body_lines:
        assert len(line) >= 10, f"short string leaked: {line!r}"


async def test_strings_extract_max_strings_cap(tool):
    out = await tool.strings_extract("shell.php", min_length=3, max_strings=2)
    body_lines = [l for l in out.splitlines() if l.startswith("  ")]
    assert len(body_lines) <= 2


async def test_file_hash_all_algorithms(tool):
    out = await tool.file_hash("note.txt", algorithm="all")
    assert "MD5" in out
    assert "SHA1" in out
    assert "SHA256" in out
