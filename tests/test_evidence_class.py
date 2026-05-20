import pytest

from blue_bench_mcp.config import EvidenceConfig, ServerConfig
from blue_bench_mcp.tool_classes.evidence import EvidenceTool


@pytest.fixture
def evidence_dir(tmp_path):
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    (tmp_path / "malware.bin").write_bytes(b"\x00\x01" * 32)
    return tmp_path


@pytest.fixture
def tool(evidence_dir):
    cfg = ServerConfig(evidence=EvidenceConfig(evidence_dir=str(evidence_dir)))
    return EvidenceTool(cfg)


async def test_list_evidence(tool):
    out = await tool.list_evidence()
    assert "hello.txt" in out
    assert "malware.bin" in out
    assert "name\tsize\tmtime" in out


async def test_list_evidence_missing_dir(tmp_path):
    cfg = ServerConfig(evidence=EvidenceConfig(evidence_dir=str(tmp_path / "nope")))
    tool = EvidenceTool(cfg)
    out = await tool.list_evidence()
    assert out.startswith("Error:")


async def test_file_hash_happy(tool):
    out = await tool.file_hash("hello.txt")
    # sha256("hello world\n") = a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447
    assert "SHA256" in out
    assert "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447" in out


async def test_file_hash_wrong_algo(tool):
    out = await tool.file_hash("hello.txt", algorithm="crc32")
    assert out.startswith("Error:")


async def test_file_hash_nonexistent(tool):
    out = await tool.file_hash("does_not_exist.txt")
    assert out.startswith("Error:")


async def test_file_hash_traversal(tool):
    out = await tool.file_hash("../../etc/passwd")
    assert out.startswith("Error:")
