from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import EvidenceConfig, ServerConfig
from blue_bench_mcp.server import register_all


async def test_evidence_registered(tmp_path):
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    cfg = ServerConfig(evidence=EvidenceConfig(evidence_dir=str(tmp_path)))
    server = FastMCP("test")
    registered = register_all(server, cfg)
    assert "evidence" in registered

    tools = await server.list_tools()
    tool_names = {t.name for t in tools}
    assert "list_evidence" in tool_names
    assert "file_hash" in tool_names
    assert "file_metadata" in tool_names
    assert "strings_extract" in tool_names
