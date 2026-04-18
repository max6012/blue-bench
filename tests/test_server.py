from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.server import create_server, register_all


def test_create_server_default_cfg():
    s = create_server()
    assert s is not None
    assert s.name == "blue-bench"


def test_register_all_returns_registered_modules():
    # Auto-discovery picks up every module under blue_bench_mcp.tools that
    # exposes a register() function. As new tools are added, this list grows.
    from mcp.server.fastmcp import FastMCP
    s = FastMCP("test")
    registered = register_all(s, ServerConfig())
    assert "evidence" in registered
