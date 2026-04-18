"""Instantiation tests for WazuhTool and OpenEDRTool — live backend tests
live in integration smoke. These just verify construction + config plumbing.
"""
from blue_bench_mcp.config import (
    ElasticConfig,
    OpenEDRConfig,
    ServerConfig,
    WazuhConfig,
)
from blue_bench_mcp.tool_classes.openedr import OpenEDRTool
from blue_bench_mcp.tool_classes.wazuh import WazuhTool


def test_wazuh_tool_instantiates():
    cfg = ServerConfig(
        wazuh=WazuhConfig(api_url="https://wazuh.example:55000", user="u", password="p"),
        elastic=ElasticConfig(url="http://es.example:9200"),
    )
    tool = WazuhTool(cfg)
    assert tool.api_url == "https://wazuh.example:55000"
    assert tool.es_url == "http://es.example:9200"
    assert tool.user == "u"
    assert tool._token == ""


def test_wazuh_tool_strips_trailing_slashes():
    cfg = ServerConfig(
        wazuh=WazuhConfig(api_url="https://wazuh.example:55000/"),
        elastic=ElasticConfig(url="http://es.example:9200/"),
    )
    tool = WazuhTool(cfg)
    assert not tool.api_url.endswith("/")
    assert not tool.es_url.endswith("/")


def test_openedr_tool_instantiates():
    cfg = ServerConfig(openedr=OpenEDRConfig(url="http://edr.example:9443", user="u", password="p"))
    tool = OpenEDRTool(cfg)
    assert tool.url == "http://edr.example:9443"
    assert tool._auth() == ("u", "p")


def test_openedr_tool_no_auth_when_blank():
    cfg = ServerConfig(openedr=OpenEDRConfig(url="http://edr.example:9443"))
    tool = OpenEDRTool(cfg)
    assert tool._auth() is None
