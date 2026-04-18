"""SigmaTool unit tests — no backend required."""
import pytest

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.sigma import SigmaTool


@pytest.fixture
def tool():
    return SigmaTool(ServerConfig())


VALID_RULE = """
title: Cobalt Strike HTTPS beacon to suspect C2
status: experimental
level: high
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    dst_ip: 203.0.113.45
    dst_port: 443
  condition: selection
tags:
  - attack.command_and_control
  - attack.t1071.001
"""


async def test_valid_rule(tool):
    out = await tool.validate_rule(VALID_RULE)
    assert out.startswith("VALID"), out


async def test_invalid_yaml(tool):
    out = await tool.validate_rule("title: [broken\n  - not closed")
    assert out.startswith("INVALID")
    assert "parse error" in out


async def test_missing_required_key(tool):
    out = await tool.validate_rule("title: x\nlogsource: {product: zeek}\n")
    assert out.startswith("INVALID")
    assert "detection" in out


async def test_literal_and_or_in_selection_flagged(tool):
    # G4 Phase 1 regression — fabricated AND/OR inside selections.
    rule = """
title: bad
logsource: {product: zeek}
detection:
  selection:
    AND:
      - dst_ip: 1.2.3.4
      - dst_port: 443
  condition: selection
"""
    out = await tool.validate_rule(rule)
    assert out.startswith("INVALID")
    assert "AND" in out


async def test_condition_missing_flagged(tool):
    rule = """
title: x
logsource: {product: zeek}
detection:
  selection:
    dst_ip: 1.2.3.4
"""
    out = await tool.validate_rule(rule)
    assert out.startswith("INVALID")
    assert "condition" in out


async def test_logsource_hints_required(tool):
    rule = """
title: x
logsource:
  foo: bar
detection:
  selection: {dst_ip: 1.2.3.4}
  condition: selection
"""
    out = await tool.validate_rule(rule)
    assert out.startswith("INVALID")
    assert "category" in out or "product" in out


async def test_warnings_for_missing_level_tags(tool):
    rule = """
title: x
logsource: {product: zeek}
detection:
  selection: {dst_ip: 1.2.3.4}
  condition: selection
"""
    out = await tool.validate_rule(rule)
    assert out.startswith("VALID")
    assert "level" in out
    assert "tags" in out
