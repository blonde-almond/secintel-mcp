"""Exercise the tools through the MCP server object, as a client would."""

from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from secintel_mcp.server import mcp

from .conftest import LOG4SHELL

EXPECTED_TOOLS = {
    "triage_cve",
    "lookup_cve",
    "epss_score",
    "check_kev",
    "query_package_vulns",
    "extract_iocs",
    "defang",
}


async def test_all_tools_are_registered_with_descriptions():
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == EXPECTED_TOOLS
    for tool in tools.values():
        assert tool.description and len(tool.description) > 40
    assert tools["query_package_vulns"].input_schema["required"] == ["ecosystem", "package"]


async def test_triage_tool_call(client):
    result = await mcp.call_tool("triage_cve", {"cve_id": LOG4SHELL})
    assert result.is_error is not True
    assert result.structured_content["priority"] == "P1"


async def test_local_tools_need_no_network(upstream, client):
    result = await mcp.call_tool("extract_iocs", {"text": "c2 at 8.8.8.8"})
    assert result.structured_content["ipv4"] == ["8.8.8.8"]
    result = await mcp.call_tool("defang", {"text": "c2 at 8.8.8.8"})
    assert result.structured_content == {"result": "c2 at 8[.]8[.]8[.]8"}
    assert upstream.requests == []


async def test_invalid_input_is_reported_with_a_readable_message(client, upstream):
    with pytest.raises(ToolError, match="Not a valid CVE ID"):
        await mcp.call_tool("lookup_cve", {"cve_id": "nope"})
    assert upstream.requests == []


async def test_upstream_outage_is_reported_with_a_readable_message(client, upstream):
    upstream.fail_hosts["api.first.org"] = 429
    with pytest.raises(ToolError, match="rate limiting"):
        await mcp.call_tool("epss_score", {"cve_id": LOG4SHELL})
