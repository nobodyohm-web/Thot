"""The MCP server Thot exposes to the official CLI."""

from __future__ import annotations

import pytest

from thot.mcp_server import EXPOSED, PROTOCOL_VERSION, Server, config_payload


@pytest.fixture
def server(toy_repo):
    return Server(toy_repo)


def test_initialize_announces_tool_support(server):
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    result = reply["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert "tools" in result["capabilities"]
    assert result["serverInfo"]["name"] == "thot"


def test_initialized_notification_gets_no_reply(server):
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_only_deterministic_tools_are_exposed(server):
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert names == set(EXPOSED)
    assert "write_file" not in names
    assert "run_command" not in names


def test_tools_have_a_schema(server):
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert all("inputSchema" in tool for tool in tools)


def test_call_answers_from_the_map(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "callers", "arguments": {"symbol": "run_command"}},
    })
    text = reply["result"]["content"][0]["text"]
    assert "src.app.main" in text


def test_unexposed_tool_is_refused(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "x", "content": "y"}},
    })
    assert reply["error"]["code"] == -32602


def test_unknown_method_returns_an_error(server):
    reply = server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})
    assert reply["error"]["code"] == -32601


def test_config_payload_is_launchable(tmp_path):
    payload = config_payload(tmp_path)
    server = payload["mcpServers"]["thot"]
    assert server["args"] == ["-m", "thot.mcp_server"]
    assert server["env"]["THOT_ROOT"] == str(tmp_path)
