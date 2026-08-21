"""The account path: command construction and stream parsing.

The real CLI is never launched here — these tests check what Thot asks for and
how it reads the answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thot.llm.claude_cli import ALLOWED_TOOLS, ClaudeCli, Events


@pytest.fixture
def cli(tmp_path):
    return ClaudeCli(root=tmp_path, model="")


def command_of(cli, prompt="salut", brief="contexte"):
    return cli._command(prompt, brief)


def test_first_turn_fixes_the_session_id(cli):
    command = command_of(cli)
    assert "--session-id" in command
    assert cli.session_id in command
    assert "--resume" not in command


def test_next_turn_resumes_the_same_thread(cli):
    cli._started = True
    command = command_of(cli)
    assert "--resume" in command
    assert command[command.index("--resume") + 1] == cli.session_id
    assert "--session-id" not in command


def test_thot_tools_are_allowed_by_name(cli):
    command = command_of(cli)
    allowed = command[command.index("--allowed-tools") + 1]
    for name in ALLOWED_TOOLS:
        assert name in allowed


def test_mcp_config_points_back_at_thot(cli, tmp_path):
    command = command_of(cli)
    config = json.loads(command[command.index("--mcp-config") + 1])
    server = config["mcpServers"]["thot"]
    assert server["args"] == ["-m", "thot.mcp_server"]
    assert server["env"]["THOT_ROOT"] == str(tmp_path)


def test_briefing_is_appended_not_replacing_the_prompt(cli):
    command = command_of(cli, brief="carte du dépôt")
    assert command[command.index("--append-system-prompt") + 1] == "carte du dépôt"
    assert command[-1] == "salut"


def test_text_deltas_are_streamed_and_collected(cli):
    chunks = []
    events = Events(on_text=chunks.append)
    answer: list[str] = []
    for text in ("Bon", "jour"):
        cli._consume(
            {
                "type": "stream_event",
                "event": {
                    "type": "content_block_delta",
                    "delta": {"type": "text_delta", "text": text},
                },
            },
            events, answer, set(),
        )
    assert "".join(answer) == "Bonjour"
    assert chunks == ["Bon", "jour"]


def test_tool_use_is_reported_once(cli):
    seen: list[tuple] = []
    events = Events(on_tool=lambda name, args: seen.append((name, args)))
    event = {
        "type": "assistant",
        "message": {
            "content": [
                {"type": "tool_use", "id": "t1",
                 "name": "mcp__thot__callers", "input": {"symbol": "main"}}
            ]
        },
    }
    already: set[str] = set()
    cli._consume(event, events, [], already)
    cli._consume(event, events, [], already)  # duplicate frame
    assert seen == [("mcp__thot__callers", {"symbol": "main"})]


def test_error_result_surfaces(cli):
    errors = []
    events = Events(on_error=errors.append)
    cli._consume(
        {"type": "result", "is_error": True, "result": "boom"}, events, [], set()
    )
    assert errors == ["boom"]


# -- the user's own MCP servers ---------------------------------------------
# Thot passed --strict-mcp-config, which silently disabled every server the
# user had configured. Inside Thot they lost their whole toolbelt and had no
# way to know why.


def test_configured_servers_are_discovered(tmp_path, monkeypatch):
    from thot.llm import claude_cli

    config = tmp_path / "claude.json"
    config.write_text(json.dumps({
        "mcpServers": {"semantic-scholar": {}, "sympy": {}},
        "projects": {str(tmp_path): {"mcpServers": {"ruflo": {}}}},
    }))
    monkeypatch.setattr(claude_cli, "CLAUDE_CONFIG", config)
    found = claude_cli.user_mcp_servers(tmp_path)
    assert set(found) == {"semantic-scholar", "sympy", "ruflo"}


def test_a_repo_local_mcp_file_is_read(tmp_path, monkeypatch):
    from thot.llm import claude_cli

    monkeypatch.setattr(claude_cli, "CLAUDE_CONFIG", tmp_path / "absent.json")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"local": {}}}))
    assert claude_cli.user_mcp_servers(tmp_path) == ("local",)


def test_thots_own_server_is_not_double_counted(tmp_path, monkeypatch):
    from thot.llm import claude_cli

    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"mcpServers": {"thot": {}, "other": {}}}))
    monkeypatch.setattr(claude_cli, "CLAUDE_CONFIG", config)
    assert claude_cli.user_mcp_servers(tmp_path) == ("other",)


def test_a_broken_config_is_not_fatal(tmp_path, monkeypatch):
    from thot.llm import claude_cli

    config = tmp_path / "claude.json"
    config.write_text("{ pas du json")
    monkeypatch.setattr(claude_cli, "CLAUDE_CONFIG", config)
    assert claude_cli.user_mcp_servers(tmp_path) == ()


def test_user_servers_are_allowed_alongside_thots(tmp_path, monkeypatch):
    from thot.llm import claude_cli

    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"mcpServers": {"sympy": {}}}))
    monkeypatch.setattr(claude_cli, "CLAUDE_CONFIG", config)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")

    command = claude_cli.ClaudeCli(root=tmp_path)._command("salut", "brief")
    allowed = command[command.index("--allowed-tools") + 1]
    assert "mcp__thot__audit" in allowed
    assert "mcp__sympy" in allowed


def test_the_user_toolbelt_is_not_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    from thot.llm.claude_cli import ClaudeCli

    assert "--strict-mcp-config" not in ClaudeCli(root=tmp_path)._command("x", "")


def test_isolation_is_available_when_asked_for(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    from thot.llm.claude_cli import ClaudeCli

    command = ClaudeCli(root=tmp_path, isolated=True)._command("x", "")
    assert "--strict-mcp-config" in command
