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
