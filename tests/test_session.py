"""The agentic loop, exercised end to end against a scripted provider.

No network: the fake provider replays a fixed sequence of replies, which is
enough to prove the loop runs tools, feeds results back, and stops.
"""

from __future__ import annotations

import pytest

from thot.llm.base import Message, Reply, ToolCall, Usage
from thot.llm.credentials import Config
from thot.session import Session


class ScriptedProvider:
    """Returns a prepared reply per call and records what it was asked."""

    name = "fake"
    model = "fake-1"

    def __init__(self, replies: list[Message]) -> None:
        self._replies = list(replies)
        self.calls: list[dict] = []

    def complete(self, *, system, messages, tools, on_text=None):
        self.calls.append(
            {"system": system, "messages": list(messages), "tools": list(tools)}
        )
        message = self._replies.pop(0)
        if on_text and message.content:
            on_text(message.content)
        return Reply(message=message, usage=Usage(10, 5))


@pytest.fixture
def session(toy_repo, monkeypatch):
    monkeypatch.setattr(
        "thot.session.PromptSession", lambda **kwargs: None
    )
    return Session(root=toy_repo, config=Config(provider="fake", model="fake-1"))


def test_recon_runs_at_startup(session):
    assert session.recon.file_count == 2
    assert session.recon.symbols
    assert any(f.rule == "sink.os.system" for f in session.recon.findings)


def test_briefing_reaches_the_system_prompt(session):
    system = session._system()
    assert "src/app.py" in system or "src.app.main" in system
    assert "sink.os.system" in system


def test_plain_answer_ends_the_turn(session):
    session.provider = ScriptedProvider([Message(role="assistant", content="Bonjour.")])
    session.messages.append(Message(role="user", content="salut"))
    session._turn()
    assert session.messages[-1].content == "Bonjour."


def test_tool_call_is_executed_and_fed_back(session):
    provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="t1", name="find_symbol", arguments={"name": "main"}),
                ),
            ),
            Message(role="assistant", content="Trouvé."),
        ]
    )
    session.provider = provider
    session.messages.append(Message(role="user", content="où est main ?"))
    session._turn()

    tool_messages = [m for m in session.messages if m.role == "tool"]
    assert len(tool_messages) == 1
    assert "src.app.main" in tool_messages[0].content
    assert tool_messages[0].tool_call_id == "t1"
    # The tool result went back to the model on the second call.
    assert len(provider.calls) == 2
    assert session.messages[-1].content == "Trouvé."


def test_graph_tools_answer_without_reading_files(session):
    provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="t1", name="callers", arguments={"symbol": "run_command"}),
                ),
            ),
            Message(role="assistant", content="ok"),
        ]
    )
    session.provider = provider
    session.messages.append(Message(role="user", content="qui appelle run_command ?"))
    session._turn()

    answer = [m for m in session.messages if m.role == "tool"][0].content
    assert "src.app.main" in answer
    assert "saut" in answer


def test_runaway_tool_loop_is_capped(session, monkeypatch):
    monkeypatch.setattr("thot.session.MAX_TOOL_ROUNDS", 3)
    looping = [
        Message(
            role="assistant",
            tool_calls=(ToolCall(id=f"t{i}", name="code_map", arguments={}),),
        )
        for i in range(10)
    ]
    session.provider = ScriptedProvider(looping)
    session.messages.append(Message(role="user", content="boucle"))
    session._turn()
    assert len([m for m in session.messages if m.role == "tool"]) == 3


def test_unknown_tool_does_not_crash_the_session(session):
    session.provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(ToolCall(id="t1", name="nope", arguments={}),),
            ),
            Message(role="assistant", content="fini"),
        ]
    )
    session.messages.append(Message(role="user", content="?"))
    session._turn()
    assert "inconnu" in [m for m in session.messages if m.role == "tool"][0].content
