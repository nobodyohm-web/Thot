"""What the model is allowed to do, as a posture rather than a list.

The posture that earns the module is `lecture`: reviewing a repository you
do not own means reading code you have every reason to distrust, and the
model editing it is rarely what you wanted.
"""

from __future__ import annotations

import pytest

from thot import agent_tools, toolsets


def test_reading_never_includes_writing_or_running():
    reading = set(toolsets.resolve("lecture"))

    assert "read_file" in reading
    assert "code_map" in reading
    for forbidden in ("write_file", "edit_file", "run_command"):
        assert forbidden not in reading


def test_the_map_posture_opens_no_file_at_all():
    only_map = set(toolsets.resolve("carte"))

    assert "read_file" not in only_map
    assert "list_dir" not in only_map
    assert {"code_map", "find_symbol", "callers", "audit"} <= only_map


def test_the_default_posture_is_everything_thot_has():
    assert set(toolsets.resolve("complet")) == {s.name for s in agent_tools.SPECS}


def test_an_unknown_posture_raises_rather_than_handing_over_everything():
    with pytest.raises(KeyError, match="complet"):
        toolsets.resolve("permissif")


def test_selecting_preserves_the_declared_order():
    selected = toolsets.select(agent_tools.SPECS, "lecture")
    names = [spec.name for spec in selected]

    assert names == [s.name for s in agent_tools.SPECS if s.name in names]
    assert "write_file" not in names


def test_the_posture_holds_at_the_dispatch_not_only_at_the_menu(toy_repo,
                                                                monkeypatch):
    """A model can ask for a tool it was never offered."""
    from thot.llm.base import Message, Reply, ToolCall, Usage
    from thot.llm.credentials import Config
    from thot.session import Session

    monkeypatch.setattr("thot.session.PromptSession", lambda **kwargs: None)

    class Insistent:
        name, model = "fake", "fake-1"

        def __init__(self):
            self.replies = [
                Message(role="assistant", tool_calls=(
                    ToolCall(id="t1", name="write_file",
                             arguments={"path": "x.py", "content": "x = 1"}),)),
                Message(role="assistant", content="bon."),
            ]

        def complete(self, *, system, messages, tools, on_text=None):
            assert "write_file" not in {t.name for t in tools}
            return Reply(message=self.replies.pop(0), usage=Usage(1, 1))

    session = Session(root=toy_repo, config=Config(provider="fake", model="f"),
                      toolset="lecture")
    session.provider = Insistent()
    session.messages.append(Message(role="user", content="écris un fichier"))
    session._turn()

    answer = [m for m in session.messages if m.role == "tool"][0].content
    assert "désactivé" in answer
    assert not (toy_repo / "x.py").exists(), "rien ne doit avoir été écrit"


def test_an_unknown_tool_is_still_unknown_not_disabled(toy_repo, monkeypatch):
    """Two different mistakes must keep two different messages."""
    from thot.llm.base import Message, Reply, ToolCall, Usage
    from thot.llm.credentials import Config
    from thot.session import Session

    monkeypatch.setattr("thot.session.PromptSession", lambda **kwargs: None)

    class Wrong:
        name, model = "fake", "fake-1"

        def __init__(self):
            self.replies = [
                Message(role="assistant", tool_calls=(
                    ToolCall(id="t1", name="teleporte", arguments={}),)),
                Message(role="assistant", content="bon."),
            ]

        def complete(self, **kwargs):
            return Reply(message=self.replies.pop(0), usage=Usage(1, 1))

    session = Session(root=toy_repo, config=Config(provider="fake", model="f"),
                      toolset="lecture")
    session.provider = Wrong()
    session.messages.append(Message(role="user", content="?"))
    session._turn()

    answer = [m for m in session.messages if m.role == "tool"][0].content
    assert "inconnu" in answer
    assert "désactivé" not in answer


def test_a_read_only_posture_also_ties_the_official_cli(toy_repo, monkeypatch):
    """In account mode the CLI owns its own Write and Bash. A posture that
    only filtered Thot's tools would be a lie exactly where it matters most."""
    from thot.llm.claude_cli import ClaudeCli
    from thot.llm.credentials import Config
    from thot.session import Session

    monkeypatch.setattr("thot.session.PromptSession", lambda **kwargs: None)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")

    session = Session(root=toy_repo,
                      config=Config(provider="claude-cli", model=""),
                      toolset="lecture")
    argv = session.claude._command("salut", "brief")

    assert "--disallowed-tools" in argv
    denied = argv[argv.index("--disallowed-tools") + 1:]
    for forbidden in ("Write", "Edit", "Bash"):
        assert forbidden in denied
    assert "Read" not in denied, "lire reste permis en mode lecture"


def test_the_map_posture_forbids_reading_files_through_the_cli_too():
    from thot import toolsets

    denied = toolsets.denied_cli_tools("carte")
    assert "Read" in denied and "Write" in denied
    assert toolsets.denied_cli_tools("complet") == ()


def test_switching_posture_mid_session_reaches_the_cli(toy_repo, monkeypatch):
    from thot.llm.credentials import Config
    from thot.session import Session

    monkeypatch.setattr("thot.session.PromptSession", lambda **kwargs: None)
    session = Session(root=toy_repo,
                      config=Config(provider="claude-cli", model=""))
    assert session.claude.denied == ()

    session._toolset("lecture")
    assert "Write" in session.claude.denied


def test_the_read_only_posture_denies_the_subagent_too():
    """One list, so one fix closed the door in both places.

    The audit engine and the session's `lecture` posture derive their denial
    list from the same tuple. `Task` was missing from it, and a subagent runs
    with its own toolset without inheriting the list — so both the engine and
    the session were denying five tools and leaving a sixth way through.
    """
    from thot.llm.claude_cli import WRITING_TOOLS
    from thot.toolsets import denied_cli_tools

    assert "Task" in WRITING_TOOLS
    assert "Task" in denied_cli_tools("lecture")
    assert "Task" in denied_cli_tools("carte")
    assert denied_cli_tools("agent") == (), (
        "la posture par défaut écrit : c'est son travail"
    )


def test_the_map_posture_denies_reading_as_well():
    """`carte` means the model works from the precomputed map alone."""
    from thot.llm.claude_cli import READING_TOOLS
    from thot.toolsets import denied_cli_tools

    denied = denied_cli_tools("carte")
    for tool in READING_TOOLS:
        assert tool in denied


def test_a_read_only_session_keeps_the_tools_that_only_read():
    """Extending the probe's denial list once took web search from `lecture`.

    A session reads a repository because its user asked it to; a probe reads
    code nobody vouches for. One list served both for an hour, and the
    narrower need won by accident.
    """
    from thot.llm.claude_cli import PROBE_DENIED
    from thot.toolsets import denied_cli_tools

    lecture = denied_cli_tools("lecture")
    assert "Write" in lecture and "Task" in lecture
    assert "WebFetch" not in lecture, "chercher sur le web, c'est lire"
    assert "WebFetch" in PROBE_DENIED
