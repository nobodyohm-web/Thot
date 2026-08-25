"""The account path: command construction and stream parsing.

The real CLI is never launched here — these tests check what Thot asks for and
how it reads the answer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from thot.llm.base import ProviderError
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


# -- surviving a turn that died ----------------------------------------------
#
# All four of these come from one real session: a run hit its session limit,
# Thot reported "`claude` s'est arrêté : code 1", and every attempt to
# continue answered "Session ID ... is already in use" — the work could not
# be resumed at all.

FAKE_CLAUDE = '''#!{python}
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["CLAUDE_LOG"], "a") as fh:
    fh.write(json.dumps(argv) + "\\n")
mode = os.environ.get("CLAUDE_MODE", "")
if mode == "session-limit":
    # Printed on stdout, outside the JSON stream — as the real CLI does.
    print("You\'ve hit your session limit \u00b7 resets 1am (Europe/Paris)")
    raise SystemExit(1)
if mode == "already-in-use":
    sys.stderr.write("Error: Session ID %s is already in use.\\n" % argv[-1])
    raise SystemExit(1)
if mode == "usage-limit":
    sys.stderr.write("Claude AI usage limit reached\\n")
    raise SystemExit(1)
print(json.dumps({{"type": "stream_event", "event": {{
    "type": "content_block_delta",
    "delta": {{"type": "text_delta", "text": "ok"}}}}}}))
raise SystemExit(0)
'''


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A CLI that fails the way the real one failed, and logs every argv."""
    import stat
    import sys

    binary = tmp_path / "claude"
    binary.write_text(FAKE_CLAUDE.format(python=sys.executable))
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    log = tmp_path / "argv.jsonl"
    monkeypatch.setenv("CLAUDE_LOG", str(log))
    return log


def calls_in(log):
    return [json.loads(line) for line in log.read_text().splitlines() if line]


def test_a_session_limit_is_named_with_its_reset_hour(cli, fake_claude, monkeypatch):
    """The cause was on stdout, so a stderr-only reader said "code 1".

    "code 1" tells the user nothing they can act on. The CLI names the hour
    the window reopens; quoting it is the whole difference.
    """
    monkeypatch.setenv("CLAUDE_MODE", "session-limit")
    with pytest.raises(ProviderError) as caught:
        cli.send("salut")

    message = str(caught.value)
    assert "session" in message.lower()
    assert "1am" in message
    assert "code 1" not in message


def test_a_dead_turn_still_spends_its_session_id(cli, fake_claude, monkeypatch):
    """The id is taken by the launch, not by the success.

    `--session-id` registers the thread before the first token. Flipping the
    started flag only on success made one failed turn permanent: every later
    turn re-sent the same id and got "already in use" forever.
    """
    monkeypatch.setenv("CLAUDE_MODE", "session-limit")
    first = cli.session_id
    with pytest.raises(ProviderError):
        cli.send("salut")

    assert cli._started is True
    assert cli.session_id == first  # the thread is not abandoned, only spent
    command = command_of(cli)
    assert "--resume" in command
    assert "--session-id" not in command


def test_a_thread_the_cli_will_not_open_is_replaced_once(
    cli, fake_claude, monkeypatch
):
    """An unopenable thread is recoverable; being stranded is not.

    Thot holds the transcript, so a fresh CLI thread continues the work.
    Two launches, two different ids, and the second refusal is reported
    rather than retried again — one retry, not a loop.
    """
    monkeypatch.setenv("CLAUDE_MODE", "already-in-use")
    seen: list[str] = []
    with pytest.raises(ProviderError):
        cli.send("salut", events=Events(on_error=seen.append))

    calls = calls_in(fake_claude)
    assert len(calls) == 2
    ids = [call[call.index("--session-id") + 1] for call in calls]
    assert ids[0] != ids[1]
    assert any("Nouveau fil" in message for message in seen)


def test_a_usage_limit_is_never_retried(cli, fake_claude, monkeypatch):
    """Retrying a limit spends the user's quota to reproduce the refusal."""
    monkeypatch.setenv("CLAUDE_MODE", "usage-limit")
    with pytest.raises(ProviderError):
        cli.send("salut")

    assert len(calls_in(fake_claude)) == 1


# -- being able to check its own work ----------------------------------------


def allowed_in(cli):
    command = command_of(cli)
    return command[command.index("--allowed-tools") + 1]


def test_the_repository_test_command_is_pre_approved(tmp_path):
    """A session that may edit must be able to run the suite.

    `acceptEdits` waves writes through and stops at `Bash`, and under `-p`
    nobody can approve it — so a self-improvement run edited six production
    files while every attempt to run pytest was refused.
    """
    cli = ClaudeCli(root=tmp_path, test_command="pytest")
    assert "Bash(pytest:*)" in allowed_in(cli)


def test_only_that_command_is_pre_approved_not_a_shell(tmp_path):
    """One capability, not arbitrary execution.

    Bare `Bash` would buy the ability to run the suite by handing over
    everything else with it.
    """
    allowed = allowed_in(ClaudeCli(root=tmp_path, test_command="pytest")).split()
    assert "Bash" not in allowed


def test_a_posture_that_forbids_the_shell_still_forbids_it(tmp_path):
    """Deny beats allow: a read-only probe stays read-only."""
    cli = ClaudeCli(root=tmp_path, test_command="pytest", denied=("Bash",))
    assert "Bash" not in allowed_in(cli)


def test_a_repository_with_no_test_command_approves_nothing(tmp_path):
    """Nothing to run means nothing to approve."""
    assert "Bash" not in allowed_in(ClaudeCli(root=tmp_path))
