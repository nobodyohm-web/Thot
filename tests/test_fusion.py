"""The seam between the three programs.

None of these touch the user's real `~/.hermes` or `~/.prime`: the wiring
reads both locations from the environment precisely so that a test — and a
second profile — can point them somewhere else.
"""

from __future__ import annotations

import json

import pytest

from thot.fusion import locate, wiring


@pytest.fixture
def homes(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes-home"
    prime = tmp_path / "prime-home"
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("PRIME_AGENT_CONFIG_DIR", str(prime))
    return hermes, prime


# -- locating ----------------------------------------------------------------


def test_a_missing_program_is_named_not_guessed_around(tmp_path, monkeypatch):
    monkeypatch.setenv(locate.HERMES_ENV, str(tmp_path / "nowhere"))
    monkeypatch.setenv(locate.PRIME_ENV, str(tmp_path / "nowhere"))

    found = {part.name: part for part in locate.parts(probe=False)}
    assert found["hermes"].ready is False
    assert "absent" in found["hermes"].detail
    assert found["thot"].ready is True


def test_an_empty_directory_is_not_a_program(tmp_path, monkeypatch):
    """A failed checkout leaves the folder behind. That is not Hermes."""
    empty = tmp_path / "hermes"
    empty.mkdir()
    monkeypatch.setenv(locate.HERMES_ENV, str(empty))
    assert locate.hermes_root() is None, "un dossier vide n'est pas un programme"

    monkeypatch.delenv(locate.HERMES_ENV)
    monkeypatch.setattr(locate, "repo_root", lambda: tmp_path)
    assert locate.hermes_root() is None


# -- wiring ------------------------------------------------------------------


def test_the_server_entry_is_what_both_agents_accept(homes):
    entry = wiring.server_entry()
    # Hermes refuses an absolute command so a plugin cannot point at any
    # binary; Prime's config is a tagged union on `type`.
    assert entry["type"] == "stdio"
    assert entry["command"] == "thot"
    assert "/" not in entry["command"]


def test_wiring_is_idempotent(homes):
    first = wiring.wire()
    assert all(step.changes for step in first)

    second = wiring.plan()
    assert not any(step.changes for step in second)


def test_prime_keeps_every_setting_it_already_had(homes):
    _, prime = homes
    prime.mkdir(parents=True)
    settings = prime / "settings.json"
    settings.write_text(json.dumps({
        "defaultModel": "opus", "telemetry": False,
        "mcpServers": {"autre": {"type": "stdio", "command": "autre"}},
    }), encoding="utf-8")

    wiring.wire_prime()

    after = json.loads(settings.read_text(encoding="utf-8"))
    assert after["defaultModel"] == "opus"
    assert after["telemetry"] is False
    assert after["mcpServers"]["autre"] == {"type": "stdio", "command": "autre"}
    assert after["mcpServers"]["thot"] == wiring.server_entry()
    assert (prime / "settings.json.thot-backup").is_file()


def test_unwiring_removes_only_thot(homes):
    _, prime = homes
    prime.mkdir(parents=True)
    (prime / "settings.json").write_text(json.dumps({
        "mcpServers": {"autre": {"type": "stdio", "command": "autre"}},
    }), encoding="utf-8")

    wiring.wire()
    wiring.unwire()

    after = json.loads((prime / "settings.json").read_text(encoding="utf-8"))
    assert after["mcpServers"] == {"autre": {"type": "stdio", "command": "autre"}}
    assert not (wiring.hermes_plugin_dir() / "mcp.json").exists()


def test_hermes_accepts_the_plugin_thot_writes(homes):
    """Validated by Hermes's own loader, not by our reading of its rules.

    The first version of this plugin was silently rejected — absolute command
    path, missing `type` — while every file looked correctly written.
    """
    hermes_home, _ = homes
    plugins = pytest.importorskip(
        "hermes_cli.agent_plugins",
        reason="Hermes n'est pas installé dans cet environnement",
    )

    wiring.wire_hermes()
    package = plugins.load_agent_plugin(
        wiring.hermes_plugin_dir(), hermes_home / "plugin-data" / "thot"
    )

    assert list(package.mcp_servers) == ["thot"]
    assert not list(getattr(package, "diagnostics", ()))


# -- the map the agents actually get -----------------------------------------


def test_the_agent_names_the_project_it_wants_mapped(toy_repo):
    """Hermes pins a plugin server's cwd inside the plugin folder, so a
    server that trusted its own cwd would map the config directory."""
    from thot.mcp_server import Server

    server = Server(root=toy_repo)
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "code_map", "arguments": {"root": str(toy_repo)}},
    }
    answer = server.handle(request)
    assert "src/app.py" in answer["result"]["content"][0]["text"]


def test_every_tool_advertises_the_root_argument():
    from thot.mcp_server import Server

    listed = Server(root=None).handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    tools = listed["result"]["tools"]
    assert tools
    for tool in tools:
        assert "root" in tool["inputSchema"]["properties"], tool["name"]


def test_a_root_that_does_not_exist_is_refused_not_swallowed(toy_repo):
    from thot.mcp_server import Server

    answer = Server(root=toy_repo).handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "code_map", "arguments": {"root": "/n/existe/pas"}},
    })
    assert "error" in answer
    assert "introuvable" in answer["error"]["message"]


def test_two_projects_do_not_share_one_map(toy_repo, tmp_path):
    from thot.mcp_server import Server

    other = tmp_path / "autre"
    other.mkdir()
    (other / "seul.py").write_text("def rien():\n    pass\n")

    server = Server(root=toy_repo)
    first = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "code_map", "arguments": {"root": str(toy_repo)}},
    })["result"]["content"][0]["text"]
    second = server.handle({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "code_map", "arguments": {"root": str(other)}},
    })["result"]["content"][0]["text"]

    assert "src/app.py" in first
    assert "seul.py" in second
    assert "src/app.py" not in second
