"""Keeping the MCP endpoint answering, across reboots and crashes.

`thot fusion wire` writes `http://127.0.0.1:8787/mcp` into Prime's
configuration. Prime's client cannot start that server — an HTTP transport
is the one transport a client does not launch — so until something
supervises it, the wiring is a promise kept only while a terminal happens to
be open. These tests are about the difference between wired and working.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot import service


def _plist(tmp_path, **kwargs) -> str:
    return service.launchd_plist(tmp_path, **kwargs)


def test_the_unit_keeps_the_server_up_rather_than_running_it_once(tmp_path):
    text = _plist(tmp_path)

    assert "<key>KeepAlive</key>" in text
    assert "<key>RunAtLoad</key>\n  <true/>" in text
    # A calendar entry would make it a nightly job, which is the opposite of
    # what an endpoint is for.
    assert "StartCalendarInterval" not in text


def test_a_crash_loop_is_throttled(tmp_path):
    """Without this, a port already taken means launchd relaunching the same
    doomed process as fast as it can exit, for ever."""
    assert "<key>ThrottleInterval</key>" in _plist(tmp_path)


def test_the_unit_carries_the_tree_it_must_serve(tmp_path):
    """The server reads THOT_ROOT or falls back to the working directory,
    and launchd hands a job `/` as its working directory."""
    text = _plist(tmp_path)

    assert f"<key>THOT_ROOT</key><string>{tmp_path}</string>" in text
    assert f"<key>WorkingDirectory</key><string>{tmp_path}</string>" in text


def test_the_unit_asks_for_the_port_it_was_given(tmp_path):
    assert "<string>9001</string>" in _plist(tmp_path, port=9001)


def test_the_unit_serves_over_http(tmp_path):
    """`thot mcp serve` without `--http` speaks stdio to a pipe nobody
    opened — a supervised process that answers nothing."""
    text = _plist(tmp_path)
    arguments = text.split("<key>ProgramArguments</key>")[1].split("</array>")[0]

    assert "<string>--http</string>" in arguments


def test_the_fallback_command_is_one_that_actually_runs(monkeypatch):
    """Sans `thot` dans le PATH, l'unité doit nommer un point d'entrée réel.

    `python -m thot.cli` n'en est pas un : `cli.py` n'a pas de bloc
    `if __name__ == "__main__"`, donc le module s'importe, définit `main` et
    sort 0 sans rien faire. Sous `KeepAlive`, ce n'est pas un serveur mort,
    c'est un relancement toutes les dix secondes indéfiniment — et `/mcp`
    reste vide côté Prime pendant tout ce temps.
    """
    monkeypatch.setattr("shutil.which", lambda name: None)

    argv = service._command(8787)

    assert "-m" in argv and argv[argv.index("-m") + 1] == "thot"
    assert not any("thot.cli" in part for part in argv)


def test_a_path_with_a_space_stays_one_argument(monkeypatch):
    """`str.split()` sur `/Users/dev/My Tools/bin/thot` nommait un binaire
    qui n'existe pas."""
    monkeypatch.setattr("shutil.which",
                        lambda name: "/Users/dev/My Tools/bin/thot"
                        if name == "thot" else None)

    assert service._command(8787)[0] == "/Users/dev/My Tools/bin/thot"


def test_the_systemd_unit_restarts_too(tmp_path):
    text = service.systemd_unit(tmp_path, port=8787)

    assert "Restart=always" in text
    assert "--http" in text
    assert f"Environment=THOT_ROOT={tmp_path}" in text


def test_installing_writes_the_unit_and_names_the_next_step(tmp_path, monkeypatch):
    """Thot writes the file and tells you the one command that loads it. A
    tool that quietly registers background agents is one you stop trusting."""
    monkeypatch.setattr(service.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(service, "LAUNCH_AGENTS", tmp_path / "LaunchAgents")

    written, step = service.install(tmp_path, port=8787)

    assert written is not None and written.exists()
    assert "launchctl" in step and str(written) in step


def test_nothing_is_written_behind_your_back(tmp_path, monkeypatch):
    """`installed()` answers about the file, not about a wish."""
    monkeypatch.setattr(service, "LAUNCH_AGENTS", tmp_path / "LaunchAgents")
    monkeypatch.setattr(service.platform, "system", lambda: "Darwin")

    assert service.installed() is False
    service.install(tmp_path, port=8787)
    assert service.installed() is True


# --- the check that closes the gap ----------------------------------------


def test_the_doctor_asks_the_endpoint_instead_of_trusting_the_file(monkeypatch):
    """A URL in Prime's settings is not a connection. After every reboot the
    file still says `http://127.0.0.1:8787/mcp` and nothing is listening —
    which is precisely the state `fusion status` used to call `branché`."""
    from thot import doctor
    from thot.fusion import wiring

    monkeypatch.setattr(wiring, "prime_endpoint",
                        lambda: "http://127.0.0.1:8787/mcp")
    monkeypatch.setattr("thot.mcp_http.endpoint_answers", lambda url: False)
    monkeypatch.setattr(service, "installed", lambda: False)

    ok, detail = doctor._served()

    assert ok is False
    assert "thot mcp service --install" in detail


def test_an_endpoint_that_answers_passes(monkeypatch):
    from thot import doctor
    from thot.fusion import wiring

    monkeypatch.setattr(wiring, "prime_endpoint",
                        lambda: "http://127.0.0.1:8787/mcp")
    monkeypatch.setattr("thot.mcp_http.endpoint_answers", lambda url: True)

    ok, _ = doctor._served()

    assert ok is True


def test_a_prime_that_was_never_wired_is_not_a_failure(monkeypatch):
    """Not wiring Prime is a choice. Only a wiring that does not work is a
    broken install."""
    from thot import doctor
    from thot.fusion import wiring

    monkeypatch.setattr(wiring, "prime_endpoint", lambda: None)

    ok, detail = doctor._served()

    assert ok is True
    assert "branché" in detail


def test_the_unit_is_written_but_never_loaded(tmp_path, monkeypatch):
    """Installing a background agent on somebody's machine is their act."""
    monkeypatch.setattr(service, "LAUNCH_AGENTS", tmp_path / "LaunchAgents")
    monkeypatch.setattr(service.platform, "system", lambda: "Darwin")

    _, step = service.install(tmp_path, port=8787)

    assert step == service.activation()
    assert "load" in step


def test_the_endpoint_read_is_the_one_prime_reads(tmp_path, monkeypatch):
    """Not `prime_server_entry()` — that is what Thot *would* write. The
    question is what the file says now, including a `false` somebody set."""
    import json

    from thot.fusion import wiring

    settings = tmp_path / "settings.json"
    monkeypatch.setattr(wiring, "prime_settings_path", lambda: settings)

    settings.write_text(json.dumps({"mcpServers": {
        "thot": {"type": "http", "url": "http://127.0.0.1:9999/mcp",
                 "enabled": True}}}))
    assert wiring.prime_endpoint() == "http://127.0.0.1:9999/mcp"

    settings.write_text(json.dumps({"mcpServers": {
        "thot": {"type": "http", "url": "http://x/mcp", "enabled": False}}}))
    assert wiring.prime_endpoint() is None

    settings.write_text(json.dumps({"mcpServers": {
        "thot": {"type": "stdio", "command": "thot"}}}))
    assert wiring.prime_endpoint() is None
