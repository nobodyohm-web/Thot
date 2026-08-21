"""The MCP catalogue Thot inherited from Hermes.

Thot curates and delegates: the official CLI owns OAuth, so these tests
are about reading manifests honestly and refusing what cannot work here.
"""

from __future__ import annotations

import json

from thot.mcp import as_json, catalog, find, install


def test_the_whole_hermes_catalogue_is_shipped():
    entries = catalog()
    assert len(entries) >= 20
    names = {s.name for s in entries}
    for expected in ("sentry", "linear", "notion", "stripe", "supabase"):
        assert expected in names


def test_a_remote_server_installs_through_the_official_cli():
    """Thot must never hold the token: the CLI's own account flow does."""
    sentry = find("sentry")
    command = sentry.add_command()

    assert command[:3] == ["claude", "mcp", "add"]
    assert "--transport" in command and "http" in command
    assert sentry.url in command
    assert sentry.auth == "oauth"


def test_a_partial_name_finds_the_server():
    assert find("supa").name == "supabase"
    assert find("ce-truc-nexiste-pas") is None


def test_an_entry_hermes_installs_locally_is_refused_by_name():
    """`${INSTALL_DIR}` is expanded by Hermes; registering it would fail later."""
    n8n = find("n8n")
    assert n8n.needs_hermes

    done, message = install(n8n)
    assert done is False
    assert "Hermes" in message and "n8n" in message


def test_an_oauth_server_reports_that_it_is_not_yet_authorised(monkeypatch):
    """Registered is not connected, and saying so is the whole point."""
    import subprocess

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""),
    )

    done, message = install(find("linear"))
    assert done is True
    assert "/mcp" in message, "il faut dire comment finir l'autorisation"


def test_a_failing_cli_reports_its_own_last_line(monkeypatch):
    import subprocess

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "already exists"),
    )

    done, message = install(find("sentry"))
    assert done is False
    assert "already exists" in message


def test_the_catalogue_is_available_as_data():
    parsed = json.loads(as_json(catalog()))
    assert {"name", "transport", "auth"} <= set(parsed[0])
