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


# --- la carte doit suivre le disque ----------------------------------------
#
# Le serveur gardait un `ToolContext` par racine et ne l'invalidait jamais.
# `Server.refresh()` existait ; aucun chemin du protocole ne l'appelait. Le
# commentaire du site d'appel disait « the CLI's own edits invalidate it » —
# sauf que ce processus n'est pas le CLI : les écritures viennent de Hermes
# et de Prime, dans leur propre processus. Un agent ajoutait une fonction,
# demandait `find_symbol`, et s'entendait répondre « aucun symbole ». La
# carte mentait, avec autorité, pour tout le reste de la session — et c'est
# exactement la promesse de la fusion.


def _call(server, tool, **arguments):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })
    return reply["result"]["content"][0]["text"]


def test_a_symbol_written_after_the_first_call_is_found(server, toy_repo):
    app = toy_repo / "src" / "app.py"
    assert "Aucun symbole" in _call(server, "find_symbol", name="ajoutee")

    app.write_text(app.read_text() + "\n\ndef ajoutee():\n    return 2\n")

    answer = _call(server, "find_symbol", name="ajoutee")
    assert "Aucun symbole" not in answer
    assert "src/app.py" in answer


def test_a_file_created_after_the_first_call_is_mapped(server, toy_repo):
    before = _call(server, "code_map")
    (toy_repo / "src" / "nouveau.py").write_text("def tout_neuf():\n    return 3\n")
    after = _call(server, "code_map")

    assert "nouveau.py" not in before
    assert "nouveau.py" in after


def test_a_deleted_file_leaves_the_map(server, toy_repo):
    assert "safe.py" in _call(server, "code_map")

    (toy_repo / "src" / "safe.py").unlink()

    assert "safe.py" not in _call(server, "code_map")


def test_an_unchanged_tree_is_not_swept_twice(server, monkeypatch):
    """Suivre le disque ne doit pas vouloir dire tout refaire à chaque appel."""
    import thot.recon as recon_module

    swept = []
    real = recon_module.sweep

    def counting(root, **kwargs):
        swept.append(kwargs.get("deep", True))
        return real(root, **kwargs)

    monkeypatch.setattr(recon_module, "sweep", counting)

    _call(server, "code_map")
    _call(server, "code_map")
    _call(server, "find_symbol", name="main")

    assert len(swept) == 1, swept


def test_the_expensive_half_is_paid_only_when_asked_for(server, monkeypatch):
    """Rebâtir la carte ne doit pas relancer l'analyse de teinte de l'arbre.

    Sur Hermes, la moitié « findings » d'un balayage coûte deux minutes ;
    la carte, quelques centaines de millisecondes. Les payer ensemble à
    chaque `code_map` rendrait la correction pire que le défaut.
    """
    import thot.recon as recon_module

    deepened = []
    real = recon_module.deepen

    def counting(recon):
        deepened.append(recon.root)
        return real(recon)

    monkeypatch.setattr(recon_module, "deepen", counting)

    _call(server, "code_map")
    assert deepened == []

    _call(server, "audit")
    assert len(deepened) == 1

    # Et une fois payée, elle n'est pas repayée tant que rien ne bouge.
    _call(server, "audit")
    assert len(deepened) == 1


# --- une racine que l'appelant choisit à chaque appel ------------------------
#
# `thot audit` refuse un dépôt sans `.thot/authorization.yaml` — c'est la
# clause de mandat que `scope/authorization.py` résume en une phrase :
# « Thot refuses to audit code it was not mandated to audit ». Le serveur MCP
# ne passait par aucun de ces chemins : `resolve_root` acceptait n'importe
# quel chemin absolu, et un agent obtenait la carte, les symboles et l'audit
# complet de n'importe quel dossier de la machine, `~/.claude` compris.
#
# La doctrine du dépôt (pipeline.py:186) est que lancer Thot dans un dossier
# vaut autorisation de ce dossier. Ici la racine n'est pas choisie au
# lancement mais à chaque appel : celle-là doit porter son propre mandat.


def test_a_root_the_caller_names_needs_its_own_mandate(server, tmp_path_factory):
    outside = tmp_path_factory.mktemp("hors-mandat")
    (outside / "secret.py").write_text("def rien():\n    pass\n")

    reply = server.handle({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "code_map", "arguments": {"root": str(outside)}},
    })

    assert reply["error"]["code"] == -32602
    assert "autorisation" in reply["error"]["message"]


def test_a_mandated_root_is_served(server, tmp_path_factory):
    from thot.scope.authorization import write_authorization

    other = tmp_path_factory.mktemp("mandate")
    (other / "seul.py").write_text("def tout_seul():\n    return 1\n")
    write_authorization(other, owner="test")

    text = _call(server, "code_map", root=str(other))

    assert "seul.py" in text


def test_the_directory_the_server_serves_needs_no_file(server, toy_repo):
    """Le dossier de lancement est autorisé par l'acte de lancement, et ses
    descendants avec lui : c'est ainsi que la session interactive fonctionne
    déjà. Exiger le fichier ici casserait tous les câblages réels."""
    assert not (toy_repo / ".thot" / "authorization.yaml").exists()

    assert "src/app.py" in _call(server, "code_map", root=str(toy_repo))
    assert "app.py" in _call(server, "code_map", root=str(toy_repo / "src"))
