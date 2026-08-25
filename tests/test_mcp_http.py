"""La carte de Thot par-dessus HTTP — la seule forme que Prime sait consommer.

`mcp-manager.js:38` jette toute entrée dont le `type` n'est pas `"http"` :
« stdio servers self-manage in Python », et ce Python n'existe pas — aucune
occurrence de `stdio_client` dans tout `prime/`. L'entrée `type: stdio` que
`thot fusion wire` écrivait dans son `settings.json` n'a donc jamais été lue.
Vérifié contre le `dist/` réellement exécuté : `mcp.config("thot")` renvoyait
`{}`.

Le transport est délibérément le plus petit qui soit correct : un POST, du
JSON dedans, du JSON dehors, sur la boucle locale seulement, derrière un
jeton. Aucune dépendance neuve — `mcp_server` parle déjà JSON-RPC à la main.
"""

from __future__ import annotations

import json
import os
import stat
import threading

import httpx
import pytest

from thot import mcp_http


@pytest.fixture
def served(toy_repo, tmp_path, monkeypatch):
    """Un serveur en écoute sur un port libre, et de quoi lui parler."""
    monkeypatch.setenv("THOT_HOME", str(tmp_path / "thot-home"))
    httpd, token = mcp_http.build(toy_repo, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    base = f"http://{host}:{port}{mcp_http.ENDPOINT}"
    try:
        yield base, token
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _rpc(base, token, method, **params):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        payload["params"] = params
    return httpx.post(
        base, json=payload, timeout=30,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/json, text/event-stream"},
    )


# -- le jeton ---------------------------------------------------------------


def test_a_request_without_a_token_is_refused(served):
    base, _ = served

    answer = httpx.post(base, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        timeout=30)

    assert answer.status_code == 401


def test_a_request_with_the_wrong_token_is_refused(served):
    base, token = served

    answer = _rpc(base, token + "x", "ping")

    assert answer.status_code == 401


def test_the_token_file_is_never_readable_by_anyone_else(tmp_path, monkeypatch):
    """Créé en 0600 d'emblée, pas créé puis corrigé."""
    monkeypatch.setenv("THOT_HOME", str(tmp_path / "thot-home"))

    mcp_http.read_or_make_token()

    mode = stat.S_IMODE(os.stat(mcp_http.token_file()).st_mode)
    assert mode == 0o600, oct(mode)


def test_the_token_survives_a_restart(tmp_path, monkeypatch):
    """Sinon le réglage écrit chez Prime cesserait d'être valable au reboot."""
    monkeypatch.setenv("THOT_HOME", str(tmp_path / "thot-home"))

    assert mcp_http.read_or_make_token() == mcp_http.read_or_make_token()


# -- le protocole -----------------------------------------------------------


def test_initialize_answers_the_handshake(served):
    base, token = served

    body = _rpc(base, token, "initialize").json()

    assert body["result"]["serverInfo"]["name"] == "thot"


def test_the_six_tools_are_listed(served):
    from thot.mcp_server import EXPOSED

    base, token = served

    tools = _rpc(base, token, "tools/list").json()["result"]["tools"]

    assert {t["name"] for t in tools} == set(EXPOSED)


def test_a_tool_answers_from_the_map(served):
    base, token = served

    body = _rpc(base, token, "tools/call",
                name="callers", arguments={"symbol": "run_command"}).json()

    assert "src.app.main" in body["result"]["content"][0]["text"]


def test_a_notification_gets_no_body(served):
    """Un message sans `id` n'attend pas de réponse : 202 et rien."""
    base, token = served

    answer = httpx.post(
        base, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        timeout=30, headers={"Authorization": f"Bearer {token}"},
    )

    assert answer.status_code == 202
    assert answer.content == b""


def test_a_batch_is_answered_as_a_batch(served):
    base, token = served

    answer = httpx.post(
        base, timeout=30,
        headers={"Authorization": f"Bearer {token}"},
        json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"},
              {"jsonrpc": "2.0", "id": 2, "method": "ping"}],
    )

    assert [item["id"] for item in answer.json()] == [1, 2]


def test_a_body_that_is_not_json_is_a_parse_error_not_a_crash(served):
    base, token = served

    answer = httpx.post(base, content=b"{ pas du json",
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)

    assert answer.status_code == 200
    assert answer.json()["error"]["code"] == -32700


# -- la surface exposée -----------------------------------------------------


def test_it_listens_on_the_loopback_only(served):
    """Un serveur qui donne la carte du dépôt n'a rien à faire sur le réseau."""
    base, _ = served

    assert base.startswith("http://127.0.0.1:")


def test_a_get_is_refused(served):
    base, token = served

    answer = httpx.get(base, headers={"Authorization": f"Bearer {token}"}, timeout=30)

    assert answer.status_code == 405


def test_another_path_is_not_served(served):
    base, token = served

    answer = httpx.post(base.replace(mcp_http.ENDPOINT, "/autre"),
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)

    assert answer.status_code == 404


def test_a_foreign_origin_is_refused(served):
    """Contre le rebinding DNS : une page web ne parlera pas à ce serveur."""
    base, token = served

    answer = httpx.post(
        base, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=30,
        headers={"Authorization": f"Bearer {token}",
                 "Origin": "https://exemple.invalide"},
    )

    assert answer.status_code == 403


def test_an_oversized_body_is_refused_before_being_read(served):
    """Refusé sur l'entête : le corps annoncé n'est jamais lu.

    Écrit à la main, parce qu'un client HTTP correct refuse d'annoncer un
    `Content-Length` qu'il n'honore pas — et c'est exactement la requête
    malhonnête contre laquelle la borne existe.
    """
    import socket
    from urllib.parse import urlparse

    base, token = served
    parsed = urlparse(base)

    with socket.create_connection((parsed.hostname, parsed.port), timeout=30) as sock:
        sock.sendall((
            f"POST {mcp_http.ENDPOINT} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Length: {mcp_http.MAX_BODY + 1}\r\n"
            "\r\n"
        ).encode("ascii"))  # les entêtes seules : aucun octet de corps ne suivra
        status = sock.recv(4096).split(b"\r\n", 1)[0]

    assert b"413" in status, status


def test_a_refusal_does_not_poison_the_next_request_on_the_same_connection(served):
    """Un refus arrive avant la lecture du corps — donc il ferme la connexion.

    Les autres tests de refus passent tous par `httpx.post`, qui ouvre une
    connexion par appel : le corps jamais lu part avec la socket et personne
    ne le voit. Un client qui réutilise sa connexion — celui de Prime — voit
    autre chose : en HTTP/1.1 les octets du corps refusé restent dans la
    socket et sont relus comme la ligne de requête suivante.
    """
    base, token = served

    with httpx.Client(timeout=30) as client:
        refused = client.post(
            base, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer faux"},
        )
        assert refused.status_code == 401

        answer = client.post(
            base, json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert answer.status_code == 200, answer.text
    assert answer.json()["id"] == 2


# -- la carte partagée ------------------------------------------------------


def test_two_requests_at_once_build_the_map_once(served, monkeypatch):
    """Deux agents qui demandent en même temps ne paient pas deux balayages."""
    import thot.recon as recon_module

    swept = []
    real = recon_module.sweep

    def counting(root, **kwargs):
        swept.append(root)
        return real(root, **kwargs)

    monkeypatch.setattr(recon_module, "sweep", counting)
    base, token = served

    answers = [None, None]

    def ask(index):
        answers[index] = _rpc(base, token, "tools/call",
                              name="code_map", arguments={}).json()

    threads = [threading.Thread(target=ask, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert all(a is not None and "result" in a for a in answers), answers
    assert len(swept) == 1, swept


# -- le client que Prime utilise réellement ---------------------------------


def test_the_official_sdk_client_can_use_it(served):
    """Le vrai client MCP, contre ce serveur, sans intermédiaire.

    Les tests ci-dessus prouvent que le serveur répond comme il est écrit.
    Celui-ci prouve qu'il répond comme le SDK l'attend — c'est la seule
    question qui décide si Prime gagne quelque chose. Le chemin reproduit
    est exactement celui de `prime/prime-agent-runtime/src/rlm/mcp_base.py`
    (`_resolve_streamable_http`, puis `Authorization: Bearer`), y compris sa
    tolérance aux deux noms et aux deux signatures du SDK.
    """
    import asyncio
    import inspect

    pytest.importorskip("mcp")
    from mcp import ClientSession
    from mcp.client import streamable_http as transport_module

    from thot.mcp_server import EXPOSED

    base, token = served
    transport = next(
        (getattr(transport_module, name)
         for name in ("streamablehttp_client", "streamable_http_client")
         if getattr(transport_module, name, None) is not None),
        None,
    )
    assert transport is not None, "le SDK installé n'expose aucun client streamable HTTP"

    async def converse():
        headers = {"Authorization": f"Bearer {token}"}
        if "headers" in inspect.signature(transport).parameters:
            opened = transport(base, headers=headers)
        else:
            import httpx2

            opened = transport(base, http_client=httpx2.AsyncClient(headers=headers))
        async with opened as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                listed = await session.list_tools()
                called = await session.call_tool(
                    "callers", {"symbol": "run_command"}
                )
                return ({tool.name for tool in listed.tools},
                        called.content[0].text)

    names, answer = asyncio.run(converse())

    assert names == set(EXPOSED)
    assert "src.app.main" in answer


def test_a_client_that_hangs_up_leaves_no_traceback(capsys):
    """Un agent lâche ses connexions en permanence ; ce n'est pas un incident."""
    httpd = mcp_http._Quiet.__new__(mcp_http._Quiet)

    try:
        raise ConnectionResetError(54, "Connection reset by peer")
    except ConnectionResetError:
        httpd.handle_error(object(), ("127.0.0.1", 1234))

    assert capsys.readouterr().err == ""


def test_a_real_error_is_still_reported(capsys):
    httpd = mcp_http._Quiet.__new__(mcp_http._Quiet)

    try:
        raise ValueError("quelque chose de vraiment cassé")
    except ValueError:
        httpd.handle_error(object(), ("127.0.0.1", 1234))

    assert "vraiment cassé" in capsys.readouterr().err


def test_prime_own_runtime_can_reach_it(served, tmp_path, monkeypatch):
    """Le client de Prime, sa classe d'intégration, et le skill que Thot livre.

    Le test au-dessus prouve que le SDK parle à ce serveur. Celui-ci prouve
    que *Prime* le fait : `rlm.McpIntegration` résout son identifiant dans
    `auth.json`, ouvre la connexion et dispatche l'appel. C'est la chaîne
    entière, et c'est elle qui n'existait pas — l'entrée `type: stdio` que
    Thot écrivait n'était lue par personne.

    Ignoré si le checkout de Prime n'est pas là : c'est une preuve
    d'intégration, pas une dépendance.
    """
    import asyncio
    import json
    import sys

    from thot.fusion.locate import prime_root

    root = prime_root()
    if root is None:
        pytest.skip("pas de checkout de Prime")
    runtime = root / "prime-agent-runtime" / "src"
    if not (runtime / "rlm" / "mcp_base.py").is_file():
        pytest.skip("runtime Python de Prime absent")
    pytest.importorskip("mcp")

    base, token = served

    # L'agent-dir que Prime lirait, avec le seul identifiant qui l'intéresse.
    agent_dir = tmp_path / "prime-agent"
    agent_dir.mkdir()
    (agent_dir / "auth.json").write_text(
        json.dumps({"mcp:thot": {"type": "api_key", "key": token}}), encoding="utf-8"
    )
    monkeypatch.setenv("PRIME_AGENT_CODING_AGENT_DIR", str(agent_dir))
    monkeypatch.syspath_prepend(str(runtime))

    from rlm import McpIntegration

    class Thot(McpIntegration):
        server = "thot"
        url = base

    integration = Thot()

    async def converse():
        listed = await integration.list_tools()
        called = await integration.callers(symbol="run_command")
        return {tool["name"] for tool in listed}, str(called)

    names, answer = asyncio.run(converse())

    assert "find_symbol" in names and "code_map" in names
    assert "src.app.main" in answer

    del sys  # syspath_prepend est défait par monkeypatch


# -- « branché » et « qui répond » sont deux questions ----------------------


def test_a_live_endpoint_is_recognised(served, tmp_path):
    base, token = served
    held = tmp_path / "jeton"
    held.write_text(token, encoding="utf-8")

    assert mcp_http.endpoint_answers(base, held) is True


def test_a_port_nobody_listens_on_is_not_wired(tmp_path):
    held = tmp_path / "jeton"
    held.write_text("peu importe", encoding="utf-8")

    assert mcp_http.endpoint_answers(
        "http://127.0.0.1:1/mcp", held, timeout=0.5
    ) is False


def test_the_wrong_token_is_not_a_connection(served, tmp_path):
    base, token = served
    held = tmp_path / "jeton"
    held.write_text(token + "faux", encoding="utf-8")

    assert mcp_http.endpoint_answers(base, held) is False


def test_a_missing_token_file_is_not_a_connection(served, tmp_path):
    base, _ = served

    assert mcp_http.endpoint_answers(base, tmp_path / "absent") is False


# -- le contrôle d'origine, tel qu'il aurait dû être écrit ------------------
#
# Comparer le début de la chaîne laissait passer `http://127.0.0.1.evil.tld`,
# un nom que n'importe qui peut faire pointer où il veut. C'est exactement
# l'attaque contre laquelle ce contrôle existe : une page visitée par
# l'utilisateur lit la carte de son dépôt à travers sa propre boucle locale.


@pytest.mark.parametrize("origine", [
    "http://127.0.0.1.evil.example",
    "http://localhost.attaquant.fr",
    "http://127.0.0.1@evil.example",
    "https://evil.example",
])
def test_an_origin_that_merely_looks_local_is_refused(served, origine):
    base, token = served

    answer = httpx.post(
        base, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=30,
        headers={"Authorization": f"Bearer {token}", "Origin": origine},
    )

    assert answer.status_code == 403, origine


@pytest.mark.parametrize("origine", [
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://[::1]:8080",
])
def test_a_genuinely_local_origin_still_works(served, origine):
    base, token = served

    answer = httpx.post(
        base, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=30,
        headers={"Authorization": f"Bearer {token}", "Origin": origine},
    )

    assert answer.status_code == 200, origine


def test_a_chunked_body_is_refused_rather_than_read_as_empty(served):
    """Sans Content-Length, le corps était lu comme vide et le JSON « illisible ».

    Répondre « JSON illisible » à une requête parfaitement formée envoie
    chercher l'erreur là où elle n'est pas.
    """
    import socket
    from urllib.parse import urlparse

    base, token = served
    parsed = urlparse(base)

    with socket.create_connection((parsed.hostname, parsed.port), timeout=30) as sock:
        sock.sendall((
            f"POST {mcp_http.ENDPOINT} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
        ).encode("ascii"))
        status = sock.recv(4096).split(b"\r\n", 1)[0]

    assert b"411" in status, status


def test_a_token_another_process_just_wrote_is_read_not_replaced(tmp_path, monkeypatch):
    """Deux démarrages simultanés ne doivent pas produire deux jetons.

    Le second écraserait celui que `fusion wire` a déposé chez Prime, et la
    connexion tomberait sans que rien ne l'explique.
    """
    monkeypatch.setenv("THOT_HOME", str(tmp_path / "thot-home"))
    (tmp_path / "thot-home").mkdir()
    mcp_http.token_file().write_text("jeton-du-premier\n", encoding="utf-8")

    real_open = mcp_http.os.open

    def racing(path, flags, mode=0o777):
        raise FileExistsError(17, "File exists")

    monkeypatch.setattr(mcp_http.os, "open", racing)

    assert mcp_http.read_or_make_token() == "jeton-du-premier"
    monkeypatch.setattr(mcp_http.os, "open", real_open)
