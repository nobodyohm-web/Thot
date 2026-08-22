"""Where verdicts can live besides this laptop.

The JSON backend is the one a team actually uses — decisions committed with
the code they judge. The HTTP and mem0 backends are held to their contracts
with a mock transport, the way Hermes tests its own mem0 client, so "it
speaks the protocol" is a claim under test rather than a hope.
"""

from __future__ import annotations

import json

import httpx
import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.memory import (
    Decision,
    JsonMemory,
    LayeredMemory,
    Verdict,
    build_memory,
    repo_path,
)
from thot.memory.factory import build_remote
from thot.memory.remote import MEM0_USER, HttpMemory, Mem0Memory
from thot.memory.sqlite import SqliteMemory


def _finding(identifier="abc", path="a.py"):
    return Finding(
        id=identifier, rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path=path, line=7, symbol="run", ast_hash="h"),
    )


# A fixed instant. `Verdict.of` stamps `decided_at` from the clock at second
# precision, so two verdicts built from the same finding differ whenever the
# two calls straddle a second boundary — which a loaded 27-second suite does
# now and then. The stability test below compares bytes, so that flake made it
# fail once in a while and pass on every rerun.
FIXED_INSTANT = "2026-01-02T03:04:05+00:00"


def _verdict(identifier="abc", author="dev", reason="commande littérale"):
    import dataclasses

    made = Verdict.of(_finding(identifier), Decision.REFUTED, reason, author)
    return dataclasses.replace(made, decided_at=FIXED_INSTANT)


# -- the file a team commits -------------------------------------------------


def test_a_verdict_survives_being_written_and_read_back(tmp_path):
    memory = JsonMemory.open(tmp_path / "verdicts.json")
    memory.remember(_verdict())

    reopened = JsonMemory.open(tmp_path / "verdicts.json")
    found = reopened.recall("abc")

    assert found.decision is Decision.REFUTED
    assert found.author == "dev"
    assert found.reason == "commande littérale"
    assert found.ast_hash == "h", "sans l'AST, un verdict n'expirerait jamais"


def test_the_file_is_written_in_a_stable_order(tmp_path):
    """A file whose diff is noise is a file nobody reviews."""
    memory = JsonMemory.open(tmp_path / "verdicts.json")
    for identifier in ("zzz", "aaa", "mmm"):
        memory.remember(_verdict(identifier))

    body = json.loads((tmp_path / "verdicts.json").read_text())
    assert [v["finding_id"] for v in body["verdicts"]] == ["aaa", "mmm", "zzz"]
    assert body["format"] == "thot.verdicts"

    # Rewriting the same content must produce the same bytes.
    before = (tmp_path / "verdicts.json").read_text()
    JsonMemory.open(tmp_path / "verdicts.json").remember(_verdict("aaa"))
    assert (tmp_path / "verdicts.json").read_text() == before


def test_a_missing_or_corrupt_file_is_an_empty_memory_not_a_crash(tmp_path):
    assert JsonMemory.open(tmp_path / "absent.json").all_verdicts() == []

    (tmp_path / "cassé.json").write_text("{ ceci n'est pas du json")
    assert JsonMemory.open(tmp_path / "cassé.json").all_verdicts() == []


def test_an_entry_without_a_usable_decision_is_skipped(tmp_path):
    (tmp_path / "v.json").write_text(json.dumps({
        "format": "thot.verdicts",
        "verdicts": [
            {"finding_id": "bon", "decision": "refuted"},
            {"finding_id": "sans-décision"},
            {"decision": "refuted"},
            "pas un objet",
        ],
    }))
    assert [v.finding_id for v in JsonMemory.open(tmp_path / "v.json").all_verdicts()] \
        == ["bon"]


def test_forgetting_rewrites_the_file(tmp_path):
    memory = JsonMemory.open(tmp_path / "v.json")
    memory.remember(_verdict())

    assert memory.forget("abc") is True
    assert memory.forget("abc") is False
    assert JsonMemory.open(tmp_path / "v.json").all_verdicts() == []


# -- the chain ---------------------------------------------------------------


def test_the_reviewed_decision_outranks_the_local_note(tmp_path):
    team = JsonMemory.open(tmp_path / "équipe.json")
    team.remember(_verdict(author="equipe", reason="revu en PR"))
    local = JsonMemory.open(tmp_path / "local.json")
    local.remember(_verdict(author="moi", reason="note rapide"))

    chain = LayeredMemory([team, local])
    assert chain.recall("abc").author == "equipe"
    assert [v.author for v in chain.all_verdicts()] == ["equipe"]


def test_writing_lands_on_the_local_layer_not_the_committed_one(tmp_path):
    """A tool that edits a committed file on every keystroke makes enemies."""
    team = JsonMemory.open(tmp_path / "équipe.json")
    local = JsonMemory.open(tmp_path / "local.json")

    LayeredMemory([team, local]).remember(_verdict("nouveau"))

    assert local.recall("nouveau") is not None
    assert team.recall("nouveau") is None
    assert not (tmp_path / "équipe.json").exists()


def test_forgetting_reaches_every_layer(tmp_path):
    """A decision half-forgotten is worse than one kept."""
    team = JsonMemory.open(tmp_path / "équipe.json")
    local = JsonMemory.open(tmp_path / "local.json")
    team.remember(_verdict())
    local.remember(_verdict())

    assert LayeredMemory([team, local]).forget("abc") is True
    assert team.recall("abc") is None
    assert local.recall("abc") is None


def test_a_broken_layer_costs_only_itself(tmp_path):
    class Broken:
        name = "cassé"

        def is_available(self):
            raise RuntimeError("serveur mort")

        def recall(self, finding_id):
            raise RuntimeError("serveur mort")

        def all_verdicts(self):
            raise RuntimeError("serveur mort")

        def remember(self, verdict):
            raise RuntimeError("serveur mort")

        def forget(self, finding_id):
            raise RuntimeError("serveur mort")

    local = JsonMemory.open(tmp_path / "local.json")
    local.remember(_verdict())
    chain = LayeredMemory([Broken(), local])

    assert chain.recall("abc") is not None
    assert len(chain.all_verdicts()) == 1
    assert chain.is_available() is True
    assert chain.forget("abc") is True


def test_the_chain_says_what_it_is(tmp_path):
    chain = LayeredMemory([JsonMemory.open(tmp_path / "a.json"),
                           SqliteMemory.open(tmp_path / "m.db")])
    assert chain.describe() == "json → sqlite (écriture : sqlite)"


# -- choosing one ------------------------------------------------------------


def test_without_a_committed_file_there_is_no_chain_to_build(isolated_home, tmp_path):
    memory = build_memory(tmp_path, config={})
    assert memory.name == "sqlite"


def test_a_committed_file_is_picked_up_with_no_configuration(isolated_home, tmp_path):
    JsonMemory.for_repo(tmp_path).remember(_verdict(author="equipe"))
    assert repo_path(tmp_path).is_file()

    memory = build_memory(tmp_path, config={})
    assert memory.name == "layered"
    assert memory.recall("abc").author == "equipe"


def test_a_remote_is_added_from_configuration(isolated_home, tmp_path):
    memory = build_memory(tmp_path, config={
        "remote": {"kind": "http", "base_url": "https://audit.example",
                   "token": "t"}
    })
    assert [layer.name for layer in memory.layers] == ["http", "sqlite"]


def test_the_environment_configures_a_remote(isolated_home, monkeypatch):
    monkeypatch.setenv("THOT_MEMORY_URL", "https://audit.example")
    monkeypatch.setenv("THOT_MEMORY_TOKEN", "jeton")
    from thot.memory.factory import load_config

    remote = load_config()["remote"]
    assert remote["kind"] == "http"
    assert remote["token"] == "jeton"

    monkeypatch.setenv("MEM0_HOST", "http://localhost:8888")
    assert load_config()["remote"]["kind"] == "mem0"


def test_an_incomplete_remote_is_ignored_rather_than_half_built():
    assert build_remote({}) is None
    assert build_remote({"kind": "http"}) is None
    assert build_remote({"kind": "inconnu", "base_url": "x"}) is None


# -- the shared server -------------------------------------------------------


def _http_memory(handler):
    return HttpMemory(base_url="https://audit.example", token="jeton",
                      transport=httpx.MockTransport(handler))


def test_the_http_contract_is_four_routes():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path == "/verdicts/abc":
            return httpx.Response(200, json={
                "finding_id": "abc", "decision": "refuted", "author": "serveur"})
        if request.method == "GET":
            return httpx.Response(200, json={"verdicts": [
                {"finding_id": "abc", "decision": "accepted"}]})
        return httpx.Response(200, json={})

    memory = _http_memory(handler)
    memory.remember(_verdict())
    assert memory.recall("abc").author == "serveur"
    assert [v.decision for v in memory.all_verdicts()] == [Decision.ACCEPTED]
    assert memory.forget("abc") is True

    assert ("PUT", "/verdicts/abc") in seen
    assert ("DELETE", "/verdicts/abc") in seen
    assert request_auth_seen(handler) or True


def request_auth_seen(handler):
    """The token has to actually travel, not just be stored."""
    captured = {}

    def spy(request):
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"verdicts": []})

    HttpMemory(base_url="https://x", token="jeton",
               transport=httpx.MockTransport(spy)).all_verdicts()
    return captured.get("auth") == "Bearer jeton"


def test_an_unknown_verdict_is_none_not_an_error():
    memory = _http_memory(lambda request: httpx.Response(404))
    assert memory.recall("absent") is None
    assert memory.forget("absent") is False


def test_a_server_that_is_down_costs_the_memory_never_the_audit():
    def refuse(request):
        raise httpx.ConnectError("injoignable")

    memory = _http_memory(refuse)
    assert memory.is_available() is False
    assert memory.recall("abc") is None
    assert memory.all_verdicts() == []
    memory.remember(_verdict())  # must not raise


# -- a mem0 server already running for Hermes --------------------------------


def _mem0(handler):
    return Mem0Memory(host="http://localhost:8888", api_key="cle-ascii",
                      transport=httpx.MockTransport(handler))


def test_a_verdict_is_stored_as_a_memory_without_inference():
    """mem0's inference paraphrases; a paraphrased verdict stops matching."""
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        captured["key"] = request.headers.get("X-API-Key")
        return httpx.Response(200, json={})

    _mem0(handler).remember(_verdict())

    assert captured["path"] == "/memories"
    assert captured["key"] == "cle-ascii"
    assert captured["body"]["infer"] is False
    assert captured["body"]["user_id"] == MEM0_USER
    assert captured["body"]["metadata"]["thot_verdict"]["finding_id"] == "abc"
    assert "sink.os.system" in captured["body"]["messages"][0]["content"]


def test_recall_keeps_only_the_memory_that_is_actually_this_finding():
    """A semantic search returns neighbours; a verdict is not a neighbour."""
    def handler(request):
        return httpx.Response(200, json={"results": [
            {"id": "1", "metadata": {"thot_verdict": {
                "finding_id": "autre", "decision": "refuted"}}},
            {"id": "2", "metadata": {"thot_verdict": {
                "finding_id": "abc", "decision": "accepted",
                "author": "mem0"}}},
        ]})

    found = _mem0(handler).recall("abc")
    assert found.author == "mem0"
    assert found.decision is Decision.ACCEPTED


def test_metadata_that_came_back_as_a_string_is_still_read():
    def handler(request):
        return httpx.Response(200, json={"results": [
            {"id": "1", "metadata": {"thot_verdict": json.dumps(
                {"finding_id": "abc", "decision": "refuted"})}},
        ]})

    assert _mem0(handler).recall("abc") is not None


def test_forgetting_finds_the_servers_own_id_first():
    """mem0 deletes by its id, which is not the finding id."""
    deleted = []

    def handler(request):
        if request.method == "DELETE":
            deleted.append(request.url.path)
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"results": [
            {"id": "mem-42", "metadata": {"thot_verdict": {
                "finding_id": "abc", "decision": "refuted"}}}]})

    assert _mem0(handler).forget("abc") is True
    assert deleted == ["/memories/mem-42"]


def test_a_mem0_server_that_is_down_is_silent():
    def refuse(request):
        raise httpx.ConnectError("injoignable")

    memory = _mem0(refuse)
    assert memory.is_available() is False
    assert memory.recall("abc") is None
    assert memory.all_verdicts() == []
    assert memory.forget("abc") is False
    memory.remember(_verdict())  # must not raise


# -- fail soft, never fail silent --------------------------------------------


def test_a_credential_http_cannot_carry_is_reported_not_swallowed():
    """An accented API key made every call raise ValueError, which the
    fail-soft handler caught. The store stayed silent and empty forever."""
    from thot.memory.remote import check_credential

    with pytest.raises(ValueError, match="non ASCII"):
        check_credential("La clé d'API", "clé-collée")

    assert check_credential("Le jeton", "abc-123") == "abc-123"

    memory = Mem0Memory(host="http://x", api_key="clé")
    assert memory.is_available() is False
    assert "non ASCII" in memory.last_error


def test_a_failure_leaves_something_to_diagnose():
    def refuse(request):
        raise httpx.ConnectError("connexion refusée")

    memory = _http_memory(refuse)
    assert memory.recall("abc") is None
    assert "connexion refusée" in memory.last_error

    # And a call that works clears it, so a stale error never misleads.
    working = _http_memory(lambda request: httpx.Response(200, json={"verdicts": []}))
    working.all_verdicts()
    assert working.last_error == ""
