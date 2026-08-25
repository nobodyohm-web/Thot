"""Sessions that survive the terminal being closed.

Every test here answers a question a user would ask out loud: is my work
still there tomorrow, can I find it again, and can I take it with me.
"""

from __future__ import annotations

import json

import pytest

from thot.state import SessionStore, export_session, import_session, write_export
from thot.state.search import CLOSE, OPEN, to_match_query


@pytest.fixture
def store(tmp_path):
    store = SessionStore.open(tmp_path / "sessions.db")
    yield store
    store.close()


def test_a_session_survives_the_process(tmp_path):
    path = tmp_path / "sessions.db"
    first = SessionStore.open(path)
    session_id = first.start("/repo")
    first.append(session_id, "user", "où sont les injections ?")
    first.close()

    reopened = SessionStore.open(path)
    assert [t.content for t in reopened.turns(session_id)] == [
        "où sont les injections ?"
    ]
    reopened.close()


def test_the_first_question_becomes_the_title(store):
    session_id = store.start("/repo")
    store.append(session_id, "user", "audite   le   parseur JSON")
    store.append(session_id, "user", "et le reste")

    info = store.info(session_id)
    assert info.title == "audite le parseur JSON"  # whitespace normalised, not reset


def test_search_finds_what_was_said_and_what_was_found(store):
    session_id = store.start("/repo")
    store.append(session_id, "user", "regarde le module de déploiement")
    store.note(session_id, "audit · HIGH sink.os.system app/deploy.py:7")

    assert [h.role for h in store.find("déploiement")] == ["user"]

    audit = store.find("sink.os.system")
    assert len(audit) == 1
    assert "app/deploy.py:7" in audit[0].plain()


def test_a_query_that_is_not_an_fts_expression_still_searches(store):
    """`run_command(` makes FTS5 raise, and the raise reads as 'no results'."""
    session_id = store.start("/repo")
    store.append(session_id, "assistant", "run_command( est appelé par main")

    assert store.searchable, "ce test ne prouve rien sans FTS5"
    assert to_match_query("run_command(") == '"run_command"'
    hits = store.find("run_command(")
    assert len(hits) == 1


def test_search_falls_back_to_substring_without_fts5(store):
    store.searchable = False
    session_id = store.start("/repo")
    store.append(session_id, "user", "le chemin de teinte part de argv")

    hits = store.find("teinte")
    assert len(hits) == 1
    assert OPEN in hits[0].snippet and CLOSE in hits[0].snippet
    assert "teinte" in hits[0].plain()


def test_search_can_be_scoped_to_one_repository(store):
    here = store.start("/repo-a")
    there = store.start("/repo-b")
    store.append(here, "user", "faille dans le routeur")
    store.append(there, "user", "faille dans le routeur")

    assert len(store.find("faille")) == 2
    assert [h.session_id for h in store.find("faille", root="/repo-a")] == [here]


def test_compacting_keeps_the_parent_whole(store):
    parent = store.start("/repo")
    store.append(parent, "user", "trois heures de travail")

    child = store.branch(parent, "conclusion : une faille confirmée")

    assert store.info(parent).ended_at, "la session compactée doit être close"
    assert store.info(child).parent_id == parent
    assert [i.id for i in store.ancestry(child)] == [parent, child]
    # The evidence is still there, not replaced by its summary.
    assert [t.content for t in store.turns(parent)] == ["trois heures de travail"]
    assert [t.content for t in store.turns(child)] == [
        "conclusion : une faille confirmée"
    ]


def test_resume_reopens_a_closed_session(store):
    session_id = store.start("/repo")
    store.end(session_id)
    assert not store.info(session_id).live

    store.reopen(session_id)
    assert store.info(session_id).live


def test_a_short_id_is_enough_when_it_is_unambiguous(store):
    session_id = store.start("/repo")
    assert store.resolve(session_id[:8]) == session_id
    assert store.resolve("zzzz") is None


def test_export_carries_the_chain_not_just_the_summary(store, tmp_path):
    parent = store.start("/repo", model="opus")
    store.append(parent, "user", "la preuve est ici")
    child = store.branch(parent, "résumé")

    payload = export_session(store, child)
    assert [s["id"] for s in payload["sessions"]] == [parent, child]
    assert payload["sessions"][0]["messages"][0]["content"] == "la preuve est ici"

    written = write_export(store, child, tmp_path / "out.json")
    assert json.loads(written.read_text())["format"] == "thot.sessions"


def test_import_never_overwrites_an_existing_session(store):
    original = store.start("/repo")
    store.append(original, "user", "unique")
    payload = export_session(store, original)

    created = import_session(store, payload)

    assert created[0] != original, "un import ne doit jamais écraser l'original"
    assert store.info(original) is not None
    assert "unique" in [t.content for t in store.turns(created[0])]


def test_import_rewrites_the_chain_to_the_new_ids(store):
    parent = store.start("/repo")
    store.append(parent, "user", "preuve")
    child = store.branch(parent, "résumé")

    created = import_session(store, export_session(store, child))

    assert store.info(created[1]).parent_id == created[0]
    assert [i.id for i in store.ancestry(created[1])] == created


def test_a_foreign_or_newer_export_is_refused_by_name(store):
    with pytest.raises(ValueError, match="export Thot"):
        import_session(store, {"format": "autre.chose", "sessions": []})

    with pytest.raises(ValueError, match="version"):
        import_session(store, {"format": "thot.sessions", "version": 99, "sessions": []})


def test_forgetting_a_session_takes_its_messages_with_it(store):
    session_id = store.start("/repo")
    store.append(session_id, "user", "à oublier")

    assert store.forget(session_id) is True
    assert store.info(session_id) is None
    assert store.find("à oublier") == []


def test_stats_say_how_search_is_actually_being_done(store):
    store.start("/repo")
    stats = store.stats()
    assert stats["sessions"] == 1
    assert stats["search"] in {"fts5", "substring"}


def test_an_empty_session_is_counted_but_not_listed(tmp_path, capsys):
    """A session where nothing was said is dropped on the way out — but a
    process that is killed cannot drop anything, and those rows are noise
    rather than history."""
    import argparse

    from thot.cli import _cmd_sessions
    from thot.state import SessionStore

    store = SessionStore.open()
    try:
        empty = store.start(root=str(tmp_path), title="")
        spoken = store.start(root=str(tmp_path), title="vrai travail")
        store.append(spoken, "user", "bonjour")
    finally:
        store.close()

    _cmd_sessions(argparse.Namespace(forget=None, show=None, all=True,
                                     path=str(tmp_path)))
    printed = capsys.readouterr().out

    assert spoken[:8] in printed
    assert empty[:8] not in printed
    assert "1 session(s) vide(s) non listée(s)" in printed


def test_search_finds_messages_written_before_the_index_existed(tmp_path, monkeypatch):
    """A base born on a SQLite without FTS5, reopened on one that has it.

    The dangerous shape: the index answers, so the LIKE fallback never runs,
    and everything older than the index is silently absent.
    """
    from thot.state import schema

    path = tmp_path / "sessions.db"
    monkeypatch.setattr(schema, "has_fts5", lambda connection: False)
    blind = SessionStore.open(path)
    old = blind.start("/repo")
    blind.append(old, "user", "une injection ancienne")
    blind.close()
    monkeypatch.undo()

    store = SessionStore.open(path)
    try:
        assert store.searchable, "ce test ne prouve rien sans FTS5"
        recent = store.start("/repo")
        store.append(recent, "user", "une injection récente")
        assert sorted(h.session_id for h in store.find("injection")) == sorted(
            [old, recent]
        )
    finally:
        store.close()


def test_forgetting_a_session_written_before_the_index_existed_still_works(
    tmp_path, monkeypatch
):
    from thot.state import schema

    path = tmp_path / "sessions.db"
    monkeypatch.setattr(schema, "has_fts5", lambda connection: False)
    blind = SessionStore.open(path)
    old = blind.start("/repo")
    blind.append(old, "user", "à oublier")
    blind.close()
    monkeypatch.undo()

    store = SessionStore.open(path)
    try:
        assert store.forget(old) is True
        assert store.info(old) is None
    finally:
        store.close()


def test_a_failed_forget_leaves_the_session_whole(store):
    """The half-deleted state is worse than the failure: a session row gone
    with its messages still on disk is unreachable and unpurgeable."""
    import sqlite3

    session_id = store.start("/repo")
    store.append(session_id, "user", "à oublier")
    # Emptying the external-content index makes the AFTER DELETE trigger fail,
    # which is what a base that predates the index does on its own.
    store._connection.execute(
        "INSERT INTO messages_fts(messages_fts) VALUES('delete-all')"
    )
    store._connection.commit()

    with pytest.raises(sqlite3.DatabaseError):
        store.forget(session_id)

    store.start("/repo")  # any later write commits whatever is still pending
    assert store.info(session_id) is not None
    assert [t.content for t in store.turns(session_id)] == ["à oublier"]


def test_full_text_search_cuts_before_it_sorts(store):
    """Twenty rows must not cost a sort over every match in the memory."""
    session_id = store.start("/repo")
    for index in range(40):
        store.append(session_id, "user", f"injection numéro {index}")

    statements: list[str] = []
    store._connection.set_trace_callback(statements.append)
    try:
        store.find("injection", limit=20)
    finally:
        store._connection.set_trace_callback(None)

    executed = [s for s in statements if "MATCH" in s]
    assert len(executed) == 1, executed
    plan = store._connection.execute(
        "EXPLAIN QUERY PLAN " + executed[0]
    ).fetchall()
    assert not any("TEMP B-TREE" in str(row[3]) for row in plan), plan


def test_a_scoped_search_fills_its_limit_from_that_repository(store):
    """Cutting early must not cut on the unscoped set: the noisy repo would
    eat the whole budget and `thot search` (scoped to cwd) would go blind."""
    noisy = store.start("/repo-a")
    wanted = store.start("/repo-b")
    for index in range(22):
        store.append(wanted, "user", f"injection cherchée {index}")
    for index in range(40):
        store.append(noisy, "user", f"injection bruyante {index}")
    # A handful of recent ones here too, so the unscoped twenty newest are
    # mostly the other repo's — and the LIKE fallback, which only runs on an
    # empty answer, cannot paper over the truncation.
    for index in range(22, 25):
        store.append(wanted, "user", f"injection cherchée {index}")

    hits = store.find("injection", root="/repo-b", limit=20)
    assert len(hits) == 20
    assert {h.session_id for h in hits} == {wanted}


def test_the_substring_fallback_finds_names_with_underscores(store):
    """`find_symbol` and `run_command` are the names one searches for in a
    Python repository; stripping `_` made every one of them unfindable."""
    store.searchable = False
    session_id = store.start("/repo")
    store.append(session_id, "user", "find_symbol est appelé par run_command")

    hits = store.find("find_symbol")
    assert len(hits) == 1
    assert "find_symbol" in hits[0].plain()


def test_the_substring_fallback_does_not_read_an_underscore_as_a_wildcard(store):
    store.searchable = False
    session_id = store.start("/repo")
    store.append(session_id, "user", "findXsymbol n'est pas find_symbol")
    other = store.start("/repo")
    store.append(other, "user", "findYsymbol seulement")

    assert [h.session_id for h in store.find("find_symbol")] == [session_id]


def _comparable(payload: dict) -> list[dict]:
    """An export stripped of what is allowed to differ between two of them."""
    return [
        {key: value for key, value in session.items()
         if key not in {"id", "parent_id"}}
        for session in payload["sessions"]
    ]


def test_an_export_round_trip_is_lossless_and_idempotent(store):
    parent = store.start("/repo", model="opus")
    store.append(parent, "user", "la preuve est ici")
    store.append(parent, "assistant", "je regarde")
    child = store.branch(parent, "résumé")
    store.end(child)

    first = export_session(store, child)
    second = export_session(store, import_session(store, first)[-1])

    assert _comparable(second) == _comparable(first)


def test_an_import_keeps_the_moments_it_was_given(store):
    """A conversation carried to another machine is dated when it happened."""
    payload = {
        "format": "thot.sessions",
        "version": 1,
        "sessions": [
            {
                "id": "ancienne",
                "root": "/repo",
                "title": "hier",
                "model": "",
                "parent_id": "",
                "started_at": "2024-01-02T03:04:05+00:00",
                "ended_at": "2024-01-02T09:00:00+00:00",
                "messages": [
                    {
                        "seq": 0,
                        "role": "user",
                        "content": "hier",
                        "tool_name": "",
                        "created_at": "2024-01-02T03:04:06+00:00",
                    }
                ],
            }
        ],
    }

    imported = import_session(store, payload)[0]

    info = store.info(imported)
    assert info.started_at == "2024-01-02T03:04:05+00:00"
    assert info.ended_at == "2024-01-02T09:00:00+00:00"
    carried = [t for t in store.turns(imported) if t.role != "meta"]
    assert [t.created_at for t in carried] == ["2024-01-02T03:04:06+00:00"]
