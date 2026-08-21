"""What a session cost, and what is filling its window."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from thot.state import SessionStore, context_breakdown


@dataclass
class M:
    role: str
    content: str


@pytest.fixture
def store(tmp_path):
    store = SessionStore.open(tmp_path / "s.db")
    yield store
    store.close()


def test_usage_accumulates_across_turns(store):
    session_id = store.start("/repo")
    store.charge(session_id, 1200, 300)
    store.charge(session_id, 800, 150)

    usage = store.usage(session_id)
    assert (usage.input_tokens, usage.output_tokens, usage.calls) == (2000, 450, 2)
    assert usage.total == 2450
    assert "2 appel(s)" in usage.describe()


def test_a_session_with_no_model_call_says_so(store):
    assert store.usage(store.start("/repo")).describe() == "aucun appel modèle"


def test_usage_can_be_read_per_repository_and_overall(store):
    here = store.start("/repo-a")
    there = store.start("/repo-b")
    store.charge(here, 100, 10)
    store.charge(there, 500, 50)

    assert store.usage_across("/repo-a").total == 110
    assert store.usage_across().total == 660


def test_the_columns_are_added_to_an_existing_database(tmp_path):
    """Additive migration: an older file must open and gain the columns."""
    import sqlite3

    from thot.state import schema

    path = tmp_path / "vieux.db"
    connection = sqlite3.connect(path)
    connection.executescript(schema.SCHEMA_SQL)
    connection.execute(
        "INSERT INTO sessions (id, root, title, model, started_at) "
        "VALUES ('vieille', '/r', 't', '', '2026-01-01')"
    )
    connection.commit()
    connection.close()

    store = SessionStore.open(path)
    assert store.usage("vieille").calls == 0
    store.charge("vieille", 10, 5)
    assert store.usage("vieille").total == 15
    store.close()


# -- what is in the window ----------------------------------------------------


def test_the_breakdown_names_the_part_you_can_do_something_about():
    slices = context_breakdown(brief="x" * 4000, messages=[M("user", "y" * 400)])
    labels = [s.label for s in slices]

    assert labels[0] == "carte du dépôt", "le plus gros d'abord"
    assert "thotignore" in slices[0].detail
    assert "messages · user" in labels


def test_the_breakdown_is_empty_when_nothing_is_loaded():
    assert context_breakdown() == []


def test_roles_are_counted_separately():
    slices = context_breakdown(messages=[
        M("user", "a" * 400), M("tool", "b" * 4000), M("tool", "c" * 400),
    ])
    by_label = {s.label: s for s in slices}

    assert by_label["messages · tool"].tokens > by_label["messages · user"].tokens
    assert "2 message(s)" in by_label["messages · tool"].detail
