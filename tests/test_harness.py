"""What Thot has learned about a codebase, kept between sessions.

Prime Agent calls the act refinement. For an audit tool the entries are
facts no static analysis will ever derive — which wrapper sanitises, which
directory is generated, which framework the taint engine cannot see.
"""

from __future__ import annotations

import json

import pytest

from thot.harness import Harness


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path / "local.json", tmp_path / "global.json")


def test_an_entry_survives_a_reopen(tmp_path):
    first = Harness(tmp_path / "l.json", tmp_path / "g.json")
    first.remember(title="generated/", content="régénéré à chaque build")

    again = Harness(tmp_path / "l.json", tmp_path / "g.json")
    assert [e.title for e in again.all()] == ["generated/"]


def test_the_repository_outranks_what_you_assume_everywhere(harness):
    harness.remember(title="tests", content="npm test", scope="global")
    harness.remember(title="tests", content="pytest -q", scope="local")

    entries = harness.all()
    assert len(entries) == 2, "les deux existent, dans leurs fichiers respectifs"
    local = [e for e in entries if e.scope == "local"]
    assert local[0].content == "pytest -q"


def test_the_same_title_updates_rather_than_accumulating(harness):
    first = harness.remember(title="team.shell", content="ancienne note")
    second = harness.remember(title="Team.Shell", content="nouvelle note")

    assert first.id == second.id
    assert [e.content for e in harness.all()] == ["nouvelle note"]


def test_the_briefing_is_empty_when_nothing_was_learned(harness):
    assert harness.brief() == ""


def test_the_briefing_names_what_it_knows(harness):
    harness.remember(title="team.shell.run",
                     content="échappe ses arguments avec shlex.quote")

    brief = harness.brief()
    assert "Ce que tu sais déjà" in brief
    assert "shlex.quote" in brief


def test_the_briefing_is_bounded(harness):
    for index in range(40):
        harness.remember(title=f"fait {index:02d}", content="x")

    assert len(harness.brief().splitlines()) <= 13


def test_an_empty_title_or_content_is_refused(harness):
    with pytest.raises(ValueError):
        harness.remember(title="", content="quelque chose")
    with pytest.raises(ValueError):
        harness.remember(title="titre", content="   ")


def test_content_is_clipped_so_a_briefing_stays_a_briefing(harness):
    from thot.harness import MAX_CONTENT

    entry = harness.remember(title="long", content="x" * 5000)
    assert len(entry.content) <= MAX_CONTENT


def test_forgetting_reaches_both_scopes(harness):
    local = harness.remember(title="a", content="x")
    other = harness.remember(title="b", content="y", scope="global")

    assert harness.forget(local.id) is True
    assert harness.forget(other.id) is True
    assert harness.forget("inconnu") is False
    assert harness.all() == []


def test_the_local_file_is_written_where_a_team_can_review_it(tmp_path):
    harness = Harness.open(tmp_path)
    harness.remember(title="a", content="x")

    written = tmp_path / ".thot" / "harness.json"
    assert written.is_file()
    body = json.loads(written.read_text(encoding="utf-8"))
    assert body["format"] == "thot.harness"
    assert body["entries"][0]["title"] == "a"


def test_a_corrupt_file_is_an_empty_harness_not_a_crash(tmp_path):
    (tmp_path / "l.json").write_text("{ pas du json")
    assert Harness(tmp_path / "l.json", tmp_path / "g.json").all() == []


def test_an_unknown_kind_falls_back_rather_than_raising(harness):
    assert harness.remember(title="a", content="x", kind="licorne").kind == "memory"
