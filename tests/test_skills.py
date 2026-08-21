"""Skill discovery, in the format Hermes Agent and Prime Agent both use.

A skill is a SKILL.md with YAML frontmatter. Thot ships a library of them,
the user can add their own, and a repository can carry skills specific to it.
Anything written for Hermes or Prime loads here unmodified.
"""

from __future__ import annotations

import pytest

from thot.skills import loader


def write_skill(directory, name, description="fait des choses", body="# Corps\n", extra=""):
    folder = directory / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n{extra}---\n\n{body}",
        encoding="utf-8",
    )
    return folder


def test_a_flat_directory_of_skills_is_read(tmp_path):
    write_skill(tmp_path, "refine")
    write_skill(tmp_path, "goal")
    found = loader.load_from(tmp_path)
    assert {s.name for s in found} == {"refine", "goal"}


def test_hermes_style_categories_are_read(tmp_path):
    write_skill(tmp_path / "software-development", "plan")
    write_skill(tmp_path / "review", "sdlc-review")
    found = loader.load_from(tmp_path)
    assert {s.name for s in found} == {"plan", "sdlc-review"}
    assert {s.category for s in found} == {"software-development", "review"}


def test_the_body_is_kept_separate_from_the_frontmatter(tmp_path):
    write_skill(tmp_path, "plan", body="# Plan\n\nÉcris un plan.\n")
    skill = loader.load_from(tmp_path)[0]
    assert skill.description == "fait des choses"
    assert "Écris un plan." in skill.body
    assert "---" not in skill.body


def test_metadata_survives(tmp_path):
    write_skill(tmp_path, "plan", extra="version: 1.2.0\nauthor: Quelqu'un\n")
    skill = loader.load_from(tmp_path)[0]
    assert skill.metadata.get("version") == "1.2.0"
    assert skill.metadata.get("author") == "Quelqu'un"


def test_a_skill_without_frontmatter_is_skipped(tmp_path):
    folder = tmp_path / "cassé"
    folder.mkdir()
    (folder / "SKILL.md").write_text("Juste du texte, pas de frontmatter.\n")
    assert loader.load_from(tmp_path) == []


def test_broken_yaml_does_not_stop_the_others(tmp_path):
    folder = tmp_path / "cassé"
    folder.mkdir()
    (folder / "SKILL.md").write_text("---\nname: [\n---\ncorps\n")
    write_skill(tmp_path, "bon")
    assert [s.name for s in loader.load_from(tmp_path)] == ["bon"]


def test_a_missing_directory_is_empty_not_an_error(tmp_path):
    assert loader.load_from(tmp_path / "absent") == []


def test_later_sources_override_earlier_ones_by_name(tmp_path):
    library = tmp_path / "library"
    personal = tmp_path / "personal"
    write_skill(library, "plan", description="version livrée")
    write_skill(personal, "plan", description="ma version")
    found = loader.discover(sources=[library, personal])
    assert len(found) == 1
    assert found[0].description == "ma version"


def test_the_bundled_library_is_found_and_non_empty():
    """The skills ported from Hermes must actually ship."""
    found = loader.bundled()
    names = {s.name for s in found}
    assert "systematic-debugging" in names
    assert "test-driven-development" in names
    assert len(found) >= 10


def test_every_bundled_skill_has_a_usable_description():
    for skill in loader.bundled():
        assert skill.description.strip(), f"{skill.name} n'a pas de description"
        assert skill.body.strip(), f"{skill.name} n'a pas de corps"


def test_a_catalogue_line_is_short_enough_to_brief_with(tmp_path):
    write_skill(tmp_path, "plan", description="x" * 500)
    line = loader.load_from(tmp_path)[0].summary()
    assert len(line) < 220
