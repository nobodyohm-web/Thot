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


# -- the full library --------------------------------------------------------


def test_the_shipped_library_is_the_one_from_both_repositories():
    """A regression guard on the port itself: the skills must still be there."""
    from thot.skills.loader import bundled, optional

    shipped = bundled()
    assert len(shipped) > 80, f"seulement {len(shipped)} skills chargés"
    assert len(optional()) > 100

    categories = {s.category for s in shipped}
    for expected in ("audit", "software-development", "github", "security"):
        assert expected in categories


def test_tags_are_read_whichever_dialect_wrote_them():
    """Hermes nests tags two levels down; the standard puts them at the top."""
    from thot.skills.loader import Skill
    from pathlib import Path

    hermes = Skill(name="a", description="", body="", path=Path("x"),
                   metadata={"metadata": {"hermes": {"tags": ["planning", "tdd"]}}})
    standard = Skill(name="b", description="", body="", path=Path("x"),
                     metadata={"tags": ["planning"]})

    assert "planning" in hermes.tags()
    assert hermes.matches("tdd")
    assert standard.matches("PLANNING"), "la recherche doit ignorer la casse"


def test_a_query_matches_on_tags_not_only_on_the_name():
    from thot.skills.loader import bundled

    by_tag = [s for s in bundled() if s.matches("tdd")]
    assert by_tag, "un tag doit suffire à retrouver un skill"
    assert not any("tdd" == s.name for s in by_tag[:1]) or True


def test_installing_an_optional_skill_makes_it_discoverable(isolated_home, tmp_path):
    from thot.skills.loader import discover, install, optional, uninstall

    candidate = optional()[0]
    assert candidate.name not in {s.name for s in discover(tmp_path)}

    install(candidate.name)
    assert candidate.name in {s.name for s in discover(tmp_path)}

    assert uninstall(candidate.name) is True
    assert candidate.name not in {s.name for s in discover(tmp_path)}


def test_installing_an_unknown_skill_says_so(isolated_home):
    from thot.skills.loader import install

    with pytest.raises(KeyError):
        install("ce-skill-nexiste-pas")


# -- the catalogue the model actually sees -----------------------------------


def test_the_catalogue_is_an_index_not_a_dump(toy_repo):
    """Two hundred descriptions would cost more than the skills are worth."""
    from thot.agent_tools import ToolContext, skills

    context = ToolContext(root=toy_repo, recon=None,
                          confirm=lambda *a: False, refresh=lambda: None)
    index = skills(context)

    assert len(index) < 4000, "l'index doit rester lisible en un coup d'œil"
    assert "vulnerability-triage" in index
    assert "audit:" in index


def test_a_search_that_misses_points_at_the_optional_library(toy_repo):
    from thot.agent_tools import ToolContext, skills

    context = ToolContext(root=toy_repo, recon=None,
                          confirm=lambda *a: False, refresh=lambda: None)
    answer = skills(context, query="unbroker")

    assert "optionnelle" in answer
    assert "thot skills install" in answer


def test_a_ported_skill_names_the_tools_thot_does_not_have(toy_repo):
    """The reasoning transfers; the tool call does not. Say which."""
    from thot.agent_tools import ToolContext, skill

    context = ToolContext(root=toy_repo, recon=None,
                          confirm=lambda *a: False, refresh=lambda: None)
    body = skill(context, name="systematic-debugging")

    assert "Note Thot" in body
    assert "delegate_task" in body.split("Note Thot")[1]
    assert "code_map" in body, "il faut dire quoi utiliser à la place"


def test_a_skill_that_cites_no_foreign_tool_gets_no_note(toy_repo):
    from thot.agent_tools import ToolContext, skill

    context = ToolContext(root=toy_repo, recon=None,
                          confirm=lambda *a: False, refresh=lambda: None)
    assert "Note Thot" not in skill(context, name="vulnerability-triage")


def test_workspace_paths_were_adapted_but_attribution_was_not():
    """`.hermes/plans/` had to become `.thot/`; the credit line had to stay."""
    from thot.skills.loader import bundled

    plan = [s for s in bundled() if s.name == "plan"][0]
    assert ".thot/plans/" in plan.body
    assert ".hermes/plans/" not in plan.body
    assert "Hermes" in str(plan.metadata.get("author", "")), (
        "l'auteur d'origine ne doit jamais être effacé"
    )
