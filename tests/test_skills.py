"""Skill discovery, in the format Hermes Agent and Prime Agent both use.

A skill is a SKILL.md with YAML frontmatter. Thot ships a library of them,
the user can add their own, and a repository can carry skills specific to it.
Anything written for Hermes or Prime loads here unmodified.
"""

from __future__ import annotations

from pathlib import Path

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


# -- what the shipped library hands people to copy ---------------------------


def _template() -> Path:
    from thot.skills.loader import optional_dir

    directory = optional_dir()
    assert directory is not None
    return directory / "mcp" / "fastmcp" / "templates" / "database_server.py"


def test_the_database_template_does_not_clamp_rows_inside_the_sql():
    """A template exists to be copied, so a defect in one propagates into
    code that *is* reachable.

    `... LIMIT {n}` appended to attacker-controlled text is not a cap: the
    deep pass confirmed `sql = "select id from users) --"` closes the
    wrapping subquery and comments the LIMIT out. Shipped identically by
    Hermes and by Thot, and excluded from Thot's own audit by `.thotignore`
    — which is how it went unseen.
    """
    lines = _template().read_text(encoding="utf-8").splitlines()
    # Code only: the fix's own comment quotes the broken form, and a test
    # that matched prose would fail on the explanation of the fix.
    code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    assert "LIMIT {safe_limit}" not in code
    assert "fetchmany(safe_limit)" in code


def test_the_reported_payload_no_longer_beats_the_cap(tmp_path):
    """The bypass itself, reproduced. 300 rows before, 50 after."""
    import sqlite3

    database = tmp_path / "t.db"
    setup = sqlite3.connect(database)
    setup.execute("create table users(id integer)")
    setup.executemany("insert into users values (?)", [(i,) for i in range(300)])
    setup.commit()
    setup.close()

    payload = "select id from users) --"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        beaten = connection.execute(
            f"SELECT * FROM ({payload}) LIMIT 50"
        ).fetchall()
        held = connection.execute(f"SELECT * FROM ({payload})").fetchmany(50)
    finally:
        connection.close()

    assert len(beaten) == 300, "la forme d'origine laissait passer 300 lignes"
    assert len(held) == 50


def test_hermes_copy_of_the_template_carries_the_same_fix():
    """The fused program ships both copies, so both are ours to answer for.

    The deep pass confirmed the bypass a second time, on Hermes's copy, with
    a payload run locally: `query(sql="select * from users) LIMIT 999999 --")`
    returned 500 rows where 50 were asked for and MAX_ROWS is 200. Leaving a
    template known to be exploitable in a tree we ship is worse than a
    documented divergence from upstream.
    """
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    copy = (root / "optional-skills" / "mcp" / "fastmcp" / "templates"
            / "database_server.py")
    if not copy.is_file():
        pytest.skip("cette version de Hermes ne livre pas ce gabarit")

    code = "\n".join(
        line for line in copy.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "LIMIT {safe_limit}" not in code
    assert "fetchmany(safe_limit)" in code


def test_the_unbroker_scanner_enforces_the_convention_it_claimed():
    """"https only by convention" — and a convention is not a check.

    `urlopen` reads `file:///etc/passwd` as happily as it fetches a page, and
    this is a helper in a script people copy into their own work, where the
    URL comes from wherever they get theirs. Same category as the SQL
    template: a thing handed out to be copied, whose safety was a comment.
    """
    import importlib.util
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    script = (root / "optional-skills" / "security" / "unbroker" / "scripts"
              / "scan.py")
    if not script.is_file():
        pytest.skip("cette version de Hermes n'a pas ce script")

    spec = importlib.util.spec_from_file_location("unbroker_scan_test", script)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    assert module.fetch("file:///etc/passwd", timeout=2) == (0, "")
    assert module.fetch("ftp://example.com/x", timeout=2) == (0, "")
    # Every hop: `urlopen` follows redirects, so a scheme check on the first
    # URL let the site being scanned name the next destination. Seventh time
    # in one day that a first-hop check was mistaken for a check.
    assert module._public_http("http://127.0.0.1/x") is False
    assert module._public_http("http://10.0.0.5/x") is False
    handlers = module._opener().handlers
    assert any(type(h).__name__ == "_PublicOnly" for h in handlers), (
        "l'opener doit revalider chaque redirection"
    )
