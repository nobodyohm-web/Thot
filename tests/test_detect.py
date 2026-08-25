from thot.scope.detect import detect_scope


def test_python_files_are_collected(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src/app.py" in manifest.files
    assert "src/safe.py" in manifest.files


def test_excluded_directories_are_skipped(toy_repo):
    manifest = detect_scope(toy_repo)
    assert not any(f.startswith("node_modules/") for f in manifest.files)


def test_languages_are_counted(toy_repo):
    manifest = detect_scope(toy_repo)
    assert manifest.languages["python"] == 2


def test_main_is_detected_as_entrypoint(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src.app.main" in manifest.entrypoints


def test_paths_are_relative_never_absolute(toy_repo):
    manifest = detect_scope(toy_repo)
    assert all(not f.startswith("/") for f in manifest.files)


# -- .thotignore -------------------------------------------------------------


def test_a_repository_can_exclude_what_it_did_not_write(tmp_path):
    """Vendored code produces noise that hides findings, not findings."""
    from thot.scope.detect import detect_scope

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "vendored").mkdir()
    (tmp_path / "vendored" / "lib.py").write_text("y = 2\n")
    (tmp_path / ".thotignore").write_text("vendored/\n")

    files = detect_scope(tmp_path).files
    assert "src/app.py" in files
    assert "vendored/lib.py" not in files


def test_comments_and_blank_lines_are_not_patterns(tmp_path):
    from thot.scope.detect import load_ignore

    (tmp_path / ".thotignore").write_text("# rien\n\n  build/  \n")
    assert load_ignore(tmp_path) == ("build/",)


def test_ignore_patterns_behave_the_way_people_type_them():
    from thot.scope.detect import is_ignored

    patterns = ("skills/", "*.generated.py", "fixtures")

    assert is_ignored("skills/a/b.py", patterns)
    assert is_ignored("skills/x.py", patterns)
    assert is_ignored("src/client.generated.py", patterns)
    # A bare name matches at any depth, the way gitignore does.
    assert is_ignored("tests/fixtures/broken.py", patterns)

    assert not is_ignored("src/skillset.py", patterns)
    assert not is_ignored("src/app.py", patterns)


def test_no_ignore_file_means_no_patterns(tmp_path):
    from thot.scope.detect import load_ignore

    assert load_ignore(tmp_path) == ()


def test_thot_excludes_its_own_ported_library():
    """The port made Thot's own audit unreadable; this is why the file exists."""
    from pathlib import Path

    from thot.scope.detect import load_ignore

    patterns = load_ignore(Path(__file__).resolve().parents[1])
    assert "skills/" in patterns
    assert "optional-skills/" in patterns


# -- l'empreinte de l'arbre, et le parcours qui la produit -------------------
#
# Une carte qui ne se relit jamais ment dès la première écriture de l'agent ;
# une carte qui se refait à chaque question coûte deux minutes sur `hermes/`.
# L'empreinte est ce qui permet les deux : assez bon marché pour être prise à
# chaque appel d'outil, assez fidèle pour dire quand il faut tout revoir.
#
# Elle n'est bon marché que si le parcours n'entre pas dans ce qu'il va de
# toute façon jeter. `.git`, `node_modules`, `.venv` et les dossiers nommés
# par `.thotignore` étaient descendus en entier puis filtrés fichier par
# fichier : sur ce dépôt, dont le `.thotignore` écarte `hermes/` et `prime/`,
# cela coûtait 912 ms pour 196 fichiers retenus.

import os

from thot.scope.detect import iter_source_files, source_versions


def test_the_fingerprint_covers_exactly_what_is_in_scope(toy_repo):
    versions = source_versions(toy_repo)
    walked = sorted(
        p.relative_to(toy_repo).as_posix() for p in iter_source_files(toy_repo)
    )

    assert [relative for relative, _, _ in versions] == walked
    assert all(size > 0 for _, size, _ in versions)


def test_changing_the_ignore_rules_changes_the_fingerprint(toy_repo):
    """Le périmètre fait partie de la version de l'arbre."""
    (toy_repo / ".thotignore").write_text("rien/\n")
    before = source_versions(toy_repo)

    (toy_repo / ".thotignore").write_text("src/safe.py\n")
    after = source_versions(toy_repo)

    assert after != before
    assert not any(r == "src/safe.py" for r, _, _ in after)
    assert any(r == ".thotignore" for r, _, _ in after)


def test_the_fingerprint_ignores_what_the_map_ignores(toy_repo):
    versions = source_versions(toy_repo)

    assert not any(r.startswith("node_modules/") for r, _, _ in versions)


def test_an_untouched_tree_keeps_its_fingerprint(toy_repo):
    assert source_versions(toy_repo) == source_versions(toy_repo)


def test_an_edit_changes_the_fingerprint(toy_repo):
    before = source_versions(toy_repo)
    app = toy_repo / "src" / "app.py"
    app.write_text(app.read_text() + "\n\ndef ajoutee():\n    return 1\n")

    assert source_versions(toy_repo) != before


def test_a_new_file_changes_the_fingerprint(toy_repo):
    before = source_versions(toy_repo)
    (toy_repo / "src" / "nouveau.py").write_text("def neuf():\n    return 1\n")

    assert source_versions(toy_repo) != before


def test_a_deletion_changes_the_fingerprint(toy_repo):
    before = source_versions(toy_repo)
    (toy_repo / "src" / "safe.py").unlink()

    assert source_versions(toy_repo) != before


def test_a_pruned_directory_is_never_descended(toy_repo, monkeypatch):
    """Ce test épingle un coût, pas une forme.

    Le filtrage a posteriori donne la même liste de fichiers ; il la donne
    après avoir énuméré chaque objet de `node_modules`. Rien dans le résultat
    ne le trahit, donc c'est le parcours lui-même qu'il faut regarder.
    """
    (toy_repo / "node_modules" / "profond").mkdir()
    (toy_repo / "node_modules" / "profond" / "encore.py").write_text("x = 1\n")
    (toy_repo / ".thotignore").write_text("exclu/\n")
    (toy_repo / "exclu").mkdir()
    (toy_repo / "exclu" / "dedans.py").write_text("y = 2\n")

    visited: list[str] = []
    real = os.walk

    def watching(top, *args, **kwargs):
        for base, dirnames, filenames in real(top, *args, **kwargs):
            visited.append(os.path.relpath(base, toy_repo))
            yield base, dirnames, filenames

    monkeypatch.setattr(os, "walk", watching)
    list(iter_source_files(toy_repo))

    assert not any(v.startswith("node_modules") for v in visited), visited
    assert not any(v.startswith("exclu") for v in visited), visited


# -- lire les points d'entrée ne doit pas reparser l'arbre -------------------
#
# `detect_scope` parsait chaque fichier Python en AST pour y lire les noms de
# fonctions de premier niveau, puis `index_files` les reparsait tous pour en
# tirer les symboles : deux arbres syntaxiques complets par fichier et par
# balayage. Mesuré sur `hermes/` : 5,4 s des 11 s que coûtait la
# reconstruction d'une carte après le changement d'un seul fichier.


def _counting_parses(monkeypatch) -> list[int]:
    import thot.scope.detect as detect

    seen: list[int] = []
    real = detect.ast.parse

    def counting(source, *args, **kwargs):
        seen.append(len(source))
        return real(source, *args, **kwargs)

    monkeypatch.setattr(detect.ast, "parse", counting)
    return seen


def test_an_unchanged_tree_is_not_parsed_twice_for_entry_points(
    toy_repo, monkeypatch
):
    from thot.scope.detect import forget_entrypoints

    forget_entrypoints()
    parsed = _counting_parses(monkeypatch)

    detect_scope(toy_repo)
    first = len(parsed)
    detect_scope(toy_repo)

    assert first > 0, "le premier balayage n'a rien lu du tout"
    assert len(parsed) == first, "l'arbre a été relu alors que rien n'a bougé"


def test_an_edited_file_is_read_again_for_entry_points(toy_repo, monkeypatch):
    from thot.scope.detect import forget_entrypoints

    forget_entrypoints()
    parsed = _counting_parses(monkeypatch)
    detect_scope(toy_repo)
    parsed.clear()

    app = toy_repo / "src" / "app.py"
    app.write_text(app.read_text() + "\n\ndef run():\n    pass\n")
    manifest = detect_scope(toy_repo)

    assert len(parsed) == 1, parsed
    assert "src.app.run" in manifest.entrypoints


def test_a_new_file_brings_its_own_entry_points(toy_repo):
    from thot.scope.detect import forget_entrypoints

    forget_entrypoints()
    detect_scope(toy_repo)

    (toy_repo / "src" / "worker.py").write_text("def handler(event):\n    pass\n")

    assert "src.worker.handler" in detect_scope(toy_repo).entrypoints


# -- la famille JavaScript au complet ----------------------------------------
#
# Quatre listes de suffixes décrivaient la même famille et divergeaient :
# `ts_indexer.EXTENSIONS` (8), `guard.patterns._JS_EXTS` (10),
# `guard.suppressions.READABLE`, et celle-ci (5). C'est la plus étroite qui
# décide de ce qui existe, puisqu'elle est le seul point de collecte —
# mesuré : `hermes/` 6924 fichiers collectés sur 7080, `prime/` 938 sur 952.


def test_the_modern_javascript_suffixes_are_collected(tmp_path):
    from thot.scope.detect import detect_scope

    for name in ("worker.mjs", "danger.cjs", "types.mts", "legacy.cts"):
        (tmp_path / name).write_text("export const x = 1;\n", encoding="utf-8")

    manifest = detect_scope(tmp_path)

    assert set(manifest.files) == {
        "worker.mjs", "danger.cjs", "types.mts", "legacy.cts",
    }
    assert manifest.languages == {"javascript": 2, "typescript": 2}


def test_a_component_file_is_read_without_claiming_a_taint_engine(tmp_path):
    """`.vue` et `.svelte` passent les règles motif, rien de plus.

    Les compter en `javascript` ferait dire au rapport « teinte au fichier
    près : javascript 2 » alors que ni l'indexeur ni `js_engine` ne lit ces
    suffixes : le mensonge de couverture que la collecte corrige justement.
    """
    from thot.codemap import INDEXED_LANGUAGES
    from thot.scope.detect import detect_scope

    (tmp_path / "Danger.vue").write_text("<script>x=1</script>\n", encoding="utf-8")
    (tmp_path / "Widget.svelte").write_text("<script>y=2</script>\n", encoding="utf-8")

    manifest = detect_scope(tmp_path)

    assert set(manifest.files) == {"Danger.vue", "Widget.svelte"}
    assert manifest.languages == {"vue": 1, "svelte": 1}
    assert not {"vue", "svelte"} & set(INDEXED_LANGUAGES)


def test_every_suffix_a_scanner_can_read_is_collected(tmp_path):
    """Le collecteur ne peut pas être plus étroit que ses consommateurs.

    Sur le modèle de `test_the_whole_javascript_family_is_masked`, qui épingle
    déjà le masqueur sur le catalogue et aurait attrapé la divergence si la
    collecte avait été incluse.
    """
    from thot.codemap.ts_indexer import EXTENSIONS
    from thot.guard.patterns import _JS_EXTS
    from thot.scope.detect import LANGUAGE_BY_SUFFIX

    unreachable = (set(EXTENSIONS) | set(_JS_EXTS)) - set(LANGUAGE_BY_SUFFIX)

    assert unreachable == set(), f"jamais collectés, donc jamais lus : {unreachable}"


# -- ce qu'on indexe et ce qu'on balaie ne sont pas la même liste -----------
#
# `sweep_patterns(root, manifest.files)` ne recevait que les extensions de
# code. Deux conséquences mesurées : la règle `github_actions_workflow` de
# `guard/patterns.py`, qui teste `".github/workflows/" in path`, ne pouvait
# jamais se déclencher pendant un audit ; et les règles de secrets — clés AWS,
# jetons GitHub, en-têtes PEM, URL de connexion — ne voyaient ni un `.env`, ni
# un `.pem`, ni un `docker-compose.yml`. Le commentaire de `pipeline.py`
# annonçait pourtant « JavaScript, YAML, CI workflows ».
#
# Le prix, mesuré avant : +6 fichiers sur Thot, +54 sur Prime, +333 (4 Mo) sur
# Hermes, contre 6 924 fichiers de code.


def test_a_workflow_is_in_scope_without_being_indexed(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: [push]\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")

    manifest = detect_scope(tmp_path)

    assert "app.py" in manifest.files
    assert ".github/workflows/ci.yml" not in manifest.files, (
        "un YAML dans `files` serait passé à l'indexeur AST"
    )
    assert ".github/workflows/ci.yml" in manifest.extra_files


def test_the_files_that_carry_secrets_are_read(tmp_path):
    for nom in ("cle.pem", ".env", "docker-compose.yml", "deploy.sh",
                "config.toml", "reglages.json"):
        (tmp_path / nom).write_text("x\n", encoding="utf-8")

    extra = set(detect_scope(tmp_path).extra_files)

    assert extra == {"cle.pem", ".env", "docker-compose.yml", "deploy.sh",
                     "config.toml", "reglages.json"}


def test_a_file_named_without_a_suffix_still_counts(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "Makefile").write_text("all:\n\techo\n", encoding="utf-8")

    extra = set(detect_scope(tmp_path).extra_files)

    assert {"Dockerfile", "Makefile"} <= extra


def test_a_scanned_file_is_not_counted_as_a_language(tmp_path):
    (tmp_path / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    (tmp_path / "ci.yml").write_text("on: [push]\n", encoding="utf-8")

    manifest = detect_scope(tmp_path)

    assert manifest.languages == {"python": 1}


def test_a_scanned_file_is_ignored_like_any_other(tmp_path):
    (tmp_path / ".thotignore").write_text("secrets/\n", encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "prod.env").write_text("A=1\n", encoding="utf-8")

    assert detect_scope(tmp_path).extra_files == ()


def test_the_fingerprint_notices_a_changed_workflow(tmp_path):
    (tmp_path / "ci.yml").write_text("on: [push]\n", encoding="utf-8")
    before = source_versions(tmp_path)

    (tmp_path / "ci.yml").write_text("on: [pull_request_target]\n", encoding="utf-8")

    assert source_versions(tmp_path) != before, (
        "un fichier balayé qui change doit périmer la carte comme un autre"
    )


# -- web routes as entry points ----------------------------------------------
#
# The most common entry point in Python was covered by none of the five names
# in `ENTRYPOINT_NAMES`, and the cost was not a ranking detail. A taint
# finding is PLAUSIBLE (0.6) and `sink.network` carries MEDIUM impact (0.5);
# with reach unknown that is 0.5 x 0.8 x 0.6 = 0.24 against a MEDIUM
# threshold of 0.25. Every route handler in every web application sat one
# hundredth under the line the default report draws — found by the engine,
# ranked `low`, shown to nobody. Measured on a labelled corpus: 906 true
# positives reported as 292.


def _entrypoints(root, name, body):
    from thot.scope.detect import _python_entrypoints

    (root / name).write_text(body, encoding="utf-8")
    return _python_entrypoints(root, name)


def test_a_flask_route_is_an_entrypoint(tmp_path):
    found = _entrypoints(tmp_path, "web.py", (
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/things', methods=['POST'])\n"
        "def create():\n"
        "    return ''\n"
    ))
    assert found == ["web.create"]


def test_a_fastapi_verb_decorator_is_an_entrypoint(tmp_path):
    found = _entrypoints(tmp_path, "api.py", (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.post('/things')\n"
        "async def create(request):\n"
        "    return {}\n"
    ))
    assert found == ["api.create"]


def test_a_blueprint_or_router_is_an_entrypoint_like_the_app(tmp_path):
    """Keyed on the decorator's attribute, not on the object's name — real
    applications mount routes on `bp`, `router` and `api`, never only `app`."""
    found = _entrypoints(tmp_path, "mod.py", (
        "@router.get('/a')\n"
        "def a():\n    return 1\n\n"
        "@bp.route('/b')\n"
        "def b():\n    return 2\n"
    ))
    assert found == ["mod.a", "mod.b"]


def test_a_django_view_is_an_entrypoint(tmp_path):
    """No decorator to key on — Django's routing table lives in `urls.py` —
    so the convention every Django project follows is the only signal."""
    found = _entrypoints(tmp_path, "views.py", (
        "from django.http import HttpResponse\n\n"
        "def show(request):\n"
        "    return HttpResponse('')\n"
    ))
    assert found == ["views.show"]


def test_taking_request_is_not_enough_without_django(tmp_path):
    """The argument name alone matches any helper handed a request object.
    Both halves are required or every `def handle(request)` becomes a public
    surface."""
    found = _entrypoints(tmp_path, "helpers.py", (
        "def handle(request):\n"
        "    return request\n"
    ))
    assert found == []


def test_importing_django_is_not_enough_without_the_convention(tmp_path):
    found = _entrypoints(tmp_path, "models.py", (
        "from django.db import models\n\n"
        "def helper(value):\n"
        "    return value\n"
    ))
    assert found == []


def test_a_bare_attribute_decorator_is_not_a_route(tmp_path):
    """A route always carries a path. `@cache.get` without parentheses is far
    more likely to be an accessor used as a decorator than an endpoint."""
    found = _entrypoints(tmp_path, "cached.py", (
        "@cache.get\n"
        "def value():\n    return 1\n"
    ))
    assert found == []


def test_a_nested_route_is_not_a_top_level_entrypoint(tmp_path):
    """Only `tree.body` is walked. A route defined inside a factory is real,
    but the graph names symbols by module and top-level name, so promoting
    it here would produce an entry point nothing can match."""
    found = _entrypoints(tmp_path, "factory.py", (
        "def make():\n"
        "    @app.route('/x')\n"
        "    def inner():\n        return 1\n"
        "    return inner\n"
    ))
    assert found == []


def test_the_old_names_still_win_on_their_own(tmp_path):
    found = _entrypoints(tmp_path, "tool.py", "def main():\n    pass\n")
    assert found == ["tool.main"]


def test_a_module_with_both_kinds_reports_both(tmp_path):
    found = _entrypoints(tmp_path, "both.py", (
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/x')\n"
        "def served():\n    return 1\n\n"
        "def main():\n    pass\n"
    ))
    assert sorted(found) == ["both.main", "both.served"]


def test_a_route_handler_reaches_the_manifest(tmp_path):
    """The integration the rest of the scoring depends on."""
    (tmp_path / "web.py").write_text(
        "@app.route('/x')\ndef served():\n    return 1\n", encoding="utf-8")
    assert "web.served" in detect_scope(tmp_path).entrypoints
