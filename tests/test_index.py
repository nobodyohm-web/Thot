"""Indexer une seconde fois ne doit pas coûter une seconde fois.

Reparser un arbre entier était le prix de toute carte : le serveur MCP la
bâtissait au démarrage et n'y revenait jamais, la session la refaisait en
entier après chaque écriture d'outil, et `thot audit` recommençait de zéro
à chaque lancement. Mesuré sur `hermes/` : 6 924 fichiers, 26 s
d'indexation. Le fichier qui n'a pas bougé est le même fichier — c'est la
seule chose que ce cache affirme.
"""

from __future__ import annotations

import os

import thot.codemap.python_indexer as python_indexer
from thot.codemap.index import forget_symbols, index_files


def _parsed(monkeypatch) -> list[str]:
    """Les fichiers réellement passés à l'indexeur, dans l'ordre."""
    seen: list[str] = []
    real = python_indexer.PythonIndexer.index_file

    def counting(self, root, relative):
        seen.append(relative)
        return real(self, root, relative)

    monkeypatch.setattr(python_indexer.PythonIndexer, "index_file", counting)
    return seen


def _repo(tmp_path):
    forget_symbols()
    (tmp_path / "a.py").write_text("def alpha():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def beta():\n    return 2\n", encoding="utf-8")
    return tmp_path, ["a.py", "b.py"]


def test_an_unchanged_tree_is_parsed_once(tmp_path, monkeypatch):
    root, files = _repo(tmp_path)
    parsed = _parsed(monkeypatch)

    first = index_files(root, files)
    second = index_files(root, files)

    assert parsed == ["a.py", "b.py"], parsed
    assert [s.name for s in second] == [s.name for s in first]


def test_only_the_edited_file_is_parsed_again(tmp_path, monkeypatch):
    root, files = _repo(tmp_path)
    parsed = _parsed(monkeypatch)
    index_files(root, files)
    parsed.clear()

    (root / "b.py").write_text("def beta():\n    return 2\n\ndef gamma():\n    return 3\n",
                               encoding="utf-8")
    symbols = index_files(root, files)

    assert parsed == ["b.py"], parsed
    assert {s.name for s in symbols} == {"a.alpha", "b.beta", "b.gamma"}


def test_a_rewrite_of_the_same_size_is_still_a_new_file(tmp_path, monkeypatch):
    """Même longueur, autre contenu : c'est l'horodatage qui tranche."""
    root, files = _repo(tmp_path)
    parsed = _parsed(monkeypatch)
    index_files(root, files)
    parsed.clear()

    original = (root / "a.py").stat()
    (root / "a.py").write_text("def alphb():\n    return 1\n", encoding="utf-8")
    assert (root / "a.py").stat().st_size == original.st_size
    os.utime(root / "a.py", ns=(original.st_atime_ns, original.st_mtime_ns + 1_000_000))

    symbols = index_files(root, files)

    assert parsed == ["a.py"], parsed
    assert "a.alphb" in {s.name for s in symbols}


def test_two_paths_never_share_an_entry(tmp_path, monkeypatch):
    """Deux fichiers aux octets identiques restent deux fichiers."""
    root, _ = _repo(tmp_path)
    (root / "copie.py").write_text((root / "a.py").read_text(encoding="utf-8"),
                                   encoding="utf-8")
    parsed = _parsed(monkeypatch)

    symbols = index_files(root, ["a.py", "copie.py"])

    assert parsed == ["a.py", "copie.py"], parsed
    assert sorted(s.path for s in symbols) == ["a.py", "copie.py"]


def test_a_file_that_cannot_be_parsed_is_not_retried_for_ever(tmp_path, monkeypatch):
    """Un fichier illisible coûte une tentative, pas une par balayage."""
    root, _ = _repo(tmp_path)
    (root / "casse.py").write_text("def (\n", encoding="utf-8")
    parsed = _parsed(monkeypatch)

    assert index_files(root, ["casse.py"]) == []
    assert index_files(root, ["casse.py"]) == []
    assert parsed == ["casse.py"], parsed


def test_forgetting_the_cache_brings_the_parser_back(tmp_path, monkeypatch):
    root, files = _repo(tmp_path)
    parsed = _parsed(monkeypatch)
    index_files(root, files)
    forget_symbols()
    index_files(root, files)

    assert parsed == ["a.py", "b.py", "a.py", "b.py"], parsed


def test_a_vanished_file_is_simply_absent(tmp_path, monkeypatch):
    """Le cache ne doit pas ressusciter ce qui a été supprimé."""
    root, files = _repo(tmp_path)
    index_files(root, files)
    (root / "b.py").unlink()

    symbols = index_files(root, files)

    assert {s.name for s in symbols} == {"a.alpha"}


# -- plusieurs cœurs, et le cache qui doit y survivre ------------------------
#
# Un pool qui parse dans d'autres processus rapporte des symboles mais laisse
# `_SYMBOL_CACHE` vide dans le parent — et `gateway/commands.py` comme
# `schedule/runner.py` appellent `run_audit` en boucle dans UN seul processus.
# Perdre le cache là, c'est repayer l'indexation entière à chaque tour :
# mesuré 0,06 s → 5,4 s sur hermes, une régression d'un facteur 90 introduite
# par l'optimisation elle-même.


def _many(tmp_path, count):
    forget_symbols()
    for index in range(count):
        (tmp_path / f"m{index}.py").write_text(
            f"def f{index}():\n    return {index}\n", encoding="utf-8"
        )
    return tmp_path, [f"m{index}.py" for index in range(count)]


def test_the_parallel_pass_gives_exactly_the_serial_answer(tmp_path, monkeypatch):
    """Le vrai pool, vraiment démarré — sinon ce test ne prouve rien."""
    root, files = _many(tmp_path, 40)
    monkeypatch.setenv("THOT_JOBS", "1")
    serial = index_files(root, files)

    forget_symbols()
    monkeypatch.setenv("THOT_JOBS", "4")
    from thot import parallel

    monkeypatch.setattr(parallel, "PARALLEL_THRESHOLD", 4)

    # Sans cette preuve, le test passerait en série en croyant avoir mesuré
    # le parallèle — et ne vérifierait rien du tout.
    started = []
    real_pool = parallel.ProcessPoolExecutor

    def counting(*args, **kwargs):
        started.append(kwargs.get("max_workers"))
        return real_pool(*args, **kwargs)

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", counting)
    spread = index_files(root, files)

    assert started == [4], "aucun pool n'a démarré : le chemin parallèle n'a pas été pris"
    assert [(s.name, s.path, s.lineno) for s in spread] == \
           [(s.name, s.path, s.lineno) for s in serial]


def test_what_the_workers_parsed_is_remembered_by_the_parent(tmp_path, monkeypatch):
    root, files = _many(tmp_path, 40)
    monkeypatch.setenv("THOT_JOBS", "4")
    from thot import parallel

    monkeypatch.setattr(parallel, "PARALLEL_THRESHOLD", 4)
    index_files(root, files)

    # Second passage : rien n'a bougé, donc aucun worker ne doit démarrer.
    def refuse(*args, **kwargs):
        raise AssertionError("le cache du parent n'a pas été repeuplé")

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", refuse)
    parsed = _parsed(monkeypatch)
    again = index_files(root, files)

    assert parsed == []
    assert len(again) == 40


def test_only_the_uncached_files_are_sent_out(tmp_path, monkeypatch):
    """Un arbre chaud avec un fichier modifié n'envoie que ce fichier."""
    root, files = _many(tmp_path, 40)
    monkeypatch.setenv("THOT_JOBS", "1")
    index_files(root, files)

    sent = []
    from thot import parallel

    real = parallel.over_files

    def watching(function, root_path, listed, **kwargs):
        sent.extend(listed)
        return real(function, root_path, listed, **kwargs)

    monkeypatch.setattr(parallel, "over_files", watching)
    (root / "m7.py").write_text("def f7():\n    return 700\n", encoding="utf-8")
    index_files(root, files)

    assert sent == ["m7.py"], sent
