"""Étaler une passe par fichier sur les cœurs, ou s'en abstenir.

Mesuré sur `hermes/`, 6 924 fichiers, dix cœurs : `thot audit` prenait
138,5 s de mur dont 135,6 s de CPU sur UN cœur — 99 % d'un processeur
pendant que sept autres dormaient. Les phases lourdes ont toutes la même
forme : une boucle qui lit un fichier, le parse, et ajoute à une liste
locale. Rien n'est partagé entre deux fichiers.

Ce qui est épinglé ici n'est pas le gain — il dépend de la machine — mais
les trois propriétés sans lesquelles le gain ne vaut rien : l'ordre est
préservé, le parallélisme se coupe entièrement, et une machine qui refuse
les sous-processus continue d'auditer.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from thot import parallel


def _upper(root: str, files: list[str]) -> list[str]:
    return [f"{root}:{name.upper()}" for name in files]


def _who_ran_it(root: str, files: list[str]) -> list[int]:
    """Le PID du processus qui a fait le travail — la seule preuve directe."""
    import os

    return [os.getpid()] * len(files)


# -- combien de processus ---------------------------------------------------


def test_the_environment_can_pin_the_number_of_jobs(monkeypatch):
    monkeypatch.setenv(parallel.JOBS_ENV, "3")

    assert parallel.jobs_wanted() == 3


def test_an_explicit_count_beats_the_environment(monkeypatch):
    monkeypatch.setenv(parallel.JOBS_ENV, "3")

    assert parallel.jobs_wanted(1) == 1


def test_a_typo_in_the_environment_does_not_stop_an_audit(monkeypatch):
    monkeypatch.setenv(parallel.JOBS_ENV, "beaucoup")

    assert parallel.jobs_wanted() >= 1


def test_zero_jobs_is_still_one_job(monkeypatch):
    monkeypatch.setenv(parallel.JOBS_ENV, "0")

    assert parallel.jobs_wanted() == 1


# -- le découpage -----------------------------------------------------------


def test_chunks_are_contiguous_and_cover_everything():
    items = list(range(17))

    pieces = parallel.chunked(items, 4)

    assert [x for piece in pieces for x in piece] == items
    assert all(pieces), "un morceau vide ferait tourner un worker pour rien"


def test_one_piece_is_the_whole_list():
    assert parallel.chunked([1, 2, 3], 1) == [[1, 2, 3]]


# -- quand on ne parallélise pas -------------------------------------------


def _forbid_pool(monkeypatch):
    """Rendre tout démarrage de pool visible en le faisant échouer bruyamment."""
    def refuse(*args, **kwargs):
        raise AssertionError("un pool a été démarré alors qu'il ne fallait pas")

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", refuse)


def test_a_small_list_never_starts_a_pool(monkeypatch):
    _forbid_pool(monkeypatch)

    assert parallel.over_files(_upper, Path("/r"), ["a", "b"]) == ["/r:A", "/r:B"]


def test_one_job_never_starts_a_pool(monkeypatch):
    _forbid_pool(monkeypatch)
    files = [str(n) for n in range(1000)]

    assert parallel.over_files(_upper, Path("/r"), files, jobs=1)[0] == "/r:0"


def test_a_machine_that_cannot_spawn_still_audits(monkeypatch):
    """Plus lent est acceptable ; ne pas auditer ne l'est pas."""
    def broken(*args, **kwargs):
        raise OSError("pas de sous-processus ici")

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", broken)
    files = [str(n) for n in range(50)]

    got = parallel.over_files(_upper, Path("/r"), files, jobs=4, threshold=2)

    assert got == [f"/r:{n}" for n in range(50)]


# -- quand on parallélise ---------------------------------------------------


def test_the_order_survives_the_split(monkeypatch):
    """Un audit qui réordonne sa sortie casse la comparaison entre deux runs.

    Le pool est remplacé par un exécuteur en série : ce qui est vérifié ici
    est le recollement des morceaux, pas la concurrence — celle-ci est
    exercée pour de vrai par `tests/test_index.py`.
    """
    started = []

    class Serial:
        def __init__(self, max_workers=None):
            started.append(max_workers)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def map(self, function, roots, pieces):
            return [function(root, piece) for root, piece in zip(roots, pieces)]

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", Serial)
    files = [str(n) for n in range(200)]

    got = parallel.over_files(_upper, Path("/r"), files, jobs=4, threshold=2)

    assert got == [f"/r:{n}" for n in range(200)]
    assert started == [4]


def test_the_work_really_happens_in_another_process():
    """`over_files` retombe en série sur toute erreur, silencieusement.

    C'est le bon comportement — une machine qui interdit les sous-processus
    doit continuer d'auditer — mais il rend tous les autres tests de ce
    fichier incapables de distinguer « parallélisé » de « retombé en série ».
    Seul le PID tranche.
    """
    import os

    files = [str(n) for n in range(40)]

    pids = set(parallel.over_files(_who_ran_it, Path("/r"), files,
                                   jobs=2, threshold=2))

    assert pids, "aucun résultat"
    assert pids != {os.getpid()}, (
        "tout a tourné dans le processus parent : le pool a échoué en silence"
    )


def test_the_command_line_can_pin_the_jobs(tmp_path, monkeypatch):
    """`THOT_JOBS=1` suffit à un script ; un drapeau se lit dans l'historique.

    Le correctif retenu demandait les deux : « un `--jobs` / variable d'env
    pour forcer 1 (indispensable aux tests et au débogage) ».
    """
    from thot import cli
    from thot.scope.authorization import write_authorization

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("def main():\n    pass\n", encoding="utf-8")
    write_authorization(repo, owner="tester")
    monkeypatch.delenv(parallel.JOBS_ENV, raising=False)

    assert cli.main(["audit", str(repo), "--jobs", "1"]) == 0
    assert os.environ[parallel.JOBS_ENV] == "1"
