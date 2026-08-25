import pytest

from thot.contracts import Severity
from thot.errors import AuthorizationError
from thot.pipeline import run_audit
from thot.scope.authorization import write_authorization


def test_end_to_end_finds_the_command_injection(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    rules = {f.rule for f in result.findings}
    assert "sink.os.system" in rules


def test_unauthorized_repo_raises(toy_repo):
    with pytest.raises(AuthorizationError):
        run_audit(toy_repo)


def test_findings_carry_computed_severity_and_a_scenario(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    finding = next(f for f in result.findings if f.rule == "sink.os.system")
    assert finding.severity in set(Severity)
    assert finding.failure_scenario


def test_clean_repo_produces_no_findings(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    write_authorization(tmp_path, owner="tester")
    assert run_audit(tmp_path).findings == []


def test_store_persists_the_run(toy_repo, tmp_path):
    from thot.store.db import Store

    write_authorization(toy_repo, owner="tester")
    store = Store.open(tmp_path / "s.db")
    result = run_audit(toy_repo, store=store)
    assert result.run_id is not None
    assert len(store.findings_for_run(result.run_id)) == len(result.findings)
    # `symbol_cache` n'est plus alimenté : personne ne le relisait, et il ne
    # pouvait pas l'être — la clé est le nom du symbole, sans chemin ni
    # version de fichier. L'écriture coûtait 101 533 lignes par audit de
    # `hermes/` pour rien.
    assert store.cached_symbol_hashes() == {}
    store.close()


def test_a_taint_path_inside_a_test_is_demoted_too(tmp_path):
    """The role is not a pattern-rule concept: a proven taint path through a
    fixture is still a path nobody outside the repository walks."""
    import textwrap

    from thot.contracts import Severity
    from thot.pipeline import run_audit

    for folder in ("src", "tests"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "app.py").write_text(
            textwrap.dedent(
                """
                import os
                import sys


                def read_input():
                    return sys.argv[1]


                def run(argument):
                    os.system("echo " + argument)


                def main():
                    target = read_input()
                    run(target)
                """
            )
        )

    result = run_audit(tmp_path, require_authorization=False)
    by_path = {f.location.path: f for f in result.findings
               if f.rule.startswith("sink.")}
    assert "src/app.py" in by_path and "tests/app.py" in by_path

    production = by_path["src/app.py"]
    in_test = by_path["tests/app.py"]
    order = list(Severity)
    assert order.index(production.severity) <= order.index(in_test.severity)
    assert (in_test.provenance or {}).get("rôle") == "test"


def test_auditing_a_repository_never_runs_the_code_it_ships(tmp_path):
    """The audited repository does not get to execute inside the auditor.

    `run_audit` calls `annotate_findings`, which discovers plugins for the
    root being audited. A repository shipping `.thot/plugins/x/__init__.py`
    therefore used to get its module body executed by the mere act of being
    audited — with the auditor's environment and their `~/.thot` in reach.
    """
    from thot.plugins import forget_plugins

    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    folder = tmp_path / ".thot" / "plugins" / "pwn"
    folder.mkdir(parents=True)
    (folder / "plugin.yaml").write_text("name: pwn\nhooks: [on_finding]\n")
    marker = tmp_path / "executed"
    (folder / "__init__.py").write_text(
        f"from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('oui')\n\n"
        f"def on_finding(**kw):\n    return None\n"
    )
    write_authorization(tmp_path, owner="tester")
    forget_plugins()

    run_audit(tmp_path)

    assert not marker.exists()


def test_an_interrupted_deep_pass_keeps_what_it_already_decided(tmp_path):
    """Ninety minutes of judgement must not die with the ninety-first.

    The engine answers two batches and then dies. What was decided before
    the failure has to be on disk, and — because a remembered refutation is
    skipped by the next selection — the re-run has to pick up where this one
    stopped rather than pay for it twice.
    """
    from thot.engine.base import AgentResult, EngineCapabilities
    from thot.memory import build_memory
    from thot.scope.authorization import write_authorization

    for index in range(6):
        (tmp_path / f"m{index}.py").write_text(
            "import os, sys\n\n"
            "def run():\n"
            "    os.system('ls ' + sys.argv[1])\n"
        )
    write_authorization(tmp_path, owner="tester")

    class _DiesHalfway:
        def __init__(self):
            self.answered = 0

        @property
        def capabilities(self):
            return EngineCapabilities(name="scripted", max_parallel=2)

        def run(self, task):
            self.answered += 1
            if self.answered > 4:
                raise KeyboardInterrupt("l'utilisateur a coupé")
            return AgentResult(
                task_id=task.id,
                data={"verdict": "refuted", "scenario": "entrée constante"},
            )

        def fan_out(self, tasks):
            return [self.run(task) for task in tasks]

    memory = build_memory(tmp_path)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_audit(tmp_path, engine=_DiesHalfway(), budget=6, memory=memory)
        kept = [v for v in memory.all_verdicts()]
    finally:
        memory.close()

    assert len(kept) == 4, "les lots terminés doivent être sur disque"


def test_the_session_and_the_cli_see_the_same_analysis(tmp_path):
    """`/audit` and `thot audit` must never disagree about what ran.

    They are two call sites for the same rules, and a rule added to one of
    them makes the promise false without failing anything — which is exactly
    what happened to the suppression sweep, an hour after it was written.
    """
    from thot.recon import sweep
    from thot.scope.authorization import write_authorization

    (tmp_path / "app.py").write_text(
        "import os, sys\n\n"
        "def run():\n"
        "    os.system('ls ' + sys.argv[1])  # nosec B605 — entrée contrôlée\n"
    )
    write_authorization(tmp_path, owner="tester")

    from_cli = {f.rule for f in run_audit(tmp_path).findings}
    from_session = {f.rule for f in sweep(tmp_path, deep=True).findings}

    assert from_cli == from_session, (
        f"seulement en CLI : {from_cli - from_session} · "
        f"seulement en session : {from_session - from_cli}"
    )
    assert "suppression.security" in from_cli


# --- une liste coupée doit dire qu'elle l'est ------------------------------
#
# Le reste du programme marque ses coupes : « … et N autres » pour les
# findings du journal, « (+N) » pour les fichiers d'une ronde, une ligne
# dédiée au-delà de douze dépendances vulnérables. Les deux listes de
# fichiers modifiés par une sonde s'arrêtaient à dix sans le dire, laissant
# le lecteur soustraire contre l'en-tête — dans le message le plus alarmant
# que l'outil produise.


def test_a_short_list_is_shown_whole():
    from thot.pipeline import touched_lines

    assert touched_lines(("a.py", "b.py")) == ["a.py", "b.py"]


def test_a_long_list_names_what_it_left_out():
    from thot.pipeline import touched_lines

    lines = touched_lines(tuple(f"f{i}.py" for i in range(25)))

    assert len(lines) == 11
    assert lines[-1] == "… et 15 autre(s) non listé(s)"


def test_a_list_exactly_at_the_limit_says_nothing_extra():
    from thot.pipeline import touched_lines

    assert len(touched_lines(tuple(f"f{i}.py" for i in range(10)))) == 10


def test_the_parallel_sweeps_say_exactly_what_the_serial_ones_said(toy_repo, monkeypatch):
    """Le pool ne change pas ce qu'un audit trouve, seulement en combien de temps.

    Ce test descend le seuil pour emprunter POUR DE VRAI le chemin
    multiprocessus, et il exige la preuve qu'un pool a démarré : sans elle il
    comparerait la version en série à elle-même. Il attrape aussi le piège
    du spawn — un worker réimporte le module, donc tout état que le parent
    avait posé dans un global lui parvient vide.
    """
    from thot import parallel
    from thot.pipeline import run_audit

    monkeypatch.setenv("THOT_JOBS", "1")
    serial = run_audit(toy_repo, require_authorization=False)

    monkeypatch.setenv("THOT_JOBS", "2")
    monkeypatch.setattr(parallel, "PARALLEL_THRESHOLD", 1)
    started = []
    real_pool = parallel.ProcessPoolExecutor

    def counting(*args, **kwargs):
        started.append(kwargs.get("max_workers"))
        return real_pool(*args, **kwargs)

    monkeypatch.setattr(parallel, "ProcessPoolExecutor", counting)
    spread = run_audit(toy_repo, require_authorization=False)

    assert started, "aucun pool démarré : le chemin parallèle n'a pas été pris"
    assert [f.id for f in spread.findings] == [f.id for f in serial.findings]
    assert [(f.severity, f.location.path, f.location.line) for f in spread.findings] == \
           [(f.severity, f.location.path, f.location.line) for f in serial.findings]


def test_a_finding_names_the_kind_of_source_it_came_from(toy_repo):
    """Two findings of the same rule can sit at two different ranks now,
    because one path started at a request and the other at a command line.
    A rank whose reason is invisible is a rank nobody can argue with."""
    write_authorization(toy_repo, owner="tester")

    finding = next(f for f in run_audit(toy_repo).findings
                   if f.rule == "sink.os.system")

    assert "ligne de commande" in finding.failure_scenario
    assert (finding.provenance or {}).get("source_rule") == "source.argv"
