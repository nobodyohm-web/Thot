"""The loop that actually changes the code, and can be trusted to.

`thot improve` says it in its own docstring: *what it never does is edit
code*. It sharpens the program's judgement and leaves every real defect
exactly where it was. That is a deliberate, defensible line — and it is not
self-improvement, which is what the program claims to do.

This loop crosses it. Everything here is about the one question that makes
crossing it safe: what happens when the change is wrong. The answer is that
the test suite decides, the files go back byte for byte, and nothing is ever
committed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot.evolve import Attempt, Gate, evolve, snapshot_of


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("VALUE = 1\n")
    (tmp_path / "src" / "b.py").write_text("OTHER = 2\n")
    return tmp_path


def _gate(ok: bool) -> Gate:
    """A test command that passes or fails, without running pytest."""
    return Gate(command=["true"] if ok else ["false"], root=None)


def test_a_change_that_keeps_the_suite_green_is_kept(tmp_path):
    root = _repo(tmp_path)

    def apply(goal, attempt):
        (root / "src" / "a.py").write_text("VALUE = 42\n")
        return "a.py: VALUE 1 -> 42"

    done = evolve(root, goals=["améliore a"], apply=apply, gate=_gate(True))

    assert done[0].kept
    assert (root / "src" / "a.py").read_text() == "VALUE = 42\n"


def test_a_change_that_breaks_the_suite_is_put_back_byte_for_byte(tmp_path):
    """The whole reason this loop is allowed to exist."""
    root = _repo(tmp_path)
    before = (root / "src" / "a.py").read_bytes()

    def apply(goal, attempt):
        (root / "src" / "a.py").write_text("VALUE = oops\n")
        return "a.py cassé"

    done = evolve(root, goals=["casse a"], apply=apply, gate=_gate(False))

    assert not done[0].kept
    assert "test" in done[0].reason.lower()
    assert (root / "src" / "a.py").read_bytes() == before


def test_a_file_created_by_a_failed_change_is_removed(tmp_path):
    """Reverting only the files that existed leaves the new one behind, and
    a stray module is exactly how a green suite goes red on the next run."""
    root = _repo(tmp_path)

    def apply(goal, attempt):
        (root / "src" / "nouveau.py").write_text("import nexistepas\n")
        return "ajout de nouveau.py"

    evolve(root, goals=["ajoute"], apply=apply, gate=_gate(False))

    assert not (root / "src" / "nouveau.py").exists()


def test_a_file_deleted_by_a_failed_change_comes_back(tmp_path):
    root = _repo(tmp_path)

    def apply(goal, attempt):
        (root / "src" / "b.py").unlink()
        return "suppression de b.py"

    evolve(root, goals=["supprime"], apply=apply, gate=_gate(False))

    assert (root / "src" / "b.py").read_text() == "OTHER = 2\n"


def test_a_change_that_touched_nothing_is_not_reported_as_progress(tmp_path):
    root = _repo(tmp_path)

    done = evolve(root, goals=["ne fais rien"],
                  apply=lambda goal, attempt: "rien à faire", gate=_gate(True))

    assert not done[0].kept
    assert "aucun" in done[0].reason.lower()


def test_the_loop_stops_when_a_round_changes_nothing(tmp_path):
    root = _repo(tmp_path)
    calls = []

    def apply(goal, attempt):
        calls.append(goal)
        return "rien"

    evolve(root, goals=["a", "b", "c"], apply=apply, gate=_gate(True),
           stop_after_idle=2)

    assert len(calls) == 2


def test_the_snapshot_is_taken_before_anything_is_touched(tmp_path):
    root = _repo(tmp_path)
    seen = {}

    def apply(goal, attempt):
        seen["snapshot"] = dict(attempt.before)
        (root / "src" / "a.py").write_text("VALUE = 3\n")
        return "modifié"

    evolve(root, goals=["change"], apply=apply, gate=_gate(True))

    assert seen["snapshot"]["src/a.py"] == b"VALUE = 1\n"


def test_the_loop_never_reaches_for_git(tmp_path):
    """Not a policy comment — a check. A loop that edits code and can also
    commit is a loop that can rewrite the history it broke."""
    import inspect

    from thot import evolve as module

    source = inspect.getsource(module)
    for forbidden in ("git commit", "git checkout", "git reset", "git stash",
                      "git add", '"git"', "'git'"):
        assert forbidden not in source, f"{forbidden} n'a rien à faire ici"


def test_an_agent_that_fails_costs_its_attempt_and_not_the_run(tmp_path):
    root = _repo(tmp_path)

    def apply(goal, attempt):
        if goal == "casse":
            raise RuntimeError("l'agent est tombé")
        (root / "src" / "a.py").write_text("VALUE = 9\n")
        return "ok"

    done = evolve(root, goals=["casse", "répare"], apply=apply, gate=_gate(True))

    assert done[0].error and "tombé" in done[0].error
    assert done[1].kept


def test_snapshot_reads_only_what_the_run_may_touch(tmp_path):
    """A snapshot of a 7 000-file tree before every attempt is a snapshot
    nobody takes. Scope is what makes the safety affordable."""
    root = _repo(tmp_path)
    (root / ".venv").mkdir()
    (root / ".venv" / "huge.py").write_text("x = 1\n")

    taken = snapshot_of(root, ("src",))

    assert set(taken) == {"src/a.py", "src/b.py"}


# --- la copie de sûreté, le filet que la reprise en mémoire ne couvre pas ---
#
# `evolve --path .` passe toujours le même `~/.thot/evolve-backup`. Une copie
# qui fusionne avec celle du run précédent n'est la photo d'aucun instant.


def test_the_backup_replaces_the_previous_run_rather_than_merging_with_it(tmp_path):
    from thot.evolve import keep_a_copy

    (tmp_path / "repo").mkdir()
    root = _repo(tmp_path / "repo")
    into = tmp_path / "backup"
    keep_a_copy(root, into, ("src",))
    assert (into / "src" / "b.py").exists()

    (root / "src" / "b.py").unlink()
    keep_a_copy(root, into, ("src",))

    assert not (into / "src" / "b.py").exists(), (
        "un fichier supprimé depuis le run précédent revient dans la copie"
    )
    assert (into / "src" / "a.py").exists()


def test_the_backup_never_deletes_outside_the_repository(tmp_path):
    """`--scope` est une chaîne que l'utilisateur tape, et elle décide
    maintenant de ce qui est effacé dans le dossier de sauvegarde."""
    from thot.evolve import keep_a_copy

    (tmp_path / "repo").mkdir()
    root = _repo(tmp_path / "repo")
    into = tmp_path / "backup"
    (into).mkdir()
    (into / "precieux.txt").write_text("à ne pas perdre\n")

    keep_a_copy(root, into, ("..", ".", "/etc", "src"))

    assert (into / "precieux.txt").read_text() == "à ne pas perdre\n"
    assert (into / "src" / "a.py").exists()


def test_a_gate_that_cannot_start_is_not_a_verdict(tmp_path):
    """Measured on the first real run: `DEFAULT_GATE` invoked the bare name
    `python`, which is on no PATH here. The gate raised FileNotFoundError,
    the loop read that as "the change failed", and reverted work that had
    never been judged at all."""
    from thot.evolve import DEFAULT_GATE

    assert DEFAULT_GATE[0] != "python"
    assert Path(DEFAULT_GATE[0]).is_file(), "le juge doit exister pour juger"


def test_a_gate_that_cannot_run_says_so_rather_than_failing_quietly(tmp_path):
    root = _repo(tmp_path)
    gate = Gate(command=["/nexistepas/vraiment"], root=None)

    green, why = gate.passes(root)

    assert not green
    assert "n'a pas pu tourner" in why


# --- the gate has to measure, not only pass ------------------------------
#
# `Gate.passes()` answered a boolean. A patch that dropped named provenance
# from 34 % to 12 % went through green, because no test asserts a ratio —
# and a loop whose judge cannot see a regression is a loop that drifts in
# silence, one green round at a time.


def _measured(ok: bool, metrics, guards) -> Gate:
    return Gate(command=["true"] if ok else ["false"], root=None,
                metrics=metrics, guards=guards)


def test_a_green_change_that_loses_ground_is_still_reverted(tmp_path):
    root = _repo(tmp_path)
    scores = iter([{"provenance": 0.34}, {"provenance": 0.12}])
    gate = _measured(True, lambda _root: next(scores),
                     {"provenance": "ne_baisse_pas"})

    def apply(goal, attempt):
        (root / "src" / "a.py").write_text("VALUE = 2\n")
        return "moins de provenance"

    done = evolve(root, goals=["régresse"], apply=apply, gate=gate)

    assert not done[0].kept
    assert "provenance" in done[0].reason
    assert (root / "src" / "a.py").read_text() == "VALUE = 1\n"


def test_a_green_change_that_gains_ground_is_kept(tmp_path):
    root = _repo(tmp_path)
    scores = iter([{"provenance": 0.34}, {"provenance": 0.51}])
    gate = _measured(True, lambda _root: next(scores),
                     {"provenance": "ne_baisse_pas"})

    done = evolve(root, goals=["améliore"], gate=gate,
                  apply=lambda g, a: (root / "src" / "a.py").write_text("V = 2\n"))

    assert done[0].kept
    assert "provenance" in done[0].reason


def test_a_metric_that_must_not_rise_is_guarded_too(tmp_path):
    """Wall time, candidate count, anything where more is worse."""
    root = _repo(tmp_path)
    scores = iter([{"secondes": 60.0}, {"secondes": 300.0}])
    gate = _measured(True, lambda _root: next(scores), {"secondes": "ne_monte_pas"})

    done = evolve(root, goals=["ralentis"], gate=gate,
                  apply=lambda g, a: (root / "src" / "a.py").write_text("V = 2\n"))

    assert not done[0].kept


def test_a_metric_that_cannot_be_measured_is_not_evidence_of_no_regression(tmp_path):
    """The dangerous shape: measurement raises, the loop reads the silence as
    'nothing got worse', and keeps the change that broke the measurement."""
    root = _repo(tmp_path)

    def measure(_root):
        raise RuntimeError("la mesure est cassée")

    gate = _measured(True, measure, {"provenance": "ne_baisse_pas"})
    done = evolve(root, goals=["casse la mesure"], gate=gate,
                  apply=lambda g, a: (root / "src" / "a.py").write_text("V = 2\n"))

    assert not done[0].kept
    assert "mesure" in done[0].reason.lower()


def test_a_gate_with_no_metrics_behaves_exactly_as_before(tmp_path):
    root = _repo(tmp_path)
    done = evolve(root, goals=["change"], gate=_gate(True),
                  apply=lambda g, a: (root / "src" / "a.py").write_text("V = 2\n"))
    assert done[0].kept


def test_no_guard_ever_rewards_finding_less(tmp_path):
    """The gaming move the research named: an agent asked to reduce noise
    hardens the threshold until nothing is reported, and every 'fewer
    candidates is better' guard calls that a win."""
    from thot.evolve import DEFAULT_GUARDS

    for name, direction in DEFAULT_GUARDS.items():
        if "candidat" in name or "finding" in name:
            assert direction != "ne_monte_pas", (
                f"« {name} » récompenserait un seuil durci jusqu'à zéro"
            )


def test_the_measurement_runs_the_code_as_changed(tmp_path):
    """Thot measuring Thot: the module under change is already imported, so
    an in-process measurement reads the version that was loaded at startup
    and reports that nothing moved. It has to be a subprocess."""
    import inspect

    from thot.evolve import thot_metrics

    source = inspect.getsource(thot_metrics)
    assert "subprocess" in source or "run(" in source


def test_the_measurement_names_provenance_and_does_not_guard_volume(tmp_path):
    from thot.evolve import DEFAULT_GUARDS

    assert DEFAULT_GUARDS.get("provenance") == "ne_baisse_pas"
    assert "candidats" not in DEFAULT_GUARDS


def test_thot_can_be_run_as_a_module():
    """`python -m thot.cli` imported the module, never called `main`, and
    exited 0 printing nothing — which a caller reads as an empty audit."""
    import subprocess
    import sys

    done = subprocess.run([sys.executable, "-m", "thot", "--version"],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0
    assert "thot" in done.stdout
