"""The self-check. "It works" is a claim; this is the measurement.

What matters most here is that a check which cannot run reports a failure
rather than passing quietly — a green line meaning "not tested" is worse
than a red one, because it is the line people stop reading.
"""

from __future__ import annotations

from pathlib import Path

from thot import doctor


def test_every_check_reports_something_it_measured(tmp_path):
    checks = doctor.run(Path.cwd())

    assert checks, "aucune vérification n'a tourné"
    for check in checks:
        assert check.name
        assert check.detail, f"{check.name} ne dit pas ce qu'il a mesuré"


def test_a_check_that_raises_is_a_failed_check_not_a_crash():
    def explodes():
        raise RuntimeError("le disque a disparu")

    check = doctor._safe("essai", explodes)

    assert check.ok is False
    assert "le disque a disparu" in check.detail


def test_the_taint_check_exercises_both_engines(tmp_path):
    """A silent regression in either engine must turn this red."""
    ok, detail = doctor._taint(tmp_path)

    assert ok
    assert "python 1" in detail and "javascript 1" in detail


def test_the_mcp_check_speaks_the_protocol(tmp_path):
    ok, detail = doctor._mcp(tmp_path)

    assert ok
    assert "outil" in detail


def test_the_indexer_check_covers_both_languages():
    ok, detail = doctor._indexers(Path.cwd())

    assert ok
    assert "python" in detail and "typescript" in detail


def test_a_failed_check_renders_with_a_cross():
    assert doctor.Check("x", False, "cassé").line().startswith("✗")
    assert doctor.Check("x", True, "bon").line().startswith("✓")


def test_the_live_check_believes_only_what_the_agent_answered(monkeypatch):
    """The defect it exists for was invisible to every static inspection.

    Hermes could not open a path relative to its working directory and said
    so in words that read like a refusal. Nothing short of planting a file
    and reading the answer would have caught it.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Blind:
        def __init__(self, root, max_parallel=1):
            self.root = root

        @property
        def capabilities(self):
            return EngineCapabilities(name="aveugle", max_parallel=1)

        def run(self, task):
            return AgentResult(
                task_id=task.id,
                data={"verdict": "je ne peux pas lire ce fichier"},
            )

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._can_read(_Blind)
    assert ok is False
    assert "n'a pas lu" in detail


def test_the_live_check_passes_when_the_content_comes_back():
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Reads:
        def __init__(self, root, max_parallel=1):
            self.root = root

        @property
        def capabilities(self):
            return EngineCapabilities(name="voyant", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id,
                               data={"verdict": doctor.CANARY})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._can_read(_Reads)
    assert ok is True
    assert "chemin absolu" in detail


def test_the_offline_checks_do_not_include_the_live_ones():
    """`thot doctor` on a plane gives the answer it gives at a desk."""
    names = {check.name for check in doctor.run(Path.cwd())}

    assert not any(name.startswith("lecture ·") for name in names)
