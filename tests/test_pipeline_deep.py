"""The pipeline with an engine attached: verdicts, not suspicions."""

from __future__ import annotations

from thot.contracts import Confidence
from thot.engine import AgentResult, EngineCapabilities
from thot.pipeline import run_audit
from thot.store.db import Store


class VerdictEngine:
    """Confirms every probe, refutes nothing."""

    def __init__(self, refute: bool = False) -> None:
        self.refute = refute
        self.seen: list[str] = []

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(name="test-engine", max_parallel=2)

    def run(self, task):
        self.seen.append(task.id)
        if task.id.startswith("probe:"):
            return AgentResult(task_id=task.id, data={
                "verdict": "confirmed",
                "scenario": "argv non validé atteint os.system",
                "severity": "critical",
            })
        return AgentResult(task_id=task.id, data={
            "refuted": self.refute, "raison": "constante littérale"
        })

    def fan_out(self, tasks):
        return [self.run(t) for t in tasks]


def test_without_an_engine_the_run_stays_deterministic(toy_repo):
    result = run_audit(toy_repo, require_authorization=False)
    assert result.engine is None
    assert all(f.confidence is Confidence.PLAUSIBLE for f in result.findings)


def test_an_engine_confirms_and_names_itself(toy_repo):
    engine = VerdictEngine()
    result = run_audit(toy_repo, require_authorization=False, engine=engine)
    assert result.engine == "test-engine"
    assert result.confirmed
    assert "argv non validé" in result.confirmed[0].failure_scenario
    assert any(t.startswith("refute:") for t in engine.seen)


def test_refutation_keeps_the_finding_out_of_confirmed(toy_repo):
    result = run_audit(toy_repo, require_authorization=False,
                       engine=VerdictEngine(refute=True))
    assert result.confirmed == []
    assert result.refuted


def test_the_budget_bounds_the_number_of_probes(toy_repo):
    engine = VerdictEngine()
    run_audit(toy_repo, require_authorization=False, engine=engine, budget=1)
    assert len([t for t in engine.seen if t.startswith("probe:")]) == 1


def test_verdicts_are_what_gets_persisted(toy_repo, tmp_path):
    store = Store.open(tmp_path / "thot.db")
    try:
        result = run_audit(toy_repo, store=store, require_authorization=False,
                           engine=VerdictEngine())
        assert result.run_id is not None
        stored = store.findings_for_run(result.run_id)
    finally:
        store.close()
    assert any(f.confidence is Confidence.CONFIRMED for f in stored)
