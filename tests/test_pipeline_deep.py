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


# -- memory in the loop ------------------------------------------------------


def test_a_remembered_dismissal_is_applied_and_counted(toy_repo, tmp_path):
    from thot.memory import Decision, Verdict
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open(tmp_path / "m.db")
    try:
        first = run_audit(toy_repo, require_authorization=False)
        assert first.findings
        memory.remember(
            Verdict.of(first.findings[0], Decision.REFUTED, "faux positif", "dev")
        )

        second = run_audit(toy_repo, require_authorization=False, memory=memory)
        assert second.remembered == 1
        assert second.findings[0].confidence is Confidence.REFUTED
        assert "faux positif" in second.findings[0].failure_scenario
    finally:
        memory.close()


def test_a_dismissal_stops_the_model_being_paid_again(toy_repo, tmp_path):
    """The economic point of the whole feature."""
    from thot.memory import Decision, Verdict
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open(tmp_path / "m.db")
    try:
        baseline = run_audit(toy_repo, require_authorization=False)
        for finding in baseline.findings:
            memory.remember(Verdict.of(finding, Decision.REFUTED, "tous écartés"))

        engine = VerdictEngine()
        run_audit(toy_repo, require_authorization=False, engine=engine, memory=memory)
        assert engine.seen == []  # not one call made
    finally:
        memory.close()


def test_adversarial_refutations_are_remembered_for_next_time(toy_repo, tmp_path):
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open(tmp_path / "m.db")
    try:
        run_audit(toy_repo, require_authorization=False,
                  engine=VerdictEngine(refute=True), memory=memory)
        assert memory.all_verdicts()
        # Named after who actually decided, not after the tool that ran.
        assert memory.all_verdicts()[0].author == "test-engine"
    finally:
        memory.close()


def test_an_accepted_risk_is_not_re_argued_by_the_model(toy_repo, tmp_path):
    """A decision taken is a decision taken.

    Sending an accepted risk back to the model pays twice for an answer
    someone already gave, and — because the probe replaces confidence,
    severity, scenario and provenance wholesale — the reply overwrites the
    human's decision and erases who took it.
    """
    from thot.memory import Decision, Verdict
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open(tmp_path / "m.db")
    try:
        baseline = run_audit(toy_repo, require_authorization=False)
        target = baseline.findings[0]
        memory.remember(
            Verdict.of(target, Decision.ACCEPTED, "outil interne, réseau fermé", "dev")
        )

        engine = VerdictEngine()
        result = run_audit(toy_repo, require_authorization=False,
                           engine=engine, memory=memory)

        assert not any(task.endswith(target.id) for task in engine.seen), (
            "un risque accepté ne doit pas repasser devant le modèle"
        )
        kept = next(f for f in result.findings if f.id == target.id)
        assert (kept.provenance or {}).get("décidé par") == "dev"
        assert "Risque accepté" in kept.failure_scenario
    finally:
        memory.close()


def test_a_regression_is_reported_not_re_litigated(toy_repo, tmp_path):
    """`fixed` and here again means the fix went away — that is the alert.

    Letting the model refute it would silence the one finding that has
    already been judged real once.
    """
    from thot.memory import Decision, Verdict
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open(tmp_path / "m.db")
    try:
        baseline = run_audit(toy_repo, require_authorization=False)
        target = baseline.findings[0]
        memory.remember(Verdict.of(target, Decision.FIXED, "corrigé en mars", "dev"))

        engine = VerdictEngine(refute=True)
        result = run_audit(toy_repo, require_authorization=False,
                           engine=engine, memory=memory)

        kept = next(f for f in result.findings if f.id == target.id)
        assert kept.confidence is Confidence.CONFIRMED
        assert (kept.provenance or {}).get("régression") is True
        assert not any(task.endswith(target.id) for task in engine.seen)
    finally:
        memory.close()


def test_the_probe_does_not_erase_where_the_finding_came_from(toy_repo):
    """A pattern rule's provenance is not the probe's to discard."""
    result = run_audit(toy_repo, require_authorization=False, engine=VerdictEngine())
    pattern = [f for f in result.findings if f.rule.startswith("pattern.")]
    assert pattern, "le dépôt jouet doit déclencher au moins un motif"
    for finding in pattern:
        provenance = finding.provenance or {}
        assert provenance.get("source") == "hermes/security-guidance"
        assert provenance.get("moteur") == "test-engine"


def test_a_refutation_weighs_the_same_whichever_pass_reached_it(toy_repo):
    """Probe-refuted and refutation-refuted must not rank differently."""
    from thot.contracts import Severity

    class ProbeRefutes(VerdictEngine):
        def run(self, task):
            self.seen.append(task.id)
            if task.id.startswith("probe:"):
                return AgentResult(task_id=task.id, data={
                    "verdict": "refuted", "severity": "high",
                    "scenario": "aucune entrée n'atteint ce point"})
            raise AssertionError("un refus à la sonde ne va pas en réfutation")

    straight = run_audit(toy_repo, require_authorization=False, engine=ProbeRefutes())
    two_pass = run_audit(toy_repo, require_authorization=False,
                         engine=VerdictEngine(refute=True))

    for result in (straight, two_pass):
        refuted = [f for f in result.findings if f.confidence is Confidence.REFUTED]
        assert refuted
        assert all(f.severity is Severity.INFO for f in refuted)
