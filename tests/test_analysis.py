"""Analysis and refutation, driven by a scripted engine.

No model runs here. What is under test is the part that decides which
candidates deserve a model at all, what it is asked, and — the point of the
whole phase — that a refuted candidate is downgraded rather than shipped.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from thot.analysis.probe import analyse, excerpt, select_for_analysis
from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.engine import AgentResult, AgentTask, EngineCapabilities


class ScriptedEngine:
    """Answers by task id prefix, and records everything it was asked."""

    def __init__(self, answers: dict[str, dict]) -> None:
        self.answers = answers
        self.tasks: list[AgentTask] = []

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(name="scripted", max_parallel=4)

    def run(self, task: AgentTask) -> AgentResult:
        self.tasks.append(task)
        for prefix, payload in self.answers.items():
            if task.id.startswith(prefix):
                if payload is None:
                    return AgentResult(task_id=task.id, error="échec simulé")
                return AgentResult(task_id=task.id, text="", data=payload)
        return AgentResult(task_id=task.id, error="pas de réponse scriptée")

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


def make_finding(rule="sink.os.system", severity=Severity.HIGH, path="src/app.py"):
    location = CodeRef(path=path, line=3, symbol="run_command", ast_hash="h")
    return Finding(
        id=Finding.compute_id(rule, location),
        rule=rule,
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
        failure_scenario="candidat déterministe",
    )


# -- selection ---------------------------------------------------------------


def test_selection_puts_the_worst_first():
    findings = [
        make_finding(severity=Severity.LOW, path="a.py"),
        make_finding(severity=Severity.CRITICAL, path="b.py"),
        make_finding(severity=Severity.MEDIUM, path="c.py"),
    ]
    chosen = select_for_analysis(findings, limit=3)
    assert [f.severity for f in chosen] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW
    ]


def test_selection_honours_the_budget():
    findings = [make_finding(path=f"f{i}.py") for i in range(50)]
    assert len(select_for_analysis(findings, limit=7)) == 7


def test_already_refuted_findings_are_not_re_analysed():
    findings = [replace(make_finding(), confidence=Confidence.REFUTED)]
    assert select_for_analysis(findings, limit=10) == []


# -- excerpt -----------------------------------------------------------------


def test_excerpt_reads_around_the_location(toy_repo):
    text = excerpt(toy_repo, CodeRef(path="src/app.py", line=2), radius=2)
    assert text.strip()
    assert "\n" in text


def test_excerpt_of_a_missing_file_is_empty(toy_repo):
    assert excerpt(toy_repo, CodeRef(path="nope.py", line=1)) == ""


# -- analysis ----------------------------------------------------------------


def test_a_confirmed_candidate_keeps_its_scenario(toy_repo):
    engine = ScriptedEngine({
        "probe:": {"verdict": "confirmed", "scenario": "argv atteint os.system",
                   "severity": "critical"},
        "refute:": {"refuted": False, "raison": "le chemin tient"},
    })
    out = analyse(toy_repo, [make_finding()], engine)
    assert out[0].confidence is Confidence.CONFIRMED
    assert out[0].severity is Severity.CRITICAL
    assert "argv atteint os.system" in out[0].failure_scenario


def test_refutation_downgrades_a_confirmed_candidate(toy_repo):
    engine = ScriptedEngine({
        "probe:": {"verdict": "confirmed", "scenario": "exploitable",
                   "severity": "critical"},
        "refute:": {"refuted": True, "raison": "l'entrée est une constante"},
    })
    out = analyse(toy_repo, [make_finding()], engine)
    assert out[0].confidence is Confidence.REFUTED
    assert "l'entrée est une constante" in out[0].failure_scenario


def test_a_candidate_the_probe_rejects_is_never_refuted(toy_repo):
    engine = ScriptedEngine({
        "probe:": {"verdict": "refuted", "scenario": "faux positif",
                   "severity": "info"},
    })
    out = analyse(toy_repo, [make_finding()], engine)
    assert out[0].confidence is Confidence.REFUTED
    assert not any(t.id.startswith("refute:") for t in engine.tasks)


def test_an_engine_failure_leaves_the_finding_plausible(toy_repo):
    engine = ScriptedEngine({"probe:": None})
    out = analyse(toy_repo, [make_finding()], engine)
    assert out[0].confidence is Confidence.PLAUSIBLE
    assert out[0].provenance and "erreur" in str(out[0].provenance).lower()


def test_findings_beyond_the_budget_are_returned_untouched(toy_repo):
    engine = ScriptedEngine({
        "probe:": {"verdict": "confirmed", "scenario": "x", "severity": "high"},
        "refute:": {"refuted": False, "raison": "ok"},
    })
    findings = [make_finding(path=f"f{i}.py") for i in range(5)]
    out = analyse(toy_repo, findings, engine, limit=2)
    analysed = [f for f in out if f.confidence is Confidence.CONFIRMED]
    assert len(analysed) == 2
    assert len(out) == 5


def test_the_probe_prompt_carries_the_code_not_just_the_rule(toy_repo):
    engine = ScriptedEngine({
        "probe:": {"verdict": "refuted", "scenario": "x", "severity": "info"},
    })
    analyse(toy_repo, [make_finding()], engine)
    probe = engine.tasks[0]
    assert "src/app.py" in probe.prompt()
    assert probe.schema is not None
