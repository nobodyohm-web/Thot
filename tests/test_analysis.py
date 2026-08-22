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


def test_excerpt_of_a_missing_file_says_so_rather_than_going_blank(toy_repo):
    """This pinned `== ""` and had no reason written for it.

    Empty is the dangerous answer: the three task builders drop the excerpt
    under a heading reading "Code :", and an agent asked whether a candidate
    is exploitable "dans ce code, tel qu'il est écrit" — shown nothing — can
    answer `refuted`, which is then remembered for good.
    """
    text = excerpt(toy_repo, CodeRef(path="nope.py", line=1))

    assert "nope.py" in text
    assert "illisible" in text.lower()
    assert "conclus" in text.lower()


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


# -- the cascade: what survives an attack gets a second, different attacker ---


class _Member:
    """A scripted engine with a name of its own, for panel tests."""

    def __init__(self, name, answers):
        self._name = name
        self.answers = answers
        self.tasks: list[AgentTask] = []

    @property
    def capabilities(self):
        return EngineCapabilities(name=self._name, max_parallel=1)

    def run(self, task):
        self.tasks.append(task)
        for prefix, payload in self.answers.items():
            if task.id.startswith(prefix):
                return AgentResult(task_id=task.id, text="", data=payload)
        return AgentResult(task_id=task.id, error="pas de réponse scriptée")

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


_SURVIVES = {
    "probe:": {"verdict": "confirmed", "scenario": "entrée x atteint le sink"},
    "refute:": {"refuted": False, "raison": "je n'ai rien trouvé"},
    "refute2:": {"refuted": False, "raison": "moi non plus"},
}


def _panel(names):
    from thot.engine.panel import PanelEngine

    return PanelEngine(members=[_Member(name, _SURVIVES) for name in names])


def test_a_survivor_is_attacked_again_by_a_third_agent(tmp_path):
    """Two independent attackers, or the confirmation is one agent's opinion."""
    panel = _panel(["claude", "hermes", "prime"])

    result = analyse(tmp_path, [make_finding()], panel, limit=1)[0]

    provenance = result.provenance
    voices = {
        provenance["moteur"],
        provenance["contradicteur"],
        provenance["second contradicteur"],
    }
    assert len(voices) == 3, "un agent a parlé deux fois sur le même finding"
    assert provenance["phase"] == "confirmée (2 attaques)"
    assert result.confidence is Confidence.CONFIRMED


def test_without_a_third_agent_nothing_escalates(tmp_path):
    """A second attack by someone who already spoke is a rehearsal, not a test."""
    panel = _panel(["claude", "hermes"])

    analyse(tmp_path, [make_finding()], panel, limit=1)

    issued = [t.id for member in panel.members for t in member.tasks]
    assert not any(i.startswith("refute2:") for i in issued)


def test_a_refutation_is_never_re_litigated(tmp_path):
    """The attacker is told to refute when in doubt, so a refutation stands."""
    members = [
        _Member(name, {
            "probe:": {"verdict": "confirmed", "scenario": "s"},
            "refute:": {"refuted": True, "raison": "entrée constante"},
            "refute2:": {"refuted": False, "raison": "en fait si"},
        })
        for name in ("claude", "hermes", "prime")
    ]
    from thot.engine.panel import PanelEngine

    panel = PanelEngine(members=members)
    result = analyse(tmp_path, [make_finding()], panel, limit=1)[0]

    issued = [t.id for m in members for t in m.tasks]
    assert not any(i.startswith("refute2:") for i in issued)
    assert result.confidence is Confidence.REFUTED


def test_every_decision_is_announced_as_it_lands(tmp_path):
    """What makes a two-hour run survivable: nothing waits for the end."""
    engine = ScriptedEngine({
        "probe:": {"verdict": "refuted", "scenario": "faux positif"},
    })
    seen = []

    findings = [make_finding(path=f"a{i}.py") for i in range(3)]
    analyse(tmp_path, findings, engine, limit=3, on_decided=seen.append)

    assert len(seen) == 3
    assert {f.id for f in seen} == {f.id for f in findings}


def test_the_second_attacker_is_shown_the_angle_that_already_failed(tmp_path):
    """Repeating the first attack's angle would buy nothing."""
    from thot.analysis.probe import _refute_task
    from dataclasses import replace as _replace

    finding = _replace(
        make_finding(),
        provenance={"contre-argument écarté": "l'entrée est validée en amont"},
    )

    first = _refute_task(tmp_path, finding, "scénario")
    second = _refute_task(tmp_path, finding, "scénario", again=True)

    assert "l'entrée est validée en amont" in second.instructions
    assert "l'entrée est validée en amont" not in first.instructions
    assert second.id.startswith("refute2:")


def test_every_task_pins_the_agent_to_the_tree_that_was_audited(tmp_path):
    """Thot audits three trees nested inside one another.

    `hermes/` and `prime/` live inside Thot's own repository, so the same
    relative path exists more than once and a tool resolving from the git
    root opens the wrong file. It happened: a live SQL injection in Hermes's
    copy of a template was refuted with an accurate description of Thot's
    copy, fixed the day before — and the verdict was remembered.
    """
    from thot.analysis.probe import _probe_task, _refute_task

    finding = make_finding()
    probe = _probe_task(tmp_path, finding)
    refute = _refute_task(tmp_path, finding, "scénario")

    for task in (probe, refute):
        assert str(tmp_path.resolve()) in task.context
        assert "L'historique git n'est pas l'état audité" in task.context


# -- the other direction: a refutation that would bury something serious ------


def test_a_serious_refutation_is_read_by_an_agent_with_no_stake_in_it(tmp_path):
    """The two errors are not symmetrical.

    A wrong confirmation costs a human ten minutes. A wrong refutation costs
    a live defect for ever, because a remembered refutation is skipped by
    every audit that follows. It happened once for real, which is why this
    exists.
    """
    members = [
        _Member(name, {
            "probe:": {"verdict": "refuted", "scenario": "rien à voir"},
            "review:": {"sound": True, "raison": "vérifiable ici"},
        })
        for name in ("claude", "hermes", "prime")
    ]
    from thot.engine.panel import PanelEngine

    panel = PanelEngine(members=members)
    result = analyse(tmp_path, [make_finding(severity=Severity.HIGH)], panel,
                     limit=1)[0]

    issued = {m.capabilities.name: [t.id for t in m.tasks] for m in members}
    reviewers = [n for n, ids in issued.items()
                 if any(i.startswith("review:") for i in ids)]
    arguers = [n for n, ids in issued.items()
               if any(i.startswith("probe:") for i in ids)]

    assert reviewers and arguers
    assert set(reviewers).isdisjoint(arguers), "le relecteur avait déjà parlé"
    assert result.confidence is Confidence.REFUTED
    assert result.provenance["réfutation vérifiée"] == "oui"


def test_a_contested_refutation_puts_the_finding_back_where_it_was(tmp_path):
    """Not confirmed — nobody argued that. Unknown, which is the truth."""
    from thot.engine.panel import PanelEngine

    members = [
        _Member(name, {
            "probe:": {"verdict": "refuted", "scenario": "corrigé depuis"},
            "review:": {"sound": False,
                        "raison": "cette ligne est bien dans le fichier"},
        })
        for name in ("claude", "hermes")
    ]
    finding = make_finding(severity=Severity.HIGH)
    result = analyse(tmp_path, [finding], PanelEngine(members=members), limit=1)[0]

    assert result.confidence is Confidence.PLAUSIBLE
    assert result.severity is Severity.HIGH, "la sévérité d'origine revient"
    assert result.failure_scenario == finding.failure_scenario
    assert "cette ligne est bien" in result.provenance["réfutation contestée"]


def test_a_contested_refutation_is_never_written_down(tmp_path):
    """Only refutations are remembered, so a contested one keeps coming back."""
    from thot.engine.panel import PanelEngine
    from thot.memory import build_memory
    from thot.memory.base import record_verdicts

    members = [
        _Member(name, {
            "probe:": {"verdict": "refuted", "scenario": "corrigé depuis"},
            "review:": {"sound": False, "raison": "non, c'est bien là"},
        })
        for name in ("claude", "hermes")
    ]
    judged = analyse(tmp_path, [make_finding(severity=Severity.HIGH)],
                     PanelEngine(members=members), limit=1)

    memory = build_memory(tmp_path)
    try:
        assert record_verdicts(judged, memory) == 0
    finally:
        memory.close()


def test_a_minor_refutation_is_not_worth_a_second_reader(tmp_path):
    """Below MEDIUM the finding would not have woken anyone anyway."""
    from thot.engine.panel import PanelEngine

    members = [
        _Member(name, {"probe:": {"verdict": "refuted", "scenario": "bruit"}})
        for name in ("claude", "hermes")
    ]
    analyse(tmp_path, [make_finding(severity=Severity.LOW)],
            PanelEngine(members=members), limit=1)

    issued = [t.id for m in members for t in m.tasks]
    assert not any(i.startswith("review:") for i in issued)


def test_a_single_engine_does_not_review_its_own_refutation(tmp_path):
    """It would agree with itself, at full price."""
    engine = ScriptedEngine({
        "probe:": {"verdict": "refuted", "scenario": "faux positif"},
    })
    analyse(tmp_path, [make_finding(severity=Severity.CRITICAL)], engine, limit=1)

    assert not any(t.id.startswith("review:") for t in engine.tasks)


def test_a_contested_refutation_keeps_the_exploit_an_agent_had_written(tmp_path):
    """Restoring the deterministic text would throw away real work."""
    from thot.engine.panel import PanelEngine

    members = [
        _Member(name, {
            "probe:": {"verdict": "confirmed",
                       "scenario": "argv[1] atteint os.system sans filtre"},
            "refute:": {"refuted": True, "raison": "corrigé au commit suivant"},
            "review:": {"sound": False, "raison": "ce commit n'est pas audité"},
        })
        for name in ("claude", "hermes", "prime")
    ]
    result = analyse(tmp_path, [make_finding(severity=Severity.HIGH)],
                     PanelEngine(members=members), limit=1)[0]

    assert result.confidence is Confidence.PLAUSIBLE
    assert "argv[1] atteint os.system" in result.failure_scenario


def test_the_reviewer_is_told_to_read_what_the_refutation_leans_on(tmp_path):
    """A refutation almost always cites code outside the excerpt.

    The one that got through said the path handed to `dill.load` was fixed.
    It was not: the session id it is built from is taken verbatim from a
    JSONL header, in a different file the reviewer never opened. Validating
    an unchecked claim is how a real defect gets buried.
    """
    from thot.analysis.probe import _review_task

    task = _review_task(tmp_path, make_finding(), "scénario", "c'est validé en amont")

    assert "Va lire ces endroits" in task.instructions
    assert "vérifiée toi-même" in task.instructions


def test_every_task_names_the_file_by_its_absolute_path(tmp_path):
    """Measured on the three agents: Hermes cannot open a relative path.

    It answers "I cannot read that file", which reads like a refusal rather
    than a gap — so a third of the panel was blind to every claim that needed
    a second file opened, including the ones the reviewer is asked to check.
    """
    from thot.analysis.probe import _probe_task, _refute_task, _review_task

    finding = make_finding(path="src/app.py")
    expected = str((tmp_path / "src/app.py").resolve())

    for task in (
        _probe_task(tmp_path, finding),
        _refute_task(tmp_path, finding, "scénario"),
        _review_task(tmp_path, finding, "scénario", "raison"),
    ):
        assert expected in task.context
        assert "chemin ABSOLU" in task.context


# --- une réfutation sans motif n'est pas une réfutation --------------------
#
# `refuted: true` avec une `raison` vide était accepté : le finding passait en
# REFUTED/INFO avec le texte « Réfuté : » et rien après, puis la décision
# était mémorisée. Un défaut vivant réduit au silence jusqu'à ce que le code
# change, sans qu'aucune affirmation ne soit jamais faite.
#
# Ce n'est pas un plancher de longueur — Thot ne juge nulle part la longueur
# d'une justification. Vide n'est pas mince : c'est l'absence de prétention.


def _one_finding():
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    return Finding(
        id="f1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="app.py", line=2, symbol="m", ast_hash="h"),
        failure_scenario="argv atteint os.system",
    )


def _judged(toy_repo, refute_answer):
    from thot.analysis.probe import analyse

    engine = ScriptedEngine({
        "probe:": {"verdict": "confirmed", "scenario": "argv atteint os.system",
                   "severity": "high"},
        "refute:": refute_answer,
    })
    return analyse(toy_repo, [_one_finding()], engine, limit=1)[0]


def test_a_refutation_without_a_reason_is_refused(toy_repo):
    from thot.contracts import Confidence

    judged = _judged(toy_repo, {"refuted": True, "raison": ""})

    assert judged.confidence is not Confidence.REFUTED
    assert "Réfuté : \n" not in judged.failure_scenario
    assert (judged.provenance or {}).get("réfutation sans motif") == "écartée"


def test_a_reason_of_whitespace_is_no_reason(toy_repo):
    from thot.contracts import Confidence

    judged = _judged(toy_repo, {"refuted": True, "raison": "   \n  "})

    assert judged.confidence is not Confidence.REFUTED


def test_a_refutation_with_a_reason_still_stands(toy_repo):
    from thot.contracts import Confidence

    judged = _judged(
        toy_repo, {"refuted": True, "raison": "l'argument est une constante"}
    )

    assert judged.confidence is Confidence.REFUTED
    assert "constante" in judged.failure_scenario


def test_a_counter_argument_that_failed_is_still_recorded(toy_repo):
    judged = _judged(toy_repo, {"refuted": False, "raison": "tentative ratée"})

    assert (judged.provenance or {}).get("contre-argument écarté") == "tentative ratée"
