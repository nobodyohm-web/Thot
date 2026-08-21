"""Verdict memory: decide once, never re-litigate.

The expensive part of an audit is not finding candidates, it is deciding what
they mean. Losing those decisions between runs is what makes security tooling
unbearable — the same forty false positives, every week, forever.

The pivot is that a verdict is keyed on Finding.compute_id, which hashes the
normalised AST of the symbol. Reformat the file and the verdict holds. Change
what the code does and the verdict expires by construction, so a dismissal can
never hide a regression.
"""

from __future__ import annotations

import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.memory import Decision, Verdict, apply_memory
from thot.memory.sqlite import SqliteMemory


@pytest.fixture
def memory(tmp_path):
    store = SqliteMemory.open(tmp_path / "memory.db")
    yield store
    store.close()


def make_finding(ast_hash="h1", rule="sink.os.system", severity=Severity.HIGH):
    location = CodeRef(path="app.py", line=9, symbol="run", ast_hash=ast_hash)
    return Finding(
        id=Finding.compute_id(rule, location),
        rule=rule,
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
        failure_scenario="candidat",
    )


# -- storage -----------------------------------------------------------------


def test_a_verdict_survives_a_reopen(tmp_path):
    path = tmp_path / "m.db"
    finding = make_finding()
    first = SqliteMemory.open(path)
    first.remember(Verdict.of(finding, Decision.REFUTED, "entrée constante", "dev"))
    first.close()

    second = SqliteMemory.open(path)
    try:
        assert second.recall(finding.id).reason == "entrée constante"
    finally:
        second.close()


def test_recalling_an_unknown_finding_gives_nothing(memory):
    assert memory.recall("jamais-vu") is None


def test_remembering_twice_updates_rather_than_duplicates(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "première raison"))
    memory.remember(Verdict.of(finding, Decision.ACCEPTED, "deuxième raison"))
    assert len(memory.all_verdicts()) == 1
    assert memory.recall(finding.id).decision is Decision.ACCEPTED


def test_forgetting_removes_the_verdict(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "x"))
    assert memory.forget(finding.id) is True
    assert memory.recall(finding.id) is None
    assert memory.forget(finding.id) is False


# -- application -------------------------------------------------------------


def test_a_refuted_finding_is_downgraded_not_deleted(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "entrée constante"))
    out = apply_memory([finding], memory)
    assert len(out) == 1
    assert out[0].confidence is Confidence.REFUTED
    assert "entrée constante" in out[0].failure_scenario


def test_an_accepted_risk_drops_to_info(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.ACCEPTED, "risque assumé"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.INFO
    assert "risque assumé" in out[0].failure_scenario


def test_an_untouched_finding_passes_through(memory):
    finding = make_finding()
    assert apply_memory([finding], memory)[0] == finding


def test_changing_the_code_expires_the_verdict(memory):
    """The whole safety property, in one test."""
    original = make_finding(ast_hash="before")
    memory.remember(Verdict.of(original, Decision.REFUTED, "sûr à l'époque"))

    edited = make_finding(ast_hash="after")
    out = apply_memory([edited], memory)
    assert out[0].confidence is Confidence.PLAUSIBLE
    assert "sûr à l'époque" not in out[0].failure_scenario


def test_a_fixed_finding_coming_back_is_a_regression(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.FIXED, "corrigé en mars"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.HIGH
    assert "régression" in out[0].failure_scenario.lower()
    assert out[0].provenance.get("régression") is True


def test_provenance_records_where_the_decision_came_from(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "x", "dev"))
    out = apply_memory([finding], memory)
    assert out[0].provenance["mémoire"] == "refuted"
    assert out[0].provenance["décidé par"] == "dev"


# -- the expensive pass is paid once ----------------------------------------


def test_adversarial_refutations_are_recorded(memory):
    """A refutation costs two model calls. It should cost them once."""
    from thot.memory import record_verdicts

    refuted = make_finding()
    refuted = refuted.__class__(**{**refuted.__dict__,
                                   "confidence": Confidence.REFUTED,
                                   "failure_scenario": "Réfuté : constante"})
    record_verdicts([refuted], memory, author="thot")
    assert memory.recall(refuted.id).decision is Decision.REFUTED


def test_only_refutations_are_recorded_automatically(memory):
    from thot.memory import record_verdicts

    confirmed = make_finding()
    record_verdicts([confirmed], memory, author="thot")
    assert memory.all_verdicts() == []


# -- what people actually type -----------------------------------------------


@pytest.mark.parametrize("word,expected", [
    ("refute", Decision.REFUTED), ("refuted", Decision.REFUTED),
    ("réfuté", Decision.REFUTED), ("écarter", Decision.REFUTED),
    ("accept", Decision.ACCEPTED), ("accepté", Decision.ACCEPTED),
    ("fix", Decision.FIXED), ("corrigé", Decision.FIXED),
    ("REFUTE", Decision.REFUTED), (" fixed ", Decision.FIXED),
])
def test_decisions_accept_what_people_type(word, expected):
    assert Decision.parse(word) is expected


def test_an_unknown_word_is_rejected_not_guessed():
    assert Decision.parse("peut-être") is None


def test_a_dismissed_finding_leaves_the_top_of_the_report(memory):
    """Dismissing must change the ranking, not just an invisible field."""
    finding = make_finding(severity=Severity.HIGH)
    memory.remember(Verdict.of(finding, Decision.REFUTED, "faux positif"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.INFO
    assert out[0].confidence is Confidence.REFUTED
