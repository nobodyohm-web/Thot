"""Candidates that cannot be settled must stop being paid for first.

Selection is worst-first, which is right until one of them cannot be judged
at all: it keeps its severity, so it is picked first again every round.
Measured on one finding in a 1 660-line file — four attempts across three
runs, three of them buying the same wall.
"""

from __future__ import annotations

from thot.analysis import attempts
from thot.analysis.probe import select_for_analysis
from thot.contracts import CodeRef, Confidence, Finding, Severity


def _finding(name: str, severity: Severity = Severity.HIGH) -> Finding:
    location = CodeRef(path=name, line=1, symbol="f", ast_hash="h")
    return Finding(
        id=Finding.compute_id("r", location), rule="r", severity=severity,
        confidence=Confidence.PLAUSIBLE, location=location,
    )


def test_a_failure_is_counted_and_a_success_clears_it(isolated_home):
    assert attempts.record_failure("abc") == 1
    assert attempts.record_failure("abc") == 2
    assert "abc" in attempts.demoted()

    attempts.clear("abc")
    assert attempts.demoted() == set()


def test_one_failure_is_not_enough_to_demote(isolated_home):
    """A single failure is usually the world, not the finding."""
    attempts.record_failure("abc")
    assert attempts.demoted() == set()


def test_a_demoted_candidate_goes_last_but_stays_eligible():
    worst = _finding("a.py", Severity.CRITICAL)
    ordinary = _finding("b.py", Severity.LOW)

    normal = select_for_analysis([worst, ordinary], 10)
    assert [f.location.path for f in normal] == ["a.py", "b.py"]

    demoted = select_for_analysis([worst, ordinary], 10, None, {worst.id})
    assert [f.location.path for f in demoted] == ["b.py", "a.py"]


def test_a_small_budget_spends_itself_on_what_can_be_judged():
    walled = _finding("a.py", Severity.CRITICAL)
    ordinary = _finding("b.py", Severity.LOW)

    chosen = select_for_analysis([walled, ordinary], 1, None, {walled.id})
    assert [f.location.path for f in chosen] == ["b.py"]


def test_an_unreadable_ledger_is_an_empty_one(isolated_home):
    attempts.ledger_path().write_text("pas du json", encoding="utf-8")
    assert attempts.load() == {}
    assert attempts.demoted() == set()
