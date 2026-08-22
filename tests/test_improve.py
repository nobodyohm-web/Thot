"""The self-improvement loop: bounded rounds that converge.

What is under test is convergence. A loop that re-argues the same confirmed
finding every round is not improvement, it is a bill — and the mechanism
that prevents it is subtle enough to deserve a test of its own: refutations
converge because they are remembered, confirmations converge because the
session carries the ids it has already judged.
"""

from __future__ import annotations

from thot.analysis.probe import select_for_analysis
from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.improve import PartRound, backlog_of, improve


def _finding(name="a.py", confidence=Confidence.PLAUSIBLE):
    location = CodeRef(path=name, line=1, symbol="f", ast_hash="h")
    return Finding(
        id=Finding.compute_id("sink.os.system", location),
        rule="sink.os.system",
        severity=Severity.HIGH,
        confidence=confidence,
        location=location,
    )


def test_a_confirmed_finding_is_not_re_argued_next_round():
    """Confirmations are never written to memory — the session must remember."""
    finding = _finding()

    assert select_for_analysis([finding], 10) == [finding]
    assert select_for_analysis([finding], 10, skip={finding.id}) == []


def test_the_backlog_counts_what_a_further_round_could_still_judge():
    live, refuted = _finding("a.py"), _finding("b.py", Confidence.REFUTED)

    assert backlog_of([live, refuted]) == 1


def test_the_loop_stops_as_soon_as_a_round_settles_nothing(monkeypatch):
    """Paying for identical empty rounds answers nothing."""
    calls = []

    def _round(**kwargs):
        calls.append(kwargs)
        judged = 2 if len(calls) == 1 else 0
        return [PartRound(part="thot", judged=judged, refuted=judged, backlog=0)]

    monkeypatch.setattr("thot.improve.one_round", _round)

    session = improve(rounds=5)

    assert len(calls) == 2, "un tour productif, un tour vide, puis on arrête"
    assert session.judged == 2


def test_each_round_is_told_what_the_previous_ones_judged(monkeypatch):
    seen_sizes = []

    def _round(*, seen, **kwargs):
        seen_sizes.append(len(seen))
        seen.update({f"f{len(seen_sizes)}"})
        return [PartRound(part="thot", judged=1, refuted=1, backlog=1)]

    monkeypatch.setattr("thot.improve.one_round", _round)
    improve(rounds=3)

    assert seen_sizes == [0, 1, 2]


def test_a_contested_refutation_is_counted_on_its_own():
    """The one outcome that means the program caught itself burying a defect."""
    round_ = PartRound(part="hermes", judged=3, refuted=2, confirmed=0,
                       contested=1, backlog=4)

    assert "1 réfutation(s) contestée(s)" in round_.line()


def test_each_tree_is_credited_with_its_own_decisions(monkeypatch):
    """`audit_all` runs the trees in order; a caller needs the boundary.

    Slicing a flat list of decisions after the fact credited the first tree
    with every decision of the whole round.
    """
    from thot.contracts import Confidence
    from thot.improve import one_round

    class _Result:
        findings: list = []

    class _Part:
        def __init__(self, name):
            self.name, self.result, self.error = name, _Result(), ""
            self.ok = True

    def fake_audit_all(*, on_decided, **kwargs):
        for part, count in (("thot", 1), ("hermes", 2)):
            for index in range(count):
                on_decided(part, _finding(f"{part}{index}",
                                          Confidence.REFUTED))
        return [_Part("thot"), _Part("hermes")]

    monkeypatch.setattr("thot.fusion.audit.audit_all", fake_audit_all)

    result = {r.part: r for r in one_round(budget=1, parallel=1)}

    assert result["thot"].judged == 1
    assert result["hermes"].judged == 2


def test_a_round_where_everything_failed_stops_the_loop(monkeypatch):
    """A quota that ran out mid-pass must not buy four more identical rounds."""
    calls = []

    def _round(**kwargs):
        calls.append(kwargs)
        return [PartRound(part="hermes", judged=3, failed=3, backlog=40)]

    monkeypatch.setattr("thot.improve.one_round", _round)
    session = improve(rounds=5)

    assert len(calls) == 1
    assert session.failed == 3
    assert session.settled == 0
    assert "toutes les tâches ont échoué" in session.summary()


def test_a_failure_is_not_reported_as_an_undecided_finding():
    """They look identical in the finding and mean opposite things."""
    line = PartRound(part="prime", judged=2, failed=2, backlog=9).line()

    assert "2 échec(s)" in line
