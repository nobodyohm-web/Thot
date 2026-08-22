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


def _judged(confidence, provenance=None):
    from thot.contracts import CodeRef, Finding, Severity

    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    return Finding(
        id=Finding.compute_id("r", location), rule="r", severity=Severity.HIGH,
        confidence=confidence, location=location, provenance=provenance,
    )


def test_a_confirmation_is_news_and_a_refutation_is_not():
    """A refutation is housekeeping. A confirmation is the product."""
    from thot.contracts import Confidence
    from thot.improve import _is_news

    assert _is_news(_judged(Confidence.CONFIRMED)) is True
    assert _is_news(_judged(Confidence.REFUTED)) is False
    assert _is_news(_judged(Confidence.PLAUSIBLE)) is False


def test_a_contested_refutation_is_news_too():
    """It is the program saying it caught itself about to bury something."""
    from thot.contracts import Confidence
    from thot.improve import _is_news

    finding = _judged(Confidence.PLAUSIBLE,
                      {"réfutation contestée": "la ligne est bien là"})
    assert _is_news(finding) is True


def test_the_session_keeps_the_news_whole_not_counted(monkeypatch):
    """Counting sends the reader to grep the log — which is what happened."""
    from thot.contracts import Confidence

    def _round(*, news, **kwargs):
        if news is not None and not news:
            news.append(("hermes", _judged(Confidence.CONFIRMED)))
        return [PartRound(part="hermes", judged=1, confirmed=1, backlog=0)]

    monkeypatch.setattr("thot.improve.one_round", _round)
    session = improve(rounds=1)

    assert len(session.news) == 1
    assert session.news[0][0] == "hermes"


# --- « 0 jugement » a deux causes opposées, et une seule ligne ------------
#
# Mesuré en lançant une ronde réelle une fois le backlog vide : les trois
# arbres impriment « 0 jugé(s) · 0 en attente », mot pour mot ce qu'imprimait
# la boucle nocturne quand son PATH était cassé et qu'elle ne jugeait rien du
# tout. C'est la seule ligne que voit une boucle qui tourne sans témoin ;
# elle doit séparer « tout est décidé » de « rien n'a pu être fait ».


def test_a_quiet_round_says_the_tree_is_settled_not_merely_silent():
    from thot.improve import PartRound

    line = PartRound(part="hermes", findings=416, judged=0, backlog=0).line()

    assert "416" in line, line
    assert "décidé" in line or "réglé" in line, line


def test_a_tree_with_nothing_to_audit_is_not_called_settled():
    from thot.improve import PartRound

    line = PartRound(part="vide", findings=0, judged=0, backlog=0).line()

    assert "aucun finding" in line.lower(), line


def test_a_round_that_judged_something_keeps_its_ordinary_line():
    from thot.improve import PartRound

    line = PartRound(part="thot", findings=10, judged=3, refuted=3, backlog=2).line()

    assert "3 jugé(s)" in line
    assert "2 en attente" in line
    assert "décidé" not in line


def test_the_session_summary_separates_settled_from_broken():
    from thot.improve import PartRound, Session

    settled = Session(rounds=[[PartRound(part="thot", findings=4, judged=0, backlog=0)]])
    assert "Rien à juger" in settled.summary(), settled.summary()
    assert "4 finding(s)" in settled.summary(), settled.summary()

    broken = Session(rounds=[[PartRound(part="thot", findings=4, judged=0,
                                        failed=3, backlog=4)]])
    assert "Rien à juger" not in broken.summary(), broken.summary()
    assert "échec" in broken.summary(), broken.summary()


# --- une écriture pendant la boucle nocturne doit crier ---------------------
#
# `AuditResult.touched` existe parce que deux des trois agents peuvent écrire
# et qu'aucun drapeau ne les en empêche — sa docstring dit « ce qui ne peut
# pas être empêché est rendu impossible à manquer ». La session le dit, le CLI
# ponctuel le dit, et la boucle nocturne — le seul chemin sans témoin, qui
# tourne sur trois arbres — ne le disait pas du tout.


def test_a_tree_the_probe_wrote_to_says_so_on_its_own_row():
    from thot.improve import PartRound

    line = PartRound(part="hermes", findings=9, judged=2, refuted=2,
                     touched=("src/a.py", "src/b.py")).line()

    assert "2 fichier(s)" in line, line
    assert "modifié" in line, line


def test_a_quiet_round_still_reports_a_write():
    from thot.improve import PartRound

    # « rien à juger » ne doit surtout pas avaler l'alerte
    line = PartRound(part="thot", findings=4, judged=0, backlog=0,
                     touched=("src/a.py",)).line()

    assert "modifié" in line, line


def test_a_clean_round_says_nothing_about_writes():
    from thot.improve import PartRound

    assert "modifié" not in PartRound(part="thot", findings=4, judged=1).line()


def test_the_summary_names_the_files_that_were_written():
    from thot.improve import PartRound, Session

    session = Session(rounds=[[
        PartRound(part="hermes", findings=9, judged=1, touched=("src/a.py",)),
        PartRound(part="prime", findings=2, judged=1, touched=("lib/b.js",)),
    ]])
    text = session.summary()

    assert "src/a.py" in text and "lib/b.js" in text, text
    assert "modifié" in text


def test_the_summary_stays_silent_when_nothing_was_written():
    from thot.improve import PartRound, Session

    session = Session(rounds=[[PartRound(part="thot", findings=4, judged=1)]])

    assert "modifié" not in session.summary()


def test_one_round_carries_the_write_up_from_the_audit_result(monkeypatch):
    """The wiring itself, not a PartRound built by hand in a test.

    Written after the first version of these tests passed while the line that
    reads `part.result.touched` was deleted: every assertion constructed its
    own PartRound, so none of them ever crossed the real path.
    """
    from thot.improve import one_round

    class _Result:
        findings: list = []
        touched = ("hermes/cron/monitor.py",)

    class _Part:
        def __init__(self, name):
            self.name, self.result, self.error = name, _Result(), ""
            self.ok = True

    monkeypatch.setattr("thot.fusion.audit.audit_all",
                        lambda **kwargs: [_Part("hermes")])

    round_, = one_round(budget=1, parallel=1)

    assert round_.touched == ("hermes/cron/monitor.py",)
    assert "modifié" in round_.line()


# --- un tour où tout a échoué n'est pas un succès --------------------------
#
# `Session.summary()` sait le dire — « Aucun verdict : toutes les tâches ont
# échoué… un quota épuisé ou un agent absent se règle avant de relancer » —
# mais `thot improve` rendait 0 quand même. Le job nocturne, lui, sort non nul
# dans exactement le même cas, et l'asymétrie n'était expliquée nulle part :
# `thot improve && …` enchaînait comme si le tour avait travaillé.


def _improving(monkeypatch, session):
    from thot import cli

    monkeypatch.setattr("thot.improve.improve", lambda **kwargs: session)
    monkeypatch.setattr("thot.cli.run_improvement", lambda **kwargs: session,
                        raising=False)
    return cli


def test_a_round_where_every_task_failed_is_not_a_success(capsys, monkeypatch):
    from thot.improve import PartRound, Session

    session = Session(rounds=[[PartRound(part="thot", findings=4, judged=0,
                                         failed=3, backlog=4)]])
    cli = _improving(monkeypatch, session)

    code = cli.main(["improve", "--rounds", "1"])
    out = capsys.readouterr().out

    assert "toutes les tâches ont échoué" in out, out
    assert code != 0


def test_an_ordinary_round_still_succeeds(capsys, monkeypatch):
    from thot.improve import PartRound, Session

    session = Session(rounds=[[PartRound(part="thot", findings=4, judged=2,
                                         refuted=2, backlog=0)]])
    cli = _improving(monkeypatch, session)

    code = cli.main(["improve", "--rounds", "1"])
    capsys.readouterr()

    assert code == 0


def test_a_quiet_round_with_nothing_to_judge_succeeds(capsys, monkeypatch):
    from thot.improve import PartRound, Session

    session = Session(rounds=[[PartRound(part="thot", findings=4, judged=0,
                                         backlog=0)]])
    cli = _improving(monkeypatch, session)

    code = cli.main(["improve", "--rounds", "1"])
    capsys.readouterr()

    assert code == 0


def test_a_round_that_judged_something_despite_failures_succeeds(capsys,
                                                                 monkeypatch):
    """The realistic case: a quota running out part-way through.

    Without it the condition could be narrowed to `session.failed` alone and
    nothing would notice — which is what the mutation showed.
    """
    from thot.improve import PartRound, Session

    session = Session(rounds=[[PartRound(part="thot", findings=6, judged=2,
                                         refuted=2, failed=3, backlog=2)]])
    cli = _improving(monkeypatch, session)

    code = cli.main(["improve", "--rounds", "1"])
    capsys.readouterr()

    assert code == 0
