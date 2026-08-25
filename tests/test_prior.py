"""What a rule has been worth, and where the budget goes because of it.

The ledger this was written against: 638 distinct findings judged by a
model, 9 confirmed. `sink.network` accounts for 171 of them and has never
confirmed anything. Ranking by severity alone spent the budget there anyway,
every run, because severity says how bad a thing would be if true and
nothing said how often it is.
"""

from __future__ import annotations

from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.scoring.prior import NOISE_CEILING, Prior, wilson_upper


def _finding(rule="sink.network", *, path="src/app.py", line=3,
             severity=Severity.MEDIUM, source_rule="", traced=True):
    location = CodeRef(path=path, line=line, symbol="fetch", ast_hash="h")
    provenance = {"source_rule": source_rule} if source_rule else None
    return Finding(
        id=Finding.compute_id(rule, location),
        rule=rule,
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
        taint_path=(location, location) if traced else (),
        failure_scenario="candidat déterministe",
        provenance=provenance,
    )


# --- the interval ----------------------------------------------------------


def test_a_rule_nobody_has_judged_keeps_every_benefit_of_the_doubt():
    """The property that matters most: a new rule is never buried by its own
    lack of history, or no rule could ever earn one."""
    assert wilson_upper(0, 0) == 1.0
    assert Prior().ceiling("toute.nouvelle.règle") == 1.0
    assert not Prior().noisy("toute.nouvelle.règle")


def test_three_unlucky_candidates_are_not_evidence():
    """0/3 and 0/200 are the same ratio. Only one of them is an argument."""
    assert wilson_upper(0, 3) > 0.5
    assert wilson_upper(0, 200) < 0.02


def test_more_evidence_never_raises_the_ceiling():
    ceilings = [wilson_upper(0, n) for n in (1, 10, 50, 100, 500)]
    assert ceilings == sorted(ceilings, reverse=True)


def test_one_confirmation_lifts_a_rule_out_of_the_noise():
    """A rule climbs back on its own. Nothing has to be re-enabled by hand —
    which is what makes the gate safe to apply to a security tool."""
    buried = Prior({"r": (200, 0)})
    assert buried.noisy("r")
    assert not Prior({"r": (200, 5)}).noisy("r")


def test_the_measured_ledger_puts_sink_network_below_the_floor():
    """The real numbers this was built from, kept as a regression."""
    prior = Prior({"sink.network": (171, 0), "sink.sql": (127, 1),
                   "sink.fs.write": (98, 1)})
    assert prior.noisy("sink.network")
    assert prior.ceiling("sink.network") < NOISE_CEILING
    assert not prior.noisy("sink.fs.write"), "5,56 % reste au-dessus du plancher"


# --- counting the ledger ---------------------------------------------------


def test_the_ledger_counts_candidates_and_not_rows(tmp_path):
    """A refuted finding is re-written on every later run.

    15 008 judged rows for 638 distinct candidates on the machine this was
    written on. Counting rows narrows every interval by that factor — and
    unevenly, since a nightly-audited tree would look twenty times better
    evidenced than one audited twice.
    """
    from thot.store.db import Store

    store = Store.open(tmp_path / "store.db")
    finding = _finding("sink.network")
    decided = Finding(**{**finding.__dict__, "confidence": Confidence.REFUTED})
    for _ in range(40):
        run_id = store.start_run(root=str(tmp_path), commit=None)
        store.save_findings(run_id, [decided])

    ((rule, judged, confirmed),) = store.rule_precision()
    assert rule == "sink.network"
    assert judged == 1, "quarante runs sur un seul candidat restent un candidat"
    assert confirmed == 0
    assert not Prior.from_store(store).noisy("sink.network")


def test_an_unreadable_ledger_costs_the_ranking_and_not_the_audit():
    class Broken:
        def rule_precision(self):
            raise RuntimeError("base illisible")

    assert Prior.from_store(Broken()).counts == {}


# --- where the budget goes -------------------------------------------------


def test_a_measured_noise_rule_is_not_argued():
    from thot.analysis.probe import select_for_analysis

    prior = Prior({"sink.network": (171, 0)})
    pool = [_finding("sink.network", line=n) for n in range(5)]
    assert select_for_analysis(pool, 20, prior=prior) == []


def test_the_findings_are_still_reported_they_are_only_not_argued():
    """Deferring is not suppressing. The gate decides what a model is paid
    to discuss, never what the reader is shown."""
    from thot.analysis.probe import select_for_analysis

    prior = Prior({"sink.network": (171, 0)})
    pool = [_finding("sink.network")]
    assert select_for_analysis(pool, 20, prior=prior) == []
    assert pool[0].confidence is Confidence.PLAUSIBLE


def test_a_caller_can_still_ask_for_the_whole_pool():
    from thot.analysis.probe import select_for_analysis

    prior = Prior({"sink.network": (171, 0)})
    pool = [_finding("sink.network")]
    assert select_for_analysis(pool, 20, prior=prior, spend_on_noise=True) == pool


def test_no_ledger_ranks_exactly_as_before():
    from thot.analysis.probe import select_for_analysis

    pool = [_finding("sink.network", line=n) for n in range(3)]
    assert len(select_for_analysis(pool, 20)) == 3


# --- a traced source outranks an assumption --------------------------------


def test_a_named_source_is_argued_before_an_assumption():
    """Two thirds of every taint pool rests on "this parameter could carry
    anything" — 538 of 787 candidates on hermes/. A candidate traced to argv
    or to a request is a stronger claim about the same sink."""
    from thot.analysis.probe import select_for_analysis

    assumed = _finding("sink.fs.read", line=1)
    traced = _finding("sink.fs.read", line=2, source_rule="source.argv")
    chosen = select_for_analysis([assumed, traced], 1)
    assert chosen == [traced]


def test_severity_still_decides_between_equals():
    from thot.analysis.probe import select_for_analysis

    low = _finding("sink.fs.read", line=1, severity=Severity.MEDIUM,
                   source_rule="source.argv")
    high = _finding("sink.fs.read", line=2, severity=Severity.CRITICAL,
                    source_rule="source.argv")
    assert select_for_analysis([low, high], 1) == [high]


def test_a_pattern_rule_is_not_an_assumption():
    """It proves no path and claims none, so the question does not apply —
    and pattern rules hold three of the nine confirmations ever produced."""
    from thot.analysis.probe import assumed_source, select_for_analysis

    pattern = _finding("pattern.eval_injection", line=1, traced=False)
    assert not assumed_source(pattern)

    assumed = _finding("sink.fs.read", line=2)
    assert select_for_analysis([assumed, pattern], 1) == [pattern]


# --- the count reaches the reader ------------------------------------------


def test_the_deep_pass_counts_what_it_held_back(tmp_path, monkeypatch):
    """A budget that quietly skips a third of the pool is indistinguishable
    from one that found nothing there. So it is counted, and printed."""
    from thot.analysis.deep import run_deep_pass
    from thot.engine import AgentResult, EngineCapabilities

    class Silent:
        @property
        def capabilities(self):
            return EngineCapabilities(name="fake")

        def run(self, task):
            return AgentResult(task_id=task.id, error="rien à juger")

        def fan_out(self, tasks):
            return [self.run(task) for task in tasks]

    monkeypatch.setattr(Prior, "from_home",
                        classmethod(lambda cls: Prior({"sink.network": (171, 0)})))
    (tmp_path / "app.py").write_text("x = 1\n")

    pool = [_finding("sink.network", line=n) for n in range(4)]
    outcome = run_deep_pass(tmp_path, pool, Silent(), files=("app.py",), limit=20)

    assert outcome.deferred == 4
    assert len(outcome.findings) == 4, "rien n'est retiré du rapport"


def test_the_rules_command_prints_the_same_arithmetic(monkeypatch, capsys):
    """The gate decides where money goes. One nobody can inspect is one
    nobody can disagree with."""
    import argparse

    from thot.cli import _cmd_rules

    monkeypatch.setattr(Prior, "from_home",
                        classmethod(lambda cls: Prior({"sink.network": (171, 0),
                                                       "sink.eval": (3, 1)})))
    assert _cmd_rules(argparse.Namespace(all=False)) == 0

    printed = capsys.readouterr().out
    assert "sink.network" in printed and "bruit mesuré" in printed
    assert "sink.eval" in printed and "171/174" in printed
