"""The half of `evolve` that stopped guessing: two agents, and a real score.

The loop already ran, and the measured result was that it worked and changed
nothing worth having. Two causes, and this file covers both of them.

*It was scored on itself.* The guarded number was `provenance`, a ratio Thot
computes over its own findings, so "better" meant "better by its own
account". `bench_metrics` swaps in a corpus somebody else labelled — on
`flask` at floor=medium Thot measures TPR 9.6 %, FPR 0.5 %, J +9.0 %, and
that J is the number a change now has to survive.

*And only one agent ever wrote.* `Cascade.turn` picks one member per turn,
which caps the pairing at the better of the two by construction. `fused_apply`
calls both on every goal, in an order that can be checked at the seam, and
that difference is the feature — so it is what is asserted hardest here.

Every agent below is a `Fake` and every measurement is monkeypatched. A test
that starts an interpreter to check a prompt string is a test nobody runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot.bench.score import Score, Tally
from thot.engine.base import AgentResult, AgentTask, EngineCapabilities
from thot.engine.cascade import Cascade
from thot.evolve import (
    BENCH_GUARDS,
    DESIGNER,
    FUSED_BUILDER,
    GOAL_SAMPLES,
    Attempt,
    NoFusion,
    bench_gate,
    bench_metrics,
    fused_apply,
    goals_from_bench,
)
from thot.llm.base import Usage


class Fake:
    """One agent, recording what it was handed and answering a fixed line.

    Both real members are one-shot, so a fake that only records the task it
    received sees exactly what the real one would: whatever Thot put in the
    prompt is the whole of what the agent knows.
    """

    def __init__(self, name: str, text: str = "", error: str | None = None,
                 log: list[str] | None = None) -> None:
        self.name = name
        self.seen: list[AgentTask] = []
        self.text = text if text or error else f"[{name}] répond"
        self.error = error
        # Shared between the two fakes when the *order* of the calls is the
        # property under test: two counters cannot say which ran first.
        self.log = log if log is not None else []

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(name=self.name)

    def run(self, task: AgentTask) -> AgentResult:
        self.seen.append(task)
        self.log.append(self.name)
        return AgentResult(task_id=task.id, text=self.text, error=self.error,
                           usage=Usage(input_tokens=7, output_tokens=3))

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


def _cascade(root: Path, hermes: Fake | None, prime: Fake | None) -> Cascade:
    members = {name: agent for name, agent
               in (("hermes", hermes), ("prime", prime)) if agent is not None}
    return Cascade(root=root, members=members)


GOAL = "Catégorie « xss » (CWE-79) : J = -100 %"


# -- the fusion itself --------------------------------------------------------


def test_one_goal_runs_hermes_once_and_then_prime_once(tmp_path):
    """A turn calls one member; a fusion calls both, and that is the feature.

    The two are run here on the same goal, side by side, because the claim is
    a comparison. `Cascade.turn` wakes one agent and leaves the other asleep —
    it reaches for the second only when the first returns an error — which
    caps the pairing at the better of the two by construction. `fused_apply`
    hands that same goal to both, design first.
    """
    lone_hermes, lone_prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    _cascade(tmp_path, lone_hermes, lone_prime).turn(GOAL)
    assert len(lone_hermes.seen) + len(lone_prime.seen) == 1, "un tour, un membre"

    order: list[str] = []
    hermes = Fake("hermes", "SPEC", log=order)
    prime = Fake("prime", "fait", log=order)

    fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert order == ["hermes", "prime"], "concevoir puis construire, une fois chacun"
    assert hermes.seen[0].id == "evolve-design-1"
    assert prime.seen[0].id == "evolve-build-1"


def test_prime_is_handed_what_hermes_wrote(tmp_path):
    """A fusion whose second agent cannot read the first is two strangers."""
    design = "Cause : `sink.sql` ne suit pas les f-strings, catalog.py:212."
    hermes, prime = Fake("hermes", design), Fake("prime", "fait")

    fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    handed = prime.seen[-1].prompt()
    assert design in handed
    assert GOAL in handed, "l'objectif mesuré voyage avec la spécification"


def test_each_half_is_told_the_job_the_other_one_is_not_doing(tmp_path):
    """Two agents are worth more than one only if they do different work.

    Asserted on the constants themselves, not on a copy: a test that keeps
    its own wording still passes after the prompt stops saying it.
    """
    assert "tu n'écris pas le code" in DESIGNER.lower()
    assert "ne l'applique pas" in FUSED_BUILDER
    assert "fausse" in FUSED_BUILDER, "l'implémenteur peut refuser la spec"

    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert "tu n'écris pas le code" in hermes.seen[-1].prompt().lower()
    assert "ne l'applique pas" in prime.seen[-1].prompt()


def test_the_scope_travels_to_the_builder_and_not_to_the_designer(tmp_path):
    """Only one of the two can write a file, so only one is told where."""
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime), scope=("src", "tests"))

    apply(GOAL, Attempt(goal=GOAL))

    assert "src, tests" in prime.seen[-1].prompt()
    assert "src, tests" not in hermes.seen[-1].prompt()


def test_the_brief_reaches_both_agents_as_context(tmp_path):
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime), brief="Thot v0.9")

    apply(GOAL, Attempt(goal=GOAL))

    assert hermes.seen[-1].context == "Thot v0.9"
    assert prime.seen[-1].context == "Thot v0.9"


def test_what_past_runs_tried_reaches_the_designer_and_not_the_builder(tmp_path):
    """The record constrains what to *design*, so only the designer gets it.

    Goals come from the measurement and the measurement barely moves in one
    round: without a record the next round reads the same worst categories and
    gets back the specification that was already built, measured and reverted.
    Prime is spared it on purpose — it judges the specification against the
    code in front of it, not against who failed before.
    """
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime), brief="Thot v0.9",
                        history=lambda goal: f"Annulé la dernière fois : {goal}")

    apply(GOAL, Attempt(goal=GOAL))

    assert "Annulé la dernière fois" in hermes.seen[-1].context
    assert GOAL in hermes.seen[-1].context, "l'historique est interrogé sur cet objectif"
    assert "Thot v0.9" in hermes.seen[-1].context, "le brief survit à l'historique"
    assert prime.seen[-1].context == "Thot v0.9"


def test_a_history_that_has_nothing_to_say_leaves_the_brief_untouched(tmp_path):
    """A first run has no record at all, and a brief padded with two blank
    lines is a brief that reads as though something went missing."""
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime), brief="Thot v0.9",
                        history=lambda goal: "")

    apply(GOAL, Attempt(goal=GOAL))

    assert hermes.seen[-1].context == "Thot v0.9"


def test_an_empty_design_stops_the_turn_before_prime_is_reached(tmp_path):
    """Handing Prime an empty spec is the single-agent loop wearing two names.

    Whitespace counts as empty: an agent that answered with a blank line has
    said nothing, and a builder given nothing invents its own objective.
    """
    hermes, prime = Fake("hermes", "   \n\n  "), Fake("prime", "fait")

    summary = fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert summary == ""
    assert prime.seen == []


def test_an_error_from_hermes_names_the_design_half_and_spares_prime(tmp_path):
    hermes = Fake("hermes", error="quota atteint")
    prime = Fake("prime", "fait")

    with pytest.raises(RuntimeError) as raised:
        fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert "conception" in str(raised.value)
    assert "quota atteint" in str(raised.value)
    assert prime.seen == []


def test_an_error_from_prime_names_the_build_half(tmp_path):
    hermes = Fake("hermes", "SPEC")
    prime = Fake("prime", error="outil indisponible")

    with pytest.raises(RuntimeError) as raised:
        fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert "application" in str(raised.value)
    assert "outil indisponible" in str(raised.value)


@pytest.mark.parametrize("missing", ["hermes", "prime"])
def test_a_cascade_missing_one_agent_refuses_at_build_time(tmp_path, missing):
    """Before the first goal, not on it.

    A run that discovers halfway through that it only has one agent has
    already spent a snapshot, a design and an unknown amount of the user's
    quota on a loop it cannot complete.
    """
    hermes = None if missing == "hermes" else Fake("hermes")
    prime = None if missing == "prime" else Fake("prime")

    with pytest.raises(NoFusion) as raised:
        fused_apply(_cascade(tmp_path, hermes, prime))

    assert "deux agents" in str(raised.value)
    assert "fusion status" in str(raised.value), "dire quoi lancer pour savoir lequel manque"


def test_building_the_fused_loop_calls_no_agent_until_a_goal_arrives(tmp_path):
    """The refusal above lands at build time; the build itself costs nothing.

    Both members are one-shot agents running on the user's own quota, and
    `evolve` builds the applier before the first snapshot — a construction
    that greets its two agents has spent two calls on a run that may never
    reach a goal.
    """
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")

    apply = fused_apply(_cascade(tmp_path, hermes, prime))

    assert hermes.seen == [] and prime.seen == []
    assert apply(GOAL, Attempt(goal=GOAL)) == "fait", "et il marche quand même"


def test_something_that_is_not_a_cascade_at_all_refuses_at_build_time():
    """No `members` attribute either — an AttributeError here reads as a bug
    in Thot, and the loop knows perfectly well what is wrong."""
    with pytest.raises(NoFusion):
        fused_apply(object())


def test_the_summary_is_primes_last_non_blank_line(tmp_path):
    hermes = Fake("hermes", "SPEC")
    prime = Fake("prime", "j'ai lu catalog.py\n\nsink.sql suit les f-strings\n\n  \n")

    summary = fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert summary == "sink.sql suit les f-strings"


def test_a_summary_longer_than_two_hundred_characters_is_cut(tmp_path):
    """The summary is printed per attempt and stored in `Attempt.summary`; an
    agent that ends on a paragraph must not turn the run's log into one."""
    hermes = Fake("hermes", "SPEC")
    prime = Fake("prime", "préambule\n" + "x" * 500)

    summary = fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert summary == "x" * 200


def test_a_builder_that_says_nothing_at_all_yields_an_empty_summary(tmp_path):
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "\n \n")

    summary = fused_apply(_cascade(tmp_path, hermes, prime))(GOAL, Attempt(goal=GOAL))

    assert summary == ""
    assert len(prime.seen) == 1, "un tour vide reste un tour"


def test_the_design_is_shown_to_the_observer_with_the_goal_it_answers(tmp_path):
    """`thot evolve` prints the specification as it is written — a fusion the
    user cannot read is a fusion the user cannot correct."""
    seen: list[tuple[str, str]] = []
    hermes, prime = Fake("hermes", "SPEC de Hermes"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime),
                        on_design=lambda goal, design: seen.append((goal, design)))

    apply(GOAL, Attempt(goal=GOAL))

    assert seen == [(GOAL, "SPEC de Hermes")]


def test_omitting_the_observer_changes_nothing_about_the_turn(tmp_path):
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    watched = fused_apply(_cascade(tmp_path, hermes, prime),
                          on_design=lambda goal, design: None)(GOAL, Attempt(goal=GOAL))
    watched_prompt = prime.seen[-1].prompt()

    quiet_hermes, quiet_prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    quiet = fused_apply(_cascade(tmp_path, quiet_hermes, quiet_prime))(
        GOAL, Attempt(goal=GOAL))

    assert quiet == watched
    assert quiet_prime.seen[-1].prompt() == watched_prompt


def test_turns_are_numbered_so_two_goals_are_two_distinct_pairs(tmp_path):
    """The task id is what a run's transcript is read back by; two goals that
    share one are two goals nobody can tell apart afterwards."""
    hermes, prime = Fake("hermes", "SPEC"), Fake("prime", "fait")
    apply = fused_apply(_cascade(tmp_path, hermes, prime))

    apply("objectif un", Attempt(goal="objectif un"))
    apply("objectif deux", Attempt(goal="objectif deux"))

    assert [task.id for task in hermes.seen] == ["evolve-design-1", "evolve-design-2"]
    assert [task.id for task in prime.seen] == ["evolve-build-1", "evolve-build-2"]


# -- the measurement, turned into work ---------------------------------------


# CWE-79 is claimed by a rule in `report/cwe.py`; CWE-88 is claimed by none.
# Which one a fixture uses decides which of the three diagnoses a goal gets,
# so it is named rather than left to a default.
CLAIMED, UNCLAIMED = 79, 88


def _score(*, cwe: int = CLAIMED, **categories: Tally) -> Score:
    return Score(
        suite="corpus",
        by_category=dict(categories),
        cwe={name: cwe for name in categories},
    )


def test_one_goal_is_built_per_worst_category_up_to_the_limit():
    score = _score(
        xss=Tally(tp=0, fp=8, fn=8, tn=0),
        xpath=Tally(tp=0, fp=0, fn=5, tn=5),
        sqli=Tally(tp=9, fp=1, fn=1, tn=9),
        trust=Tally(tp=10, fp=0, fn=0, tn=10),
    )

    assert len(goals_from_bench(score, limit=2)) == 2
    assert len(goals_from_bench(score, limit=10)) == 4


def test_an_inverted_rule_and_a_silent_one_get_different_diagnoses():
    """Two failures that look alike in the counts and need opposite work.

    A category at −100 % has a rule that fires on the safe half: fixing it
    wins twice. A category at 0/0 fires on nothing. Telling an agent to
    "improve xpath" when the answer is "write a rule" wastes the turn.
    """
    score = _score(
        inversee=Tally(tp=0, fp=8, fn=8, tn=0),
        absente=Tally(tp=0, fp=0, fn=5, tn=5),
        cwe=UNCLAIMED,
    )

    inverted, missing = goals_from_bench(score, limit=2)

    assert "inversée" in inverted and "manque" not in inverted
    assert "manque" in missing and "inversée" not in missing


def test_a_silent_category_whose_rule_exists_is_not_told_to_write_another():
    """The third diagnosis, and the one the ranking exists to surface.

    Measured: 7 of the 54 silent categories — `xss`, `ssrf`, `pathtraver`
    among them — have a rule mapped to their class that never matches the
    code. An agent told "there is no rule" writes a second one beside the
    first, and neither fires.
    """
    score = _score(muette=Tally(tp=0, fp=0, fn=5, tn=5), cwe=CLAIMED)

    goal, = goals_from_bench(score, limit=1)

    assert "revendique déjà" in goal
    assert "il manque une règle" not in goal


def test_the_two_silences_are_told_apart_within_one_measurement():
    """Both causes present at once: each goal must carry its own diagnosis."""
    score = Score(
        suite="corpus",
        by_category={"muette": Tally(tp=0, fp=0, fn=5, tn=5),
                     "absente": Tally(tp=0, fp=0, fn=5, tn=5)},
        cwe={"muette": CLAIMED, "absente": UNCLAIMED},
    )

    first, second = goals_from_bench(score, limit=2)

    # The claimed one is ranked first — it is the cheaper fix.
    assert "muette" in first and "revendique déjà" in first
    assert "absente" in second and "aucune règle ne revendique" in second


def test_a_category_that_is_merely_weak_gets_neither_diagnosis():
    """Half the true positives and no false ones is a threshold problem, and
    naming it a missing rule would send the agent to write a second one."""
    score = _score(faible=Tally(tp=5, fp=0, fn=5, tn=10))

    goal, = goals_from_bench(score, limit=1)

    assert "inversée" not in goal
    assert "manque" not in goal
    assert "J = +50%" in goal, "un J positif reste un J, pas un diagnostic"


def test_a_goal_carries_file_paths_the_agent_can_open():
    """`combine` qualifies a case as `flask/BenchmarkTest01126`; the file is
    `benchmark_test_01126.py`. A goal that hands over the key alone starts
    with the agent hunting for the file it was just told about."""
    score = Score(
        suite="corpus",
        by_category={"xss": Tally(tp=0, fp=1, fn=1, tn=1)},
        missed={"xss": ("flask/BenchmarkTest01126",)},
        invented={"xss": ("django/BenchmarkTest00042",)},
        cwe={"xss": 79},
    )

    goal, = goals_from_bench(score, limit=1, corpus="/corpus/bp")

    assert "/corpus/bp/flask/testcode/benchmark_test_01126.py" in goal
    assert "/corpus/bp/django/testcode/benchmark_test_00042.py" in goal


def test_without_a_corpus_the_paths_stay_relative_instead_of_becoming_keys():
    score = Score(
        suite="corpus",
        by_category={"xss": Tally(tp=0, fp=0, fn=1, tn=1)},
        missed={"xss": ("flask/BenchmarkTest01126",)},
        cwe={"xss": 79},
    )

    goal, = goals_from_bench(score, limit=1)

    assert "flask/testcode/benchmark_test_01126.py" in goal
    assert "BenchmarkTest01126" not in goal


def test_a_corpus_that_is_a_single_suite_is_not_given_that_suites_name_twice():
    """`load_all` accepts being pointed straight at one suite, and `combine`
    stamps the suite name onto every key regardless — so `--corpus …/bp/flask`
    wrote `…/bp/flask/flask/testcode/x.py` into every goal, a path nothing
    can open."""
    score = Score(
        suite="flask",
        by_category={"xss": Tally(tp=0, fp=0, fn=1, tn=1)},
        missed={"xss": ("flask/BenchmarkTest01126",)},
        cwe={"xss": 79},
    )

    goal, = goals_from_bench(score, limit=1, corpus="/corpus/bp/flask")

    assert "/corpus/bp/flask/testcode/benchmark_test_01126.py" in goal
    assert "flask/flask" not in goal


def test_at_most_four_examples_of_each_kind_reach_the_goal():
    """`SAMPLES` caps what the report carries; this caps what the prompt does.
    A category at 0 % misses every one of its three thousand cases, and a
    goal that lists them is a goal no agent reads to the end."""
    many_missed = tuple(f"flask/BenchmarkTest{i:05d}" for i in range(9))
    many_invented = tuple(f"flask/BenchmarkTest{i:05d}" for i in range(100, 109))
    score = Score(
        suite="corpus",
        by_category={"xss": Tally(tp=0, fp=9, fn=9, tn=0)},
        missed={"xss": many_missed},
        invented={"xss": many_invented},
        cwe={"xss": 79},
    )

    goal, = goals_from_bench(score, limit=1)
    lines = {line.split(" : ")[0]: line for line in goal.splitlines() if " : " in line}
    missed_line = lines["Cas vulnérables non détectés"]
    invented_line = lines["Cas sains signalés à tort"]

    assert missed_line.count("benchmark_test_") == GOAL_SAMPLES
    assert invented_line.count("benchmark_test_") == GOAL_SAMPLES
    assert GOAL_SAMPLES == 4


# -- what the corpus is allowed to decide ------------------------------------


def test_the_bench_guards_hold_both_scores_and_leave_the_false_positive_rate_alone():
    """J already prices false positives. A separate floor under `fpr` would
    refuse the honest trade — twenty more true positives for one more false
    one raises J and is exactly the change worth keeping."""
    assert BENCH_GUARDS == {"youden": "ne_baisse_pas",
                            "youden_holdout": "ne_baisse_pas"}
    assert "fpr" not in BENCH_GUARDS
    assert "tpr" not in BENCH_GUARDS


def test_a_drop_in_youden_is_refused_and_the_reason_names_it(tmp_path):
    gate = bench_gate(tmp_path, hold_out="flask")

    kept, why = gate.compare({"youden": 0.090, "youden_holdout": 0.080},
                             {"youden": 0.070, "youden_holdout": 0.081})

    assert not kept
    assert "youden" in why and "0.09" in why


def test_a_drop_on_the_held_out_suite_is_refused_even_when_youden_rose(tmp_path):
    """The overfitting signature, and the only thing the headline number
    cannot see: a rule keyed on what the measured suites happen to look like
    moves them and not the one it never read."""
    gate = bench_gate(tmp_path, hold_out="flask")

    kept, why = gate.compare({"youden": 0.090, "youden_holdout": 0.080},
                             {"youden": 0.220, "youden_holdout": 0.020})

    assert not kept
    assert "youden_holdout" in why


def test_a_rise_in_both_is_accepted_and_reported(tmp_path):
    gate = bench_gate(tmp_path, hold_out="flask")

    kept, why = gate.compare({"youden": 0.090, "youden_holdout": 0.080},
                             {"youden": 0.130, "youden_holdout": 0.091})

    assert kept
    assert "0.13" in why


def test_the_gate_asks_the_corpus_out_of_process_with_what_it_was_given(monkeypatch,
                                                                       tmp_path):
    """Thot measuring Thot has the module under change already imported, so
    an in-process reading reports the version loaded at startup — fast, and
    wrong in the one direction that keeps every regression."""
    asked: list[tuple] = []

    def fake(path, *, root=None, hold_out="", floor="medium", timeout=1800):
        asked.append((str(path), hold_out, floor))
        return {"youden": 0.09, "tpr": 0.096, "fpr": 0.005, "youden_holdout": 0.08}

    monkeypatch.setattr("thot.bench.run.measure_out_of_process", fake)
    gate = bench_gate(tmp_path, hold_out="flask", floor="high")

    measured, why_not = gate.measure(tmp_path)

    assert why_not == ""
    assert measured["youden"] == 0.09
    assert asked == [(str(tmp_path), "flask", "high")]


def test_a_bench_measurement_that_fails_raises_instead_of_returning_a_default(
    monkeypatch, tmp_path
):
    """A default here would be a number the loop compares against and keeps."""
    def broken(path, **kwargs):
        raise RuntimeError("bench n'a mesuré aucune suite")

    monkeypatch.setattr("thot.bench.run.measure_out_of_process", broken)
    metrics = bench_metrics(tmp_path)

    with pytest.raises(RuntimeError, match="aucune suite"):
        metrics(tmp_path)


def test_a_measurement_that_could_not_be_taken_refuses_the_change(monkeypatch,
                                                                  tmp_path):
    """A broken instrument is not evidence that nothing got worse — and a
    loop that can edit its own bench would otherwise learn to break it."""
    def broken(path, **kwargs):
        raise RuntimeError("bench n'a mesuré aucune suite")

    monkeypatch.setattr("thot.bench.run.measure_out_of_process", broken)
    gate = bench_gate(tmp_path, hold_out="flask")

    measured, why_not = gate.measure(tmp_path)

    assert measured is None
    assert "mesure impossible" in why_not
    assert "RuntimeError" in why_not

    kept, why = gate.compare({"youden": 0.09, "youden_holdout": 0.08}, measured)
    assert not kept
    assert "mesure impossible" in why
