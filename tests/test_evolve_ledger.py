"""What one run of the loop tells the next one.

Without this the loop cannot iterate, only retry. The measurement barely
moves in a single round, so the next run reads the same worst categories,
hands the designer the same failing files, and gets back — reasonably — the
specification that was already built, measured and reverted. `--rounds 5`
becomes one attempt tried five times at five times the price, looking busy.
"""

from __future__ import annotations

import json

import pytest

from thot.bench.score import Score, Tally, already_claimed
from thot.evolve import Attempt, goal_key, recall, remember


def _attempt(goal: str, *, kept: bool = False, summary: str = "",
             reason: str = "", touched: tuple[str, ...] = ()) -> Attempt:
    return Attempt(goal=goal, summary=summary, kept=kept, reason=reason,
                   touched=touched)


BENCH_GOAL = ("Catégorie « xss » (CWE-79) : J = +0% — 0 vrais positifs sur "
              "150 cas vulnérables, 0 faux positifs sur 150 cas sains.\n"
              "Thot ne produit rien du tout sur cette classe.")


# -- naming the work ---------------------------------------------------------


def test_the_category_is_what_two_runs_call_the_same_work():
    assert goal_key(BENCH_GOAL) == "xss"


def test_the_counts_inside_a_goal_do_not_change_its_name():
    """The whole reason the key is not the goal text.

    A goal carries the tally it was built from, so the same category read on
    two different days is never byte-identical. Keying on the text would
    file every round under a new name and remember nothing.
    """
    later = BENCH_GOAL.replace("0 vrais positifs", "12 vrais positifs")
    assert later != BENCH_GOAL
    assert goal_key(later) == goal_key(BENCH_GOAL)


def test_a_goal_someone_typed_is_keyed_on_its_first_line():
    typed = "rends le moteur de teinte plus rapide\nsans perdre de findings"
    assert goal_key(typed) == "rends le moteur de teinte plus rapide"


def test_a_very_long_typed_goal_is_cut_rather_than_kept_whole():
    assert len(goal_key("x" * 500)) == 80


# -- writing it down ---------------------------------------------------------


def test_a_missing_ledger_is_silence_and_not_a_crash(tmp_path):
    assert recall(tmp_path / "jamais-ecrit.jsonl") == ""


def test_each_attempt_becomes_one_line(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL), _attempt("autre chose")], ledger)
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["key"] for row in rows] == ["xss", "autre chose"]


def test_a_second_run_appends_instead_of_replacing(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL)], ledger)
    remember([_attempt("Catégorie « ssrf » : J = +0%")], ledger)
    assert len(ledger.read_text().splitlines()) == 2


def test_the_ledger_is_created_with_its_parent_directory(tmp_path):
    ledger = tmp_path / "pas" / "encore" / "la" / "log.jsonl"
    remember([_attempt(BENCH_GOAL)], ledger)
    assert ledger.is_file()


def test_a_run_killed_mid_line_costs_that_line_and_nothing_else(tmp_path):
    """Why JSONL and not one rewritten JSON object.

    A process that dies between two writes leaves a truncated last line. Every
    completed attempt before it stays readable; a single JSON document would
    have been unparseable in its entirety.
    """
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, summary="ajouté sink.xss")], ledger)
    with ledger.open("a", encoding="utf-8") as out:
        out.write('{"when": "2026-08-24T22:0')
    assert "ajouté sink.xss" in recall(ledger)


# -- reading it back ---------------------------------------------------------


def test_what_was_reverted_is_what_the_next_run_must_not_repropose(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, kept=False, summary="ajouté sink.xss",
                       reason="youden 0.094 → 0.091")], ledger)
    read = recall(ledger)
    assert "ne repropose pas" in read
    assert "ajouté sink.xss" in read
    assert "youden 0.094 → 0.091" in read


def test_a_reverted_attempt_is_listed_before_a_kept_one(tmp_path):
    """Order is the message: the failure is the constraint, and the success
    is already in the code the agent is about to read."""
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, kept=True, summary="GARDÉ"),
              _attempt(BENCH_GOAL, kept=False, summary="ANNULÉ")], ledger)
    read = recall(ledger)
    assert read.index("ANNULÉ") < read.index("GARDÉ")


def test_only_the_history_of_the_category_asked_for_comes_back(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, summary="POUR-XSS"),
              _attempt("Catégorie « ssrf » : J = +0%", summary="POUR-SSRF")],
             ledger)
    read = recall(ledger, keys=["xss"])
    assert "POUR-XSS" in read
    assert "POUR-SSRF" not in read


def test_asking_for_nothing_in_particular_returns_everything(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, summary="POUR-XSS"),
              _attempt("Catégorie « ssrf » : J = +0%", summary="POUR-SSRF")],
             ledger)
    read = recall(ledger)
    assert "POUR-XSS" in read and "POUR-SSRF" in read


def test_a_category_with_no_history_reads_as_silence(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL)], ledger)
    assert recall(ledger, keys=["pathtraver"]) == ""


def test_an_attempt_that_said_nothing_still_names_itself(tmp_path):
    """An agent can change files and return no summary. Dropping the row
    would tell the next run the category was never tried."""
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, kept=False, reason="tests en échec")], ledger)
    read = recall(ledger)
    assert "xss" in read and "sans résumé" in read


def test_a_long_history_is_cut_to_the_most_recent(tmp_path):
    ledger = tmp_path / "log.jsonl"
    remember([_attempt(BENCH_GOAL, summary=f"essai-{n}") for n in range(20)],
             ledger)
    read = recall(ledger, limit=3)
    assert "essai-19" in read
    assert "essai-0\n" not in read and "essai-5" not in read


# -- which silence is which --------------------------------------------------


def test_a_class_some_rule_already_claims_is_told_apart_from_one_nobody_covers():
    """The distinction that orders the whole loop.

    `xss` is CWE-79 and `sink.js.dom` is mapped to it, so the rule exists and
    never matches — a pattern to widen. CWE-88 has no rule at all and has to
    be written from nothing. Both score exactly 0, and only this tells them
    apart.
    """
    scored = Score(
        suite="t",
        by_category={"xss": Tally(0, 0, 50, 50),
                     "argument_injection": Tally(0, 0, 50, 50)},
        cwe={"xss": 79, "argument_injection": 88},
    )
    claims = already_claimed(scored)
    assert claims("xss")
    assert not claims("argument_injection")


def test_a_category_whose_class_was_never_recorded_counts_as_uncovered():
    scored = Score(suite="t", by_category={"mystere": Tally(0, 0, 1, 1)})
    assert not already_claimed(scored)("mystere")


@pytest.mark.parametrize("name", ["xss", "ssrf", "pathtraver"])
def test_the_classes_the_loop_targets_first_really_are_claimed_in_the_catalog(name):
    """Pins the measured fact the ranking rests on: seven of the silent
    categories have a rule mapped to their class. If a future edit drops one
    of these mappings, the loop silently starts chasing the harder half."""
    scored = Score(suite="t", by_category={name: Tally(0, 0, 50, 50)},
                   cwe={"xss": 79, "ssrf": 918, "pathtraver": 22})
    assert already_claimed(scored)(name)
