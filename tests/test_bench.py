"""The scorer, held against ground truth it cannot argue with.

`bench/` exists because every other measurement in this program is Thot
measuring Thot, and the loudest failure it was written for —
`pattern.xml_unsafe_parse` at −100 %, flagging the `defusedxml` its own
message recommended — was invisible to precision and recall. Two properties
made it visible, and they are what most of this file pins down: a finding
that names the wrong weakness class earns nothing, and every category gets
a number whatever its size.

The suites below are two lines of CSV apiece. Auditing a real suite takes
about five seconds (flask, floor=medium: TPR 9.6 %, FPR 0.5 %, J +9.0 %,
tp=292 fp=16 fn=2758 tn=3034) — a fine measurement and a ruinous unit test,
so nothing here runs the pipeline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from thot.bench.corpus import (
    NotACorpus,
    Suite,
    case_key,
    load,
    load_all,
    read_labels,
    verified,
)
from thot.bench.score import (
    SAMPLES,
    Score,
    Tally,
    already_claimed,
    combine,
    score,
)
from thot.contracts import CodeRef, Confidence, Finding, Severity

CSV_NAME = "expectedresults-1.0.csv"

# Two rules whose CWE mapping is fixed in `report/cwe.py`: `sink.sql` is
# CWE-89 and `pattern.hardcoded_credential` is CWE-798. The whole cwe-vs-
# filename distinction is tested by pointing both at the same file.
SQLI = "sink.sql"
SQLI_CWE = 89
SECRET = "pattern.hardcoded_credential"


def make_finding(rule: str, path: str,
                 severity: Severity = Severity.HIGH) -> Finding:
    """A finding shaped as the scorer reads it: a rule and a path, no more."""
    where = CodeRef(path=path, line=1)
    return Finding(id=Finding.compute_id(rule, where), rule=rule,
                   severity=severity, confidence=Confidence.PLAUSIBLE,
                   location=where)


def make_suite(root: Path, rows: str, *, testcode: bool = True) -> Path:
    """A suite on disk: the CSV, and one `testcode/` file per row it names."""
    root.mkdir(parents=True, exist_ok=True)
    (root / CSV_NAME).write_text(rows, encoding="utf-8")
    if not testcode:
        return root
    code = root / "testcode"
    code.mkdir(exist_ok=True)
    for line in rows.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            (code / f"{line.split(',')[0]}.py").write_text("pass\n")
    return root


ONE_OF_EACH = (
    "BenchmarkTest00001,sqli,true,89\n"
    "BenchmarkTest00002,sqli,false,89\n"
)


@pytest.fixture
def sqli_suite(tmp_path: Path) -> Suite:
    """One vulnerable case and one safe one, both labelled CWE-89."""
    return load(make_suite(tmp_path / "corpus" / "flask", ONE_OF_EACH))


# -- corpus: identity -------------------------------------------------------


def test_a_snake_case_and_a_camel_case_file_name_name_the_same_case():
    """The generator picks the spelling per language; only digits are identity."""
    assert case_key("benchmark_test_01126.py") == case_key("BenchmarkTest01126.py")
    assert case_key("BenchmarkTest01126.py") == "BenchmarkTest01126"


def test_a_file_that_is_not_a_case_has_no_key():
    assert case_key("conftest.py") is None


# -- corpus: labels ---------------------------------------------------------


def test_read_labels_skips_comments_and_rows_whose_cwe_is_not_an_integer(tmp_path):
    """A row that cannot state its weakness class is corrupt, not guessable."""
    csv = tmp_path / CSV_NAME
    csv.write_text(
        "# name,category,real vulnerability,cwe\n"
        "\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,true,CWE-89\n"
        "BenchmarkTest00003,sqli,true\n",
        encoding="utf-8",
    )
    cases = read_labels(csv)
    assert set(cases) == {"BenchmarkTest00001"}
    assert cases["BenchmarkTest00001"].cwe == 89
    assert cases["BenchmarkTest00001"].vulnerable is True


# -- corpus: the four ways a path is not a corpus ---------------------------


# Each of the four asserts on the message, not just the class: the corpus is
# not vendored, so the exception *is* the instructions for fixing the path,
# and four mistakes diagnosed as one would send a reader looking in the
# wrong place.


def test_a_directory_that_does_not_exist_is_not_a_corpus(tmp_path):
    with pytest.raises(NotACorpus, match="n'est pas un dossier"):
        load(tmp_path / "nowhere")


def test_a_directory_with_no_expectedresults_csv_is_not_a_corpus(tmp_path):
    (tmp_path / "testcode").mkdir()
    with pytest.raises(NotACorpus, match="aucun expectedresults"):
        load(tmp_path)


def test_a_directory_with_no_testcode_is_not_a_corpus(tmp_path):
    make_suite(tmp_path / "flask", ONE_OF_EACH, testcode=False)
    with pytest.raises(NotACorpus, match="aucun testcode/"):
        load(tmp_path / "flask")


def test_a_csv_whose_every_row_is_unusable_is_not_a_corpus(tmp_path):
    """Labels that parse to nothing are worse than absent: they read as zero."""
    make_suite(tmp_path / "flask", "# only a header, no rows\n")
    with pytest.raises(NotACorpus, match="ne contient aucun cas"):
        load(tmp_path / "flask")


def test_load_all_finds_every_suite_under_a_parent(tmp_path):
    """Three frameworks are three suites: a rule that works on one is a fact."""
    corpus = tmp_path / "bp"
    make_suite(corpus / "django", ONE_OF_EACH)
    make_suite(corpus / "flask", ONE_OF_EACH)
    (corpus / "notes").mkdir()
    assert [s.label for s in load_all(corpus)] == ["django", "flask"]


def test_load_all_accepts_being_pointed_straight_at_one_suite(tmp_path):
    make_suite(tmp_path / "bp" / "flask", ONE_OF_EACH)
    suites = load_all(tmp_path / "bp" / "flask")
    assert [s.label for s in suites] == ["flask"]


# -- corpus: provenance -----------------------------------------------------


def test_a_suite_with_no_manifest_is_unverified_and_says_why(sqli_suite):
    ok, why = verified(sqli_suite)
    assert ok is False
    assert "manifeste" in why


def test_a_manifest_recording_the_current_csv_verifies_the_labels(sqli_suite):
    """The positive control: without it, a scorer that always says no passes."""
    csv = sqli_suite.root / CSV_NAME
    digest = hashlib.sha256(csv.read_bytes()).hexdigest()
    (sqli_suite.root.parent / "benchproctor-manifest.json").write_text(
        json.dumps({"suites": {"flask": {"csv_sha256": digest}}}), encoding="utf-8")
    ok, why = verified(sqli_suite)
    assert ok is True
    assert digest[:12] in why


def test_labels_edited_since_the_manifest_was_written_fail_verification(sqli_suite):
    """Ground truth that moved under a measurement invalidates every number since."""
    (sqli_suite.root.parent / "benchproctor-manifest.json").write_text(
        json.dumps({"suites": {"flask": {"csv_sha256": "0" * 64}}}), encoding="utf-8")
    ok, why = verified(sqli_suite)
    assert ok is False
    assert "000000000000" in why


# -- score: the four counts -------------------------------------------------


def test_a_class_with_no_cases_rates_zero_rather_than_dividing_by_zero():
    assert Tally(tn=5).tpr == 0.0
    assert Tally(tp=3, fn=1).fpr == 0.0


def test_youden_is_the_true_positive_rate_minus_the_false_positive_rate():
    tally = Tally(tp=3, fp=1, fn=1, tn=3)
    assert tally.tpr == 0.75
    assert tally.fpr == 0.25
    assert tally.youden == pytest.approx(0.5)


def test_adding_two_tallies_sums_the_four_counts():
    assert Tally(1, 2, 3, 4) + Tally(10, 20, 30, 40) == Tally(11, 22, 33, 44)


def test_a_small_inverted_category_is_not_diluted_by_a_large_healthy_one():
    """The second reason this module exists. `xml_unsafe_parse` was inverted
    over a hundred cases while the six thousand around it were fine; pooled,
    the two categories below read +92 %, and per category they read 0 %."""
    scored = Score(suite="flask", by_category={
        "sqli": Tally(tp=50, tn=50),
        "xxe": Tally(fp=2, fn=2),
    })
    assert scored.flat == Tally(tp=50, fp=2, fn=2, tn=50)
    assert scored.flat.youden == pytest.approx(48 / 52)
    assert scored.tpr == pytest.approx(0.5)
    assert scored.fpr == pytest.approx(0.5)
    assert scored.youden == pytest.approx(0.0)


# -- score: right answer to which question ----------------------------------


def test_a_finding_naming_the_labelled_weakness_class_is_a_true_positive(sqli_suite):
    findings = [make_finding(SQLI, "testcode/BenchmarkTest00001.py")]
    assert score(findings, sqli_suite).by_category["sqli"] == Tally(tp=1, tn=1)


def test_a_finding_naming_another_weakness_class_is_not_a_true_positive(sqli_suite):
    """A hardcoded-password finding on a SQL-injection case is a right answer
    to another question, and the corpus is the only thing that can say so."""
    findings = [make_finding(SECRET, "testcode/BenchmarkTest00001.py")]
    assert score(findings, sqli_suite).by_category["sqli"] == Tally(fn=1, tn=1)


def test_that_same_finding_does_count_under_filename_matching(sqli_suite):
    """`match="filename"` measures where Thot looks, not what it understands:
    it separates a missing rule from a rule mapped to the wrong class."""
    findings = [make_finding(SECRET, "testcode/BenchmarkTest00001.py")]
    scored = score(findings, sqli_suite, match="filename")
    assert scored.by_category["sqli"] == Tally(tp=1, tn=1)


def test_a_category_thot_fires_on_under_another_class_is_seen_but_unnamed(
        sqli_suite):
    """The third silence, and the one the corpus made visible.

    A category can produce nothing for three different reasons: no rule
    exists, a rule exists and never matches, or a rule fires on exactly the
    right file and calls the weakness something else. Only the third is
    *not* work — measured on BenchProctor, nine categories are in it, and
    each one was proposed as a mapping to add and refused on the taxonomy.
    Counting them as "aucune règle" sent a reader to write a rule that was
    already there.
    """
    findings = [make_finding(SECRET, "testcode/BenchmarkTest00001.py")]
    scored = score(findings, sqli_suite)
    assert scored.by_category["sqli"] == Tally(fn=1, tn=1)
    assert scored.seen["sqli"] == 1


def test_a_category_nothing_fires_on_at_all_is_not_seen(sqli_suite):
    assert score([], sqli_suite).seen.get("sqli", 0) == 0


def test_only_vulnerable_cases_count_as_seen(sqli_suite):
    """A finding on the safe half is an invention, already counted as `fp`.
    Reading it as "Thot sees this category" would make noise look like
    progress."""
    findings = [make_finding(SECRET, "testcode/BenchmarkTest00002.py")]
    assert score(findings, sqli_suite).seen.get("sqli", 0) == 0


def test_an_unknown_match_mode_is_refused(sqli_suite):
    with pytest.raises(ValueError):
        score([], sqli_suite, match="severity")


# -- score: what the counts carry with them ---------------------------------


def test_a_flagged_safe_case_is_invented_and_an_unflagged_vulnerable_one_missed(
        sqli_suite):
    """Counts diagnose; the case keys are what a fix gets written against."""
    findings = [make_finding(SQLI, "testcode/BenchmarkTest00002.py")]
    scored = score(findings, sqli_suite)
    assert scored.by_category["sqli"] == Tally(fp=1, fn=1)
    assert scored.missed == {"sqli": ("BenchmarkTest00001",)}
    assert scored.invented == {"sqli": ("BenchmarkTest00002",)}
    assert scored.cwe == {"sqli": SQLI_CWE}


def test_a_finding_belonging_to_no_case_is_dropped_rather_than_charged_to_one(
        sqli_suite):
    """Thot auditing a `.thot/` inside the tree must not cost a safe case.
    Real suites ship such a file: every `testcode/` holds an `app_runtime.py`
    the generator wrote, which no CSV row names."""
    outside = [
        make_finding(SQLI, ".thot/state.py"),
        make_finding(SQLI, "testcode/app_runtime.py"),
        make_finding(SQLI, "testcode/BenchmarkTest09999.py"),
    ]
    scored = score(outside, sqli_suite)
    # Spelled out rather than compared to `score([], …)`: two readings broken
    # the same way would agree with each other and say nothing.
    assert scored.by_category == {"sqli": Tally(fn=1, tn=1)}
    assert scored.invented == {}


# -- score: what to work on next --------------------------------------------


def test_worst_puts_an_inverted_category_ahead_of_one_that_merely_finds_nothing():
    """An inverted rule is worse than a silent one, and only the sign says so."""
    scored = Score(suite="flask", by_category={
        "silent": Tally(fn=4, tn=4),
        "inverted": Tally(fp=4, fn=4),
    })
    assert [name for name, _ in scored.worst()] == ["inverted", "silent"]


def test_worst_breaks_a_tie_on_how_many_vulnerable_cases_are_at_stake():
    scored = Score(suite="flask", by_category={
        "small": Tally(fn=4, tn=4),
        "large": Tally(fn=50, tn=50),
    })
    assert [name for name, _ in scored.worst()] == ["large", "small"]
    assert [name for name, _ in scored.worst(limit=1)] == ["large"]


def test_worst_puts_a_category_some_rule_already_claims_ahead_of_a_bigger_one():
    """Ties are most of the list — 54 of 61 categories sit at exactly 0/0 —
    so whatever breaks them decides what the loop works on. Size alone sends
    it to `argument_injection` every round; a category a rule already covers
    is the cheaper fix, and `goals_from_bench` passes that as `prefer`."""
    scored = Score(suite="flask", by_category={
        "argument_injection": Tally(fn=50, tn=50),
        "xss": Tally(fn=4, tn=4),
    })
    claimed = {"xss"}.__contains__
    assert [n for n, _ in scored.worst(prefer=claimed)] == [
        "xss", "argument_injection"]
    # Without it the bigger category wins, which is what makes the line above
    # a measurement of `prefer` rather than of the order the dict was built in.
    assert [n for n, _ in scored.worst()] == ["argument_injection", "xss"]


# -- score: crossing a process boundary -------------------------------------


def test_a_score_survives_the_round_trip_a_subprocess_measurement_makes():
    original = Score(
        suite="flask",
        by_category={"sqli": Tally(1, 2, 3, 4), "xxe": Tally(0, 5, 5, 0)},
        seconds=4.5,
        missed={"sqli": ("BenchmarkTest00001",)},
        invented={"xxe": ("BenchmarkTest00002",)},
        cwe={"sqli": 89, "xxe": 611},
    )
    back = Score.from_dict(json.loads(json.dumps(original.as_dict())))
    assert back.suite == "flask"
    assert back.by_category == original.by_category
    assert back.seconds == 4.5
    assert back.cwe == original.cwe
    assert back.missed["sqli"] == ("BenchmarkTest00001",)
    assert back.invented["xxe"] == ("BenchmarkTest00002",)
    # `from_dict` fills a key for every category while `score` only fills the
    # ones that failed, so the two dicts are not equal even when nothing was
    # lost. What has to hold is that no case crosses into the wrong list.
    assert back.missed.get("xxe", ()) == ()
    assert back.invented.get("sqli", ()) == ()


def test_a_report_carries_at_most_six_sample_cases_per_category():
    """A category at 0 % misses every case it has; three thousand keys in a
    JSON report is noise, not a problem anyone can act on."""
    keys = tuple(f"BenchmarkTest{n:05d}" for n in range(20))
    scored = Score(suite="flask", by_category={"sqli": Tally(fn=20)},
                   missed={"sqli": keys}, invented={"sqli": keys})
    cell = scored.as_dict()["categories"]["sqli"]
    assert cell["missed"] == list(keys[:SAMPLES]) == list(keys[:6])
    assert cell["invented"] == list(keys[:SAMPLES])
    assert Score.from_dict(scored.as_dict()).missed["sqli"] == keys[:SAMPLES]


# -- score: several suites as one number ------------------------------------


def test_combine_pools_a_category_across_suites_rather_than_averaging_it():
    """Three frameworks labelling the same weakness are three times the evidence."""
    pooled = combine([
        Score(suite="flask", by_category={"sqli": Tally(1, 0, 1, 2)}, seconds=1.0),
        Score(suite="django", by_category={"sqli": Tally(2, 1, 0, 1),
                                           "xxe": Tally(0, 0, 4, 4)}, seconds=2.0),
    ])
    assert pooled.suite == "total"
    assert pooled.by_category["sqli"] == Tally(3, 1, 1, 3)
    assert pooled.by_category["xxe"] == Tally(0, 0, 4, 4)
    assert pooled.seconds == 3.0


def test_combine_qualifies_case_keys_with_the_suite_they_came_from():
    """`BenchmarkTest01126` names a different file in each framework."""
    pooled = combine([
        Score(suite="flask", by_category={"sqli": Tally(fn=1)},
              missed={"sqli": ("BenchmarkTest01126",)}),
        Score(suite="django", by_category={"sqli": Tally(fp=1)},
              invented={"sqli": ("BenchmarkTest01126",)}),
    ])
    assert pooled.missed["sqli"] == ("flask/BenchmarkTest01126",)
    assert pooled.invented["sqli"] == ("django/BenchmarkTest01126",)


# -- run: the floor a real report applies -----------------------------------


def test_the_floor_keeps_the_findings_a_default_report_would_show():
    """Scoring the raw findings reads +9.5 % and the default report +9.0 %:
    85 true positives and 72 false ones sit below `medium` and reach nobody."""
    from thot.bench.run import DEFAULT_FLOOR, _above

    findings = [make_finding(SQLI, f"testcode/BenchmarkTest0000{n}.py", severity)
                for n, severity in enumerate(Severity)]
    kept = _above(findings, DEFAULT_FLOOR)
    assert {f.severity for f in kept} == {
        Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
    assert len(_above(findings, "info")) == len(findings)


# -- report: what a reader is shown, and what it is for ----------------------


def rendered(capsys, scores, total, **kwargs) -> str:
    """The screen as one line: rich wraps at eighty columns off a terminal,
    so a sentence asserted as written would be asserted against luck."""
    from thot.bench.report import render

    render(scores, total, **kwargs)
    return " ".join(capsys.readouterr().out.split())


def test_a_category_producing_neither_a_hit_nor_an_invention_is_counted_silent():
    """0/0 is not a middling score. It lands at J exactly 0, which on this
    scale reads as a coin flip, and it is an absent rule."""
    from thot.bench.report import silent

    total = Score(suite="total", by_category={
        "xss": Tally(tp=0, fp=0, fn=50, tn=50),
        "sqli": Tally(tp=40, fp=2, fn=10, tn=48),
    })
    assert silent(total) == ["xss"]


def test_a_silent_category_thot_already_fires_on_reads_as_misnamed():
    """`_state` had two answers for a silence that has three causes."""
    from thot.bench.report import _state

    assert _state(Tally(fn=4, tn=4), claimed=False, seen=3)[0] == "mal nommée"
    assert _state(Tally(fn=4, tn=4), claimed=True, seen=0)[0] == "règle muette"
    assert _state(Tally(fn=4, tn=4), claimed=False, seen=0)[0] == "aucune règle"


def test_a_category_thot_already_fires_on_is_ranked_last_not_first():
    """The ranking exists to put the cheapest repair first. A category Thot
    already fires on is not cheap, it is impossible: every one of the nine on
    BenchProctor was instructed as a mapping and refused on the taxonomy.
    Preferred on `claims` alone, `directory_listing_exposure` led the table —
    the one row nobody should start with."""
    from thot.bench.score import misnamed

    scored = Score(
        suite="s",
        by_category={"seen": Tally(fn=4, tn=4), "mute": Tally(fn=4, tn=4)},
        cwe={"seen": 209, "mute": 601},
        seen={"seen": 4},
    )
    claims, fired = already_claimed(scored), misnamed(scored)
    ranked = [name for name, _ in
              scored.worst(prefer=lambda n: claims(n) and not fired(n))]
    assert ranked == ["mute", "seen"]


def test_a_class_only_one_of_thots_own_rules_claims_counts_as_claimed():
    """`already_claimed` read `CWE_BY_RULE`, which is the forked catalogue
    alone. The thirteen rules in `audit_rules.py` carry their class on the
    rule itself and reach the map through `cwe_map()`, so every one of them
    was invisible here — `cookie_no_httponly` has a rule mapped to CWE-1004
    and was still reported as having none."""
    scored = Score(suite="s", by_category={"cookie": Tally(fn=4, tn=4)},
                   cwe={"cookie": 1004})
    assert already_claimed(scored)("cookie")


def test_a_category_that_invents_is_not_silent_however_badly_it_scores():
    """The two ask for different work: an inverted rule is repaired, a
    missing one is written. Conflating them is what the count exists to
    prevent, so the worst possible score must not be read as silence."""
    inverted = Score(suite="total",
                     by_category={"xxe": Tally(tp=0, fp=50, fn=50, tn=0)})
    from thot.bench.report import silent

    assert inverted.by_category["xxe"].youden == -1.0
    assert silent(inverted) == []


def test_an_exact_zero_carries_no_sign_and_every_other_rate_does():
    """A `+0 %` in every second row of the table is the sign meaning nothing
    in the one place it has nothing to say."""
    from thot.bench.report import percent

    assert percent(0.0, sign=True) == "0.0 %"
    assert percent(0.0904, sign=True) == "+9.0 %"
    assert percent(-0.5, sign=True) == "-50.0 %"
    assert percent(0.0904) == "9.0 %"


def test_the_count_of_silent_categories_is_stated_and_not_bounded_by_the_table(
    capsys,
):
    """Measured on the three suites at floor `medium`, 54 of 61 categories
    are silent — a number no twelve-row table can carry, and the one on the
    screen that says *a rule is missing* rather than *a threshold is off*."""
    total = Score(suite="total", by_category={
        f"cat{n:02d}": Tally(tp=0, fp=0, fn=5, tn=5) for n in range(20)
    })

    out = rendered(capsys, [total], total, limit=2)

    assert "2 catégories sur 20 — les pires d'abord" in out
    assert "20 catégories sur 20 ne produisent rien du tout" in out


def test_one_silent_category_is_announced_in_the_singular(capsys):
    """«1 catégories» next to a number is how a reader learns to skim past
    the two lines on this screen that are actionable."""
    total = Score(suite="total", by_category={
        "xss": Tally(tp=0, fp=0, fn=5, tn=5),
        "sqli": Tally(tp=5, fp=0, fn=0, tn=5),
    })

    out = rendered(capsys, [total], total)

    assert "1 catégorie sur 2 ne produit rien du tout" in out
    assert "1 catégories" not in out


def test_an_inverted_category_is_named_as_inverted_and_not_merely_ranked_first(
    capsys,
):
    """`xml_unsafe_parse` measured −100 % for as long as it existed and read
    as a blank cell. Ranking it first puts it on the screen; only the word
    says which repair it needs."""
    total = Score(suite="total", by_category={
        "xxe": Tally(tp=0, fp=50, fn=50, tn=0),
        "sqli": Tally(tp=40, fp=2, fn=10, tn=48),
    }, cwe={"xxe": 611, "sqli": 89})

    out = rendered(capsys, [total], total)

    assert "1 catégorie est *inversée*" in out
    assert "xxe" in out
    assert "-100 %" in out


def test_the_sign_is_explained_even_when_no_category_is_negative(capsys):
    """Said every run, because a reader who takes J for a percentage of
    something reads −100 % as «presque rien» on the run where it appears."""
    total = Score(suite="total",
                  by_category={"sqli": Tally(tp=5, fp=0, fn=0, tn=5)})

    out = rendered(capsys, [total], total)

    assert "0 = pile ou face, négatif = règle inversée" in out


def test_one_suite_prints_no_headline_and_several_print_one_each(capsys):
    """Three frameworks are three numbers worth comparing; one framework is
    the same number printed twice."""
    flask = Score(suite="flask",
                  by_category={"sqli": Tally(tp=5, fp=0, fn=5, tn=10)})
    django = Score(suite="django",
                   by_category={"sqli": Tally(tp=1, fp=0, fn=9, tn=10)})

    assert "flask" not in rendered(capsys, [flask], flask)

    both = rendered(capsys, [flask, django], combine([flask, django]))
    assert "flask" in both
    assert "django" in both


def test_a_measurement_with_no_category_at_all_says_so_rather_than_a_blank_table(
    capsys,
):
    """An empty table reads as a clean run, and the two are opposites."""
    empty = Score(suite="total")

    out = rendered(capsys, [empty], empty)

    assert "aucune catégorie" in out.lower()


# -- the JSON the evolution gate reads ---------------------------------------


FLASK = Score(suite="flask",
              by_category={"sqli": Tally(tp=4, fp=1, fn=6, tn=9)},
              seconds=5.0, missed={"sqli": ("BenchmarkTest00001",)},
              cwe={"sqli": 89})
DJANGO = Score(suite="django",
               by_category={"sqli": Tally(tp=1, fp=0, fn=9, tn=10)},
               seconds=5.0, cwe={"sqli": 89})


@pytest.fixture
def two_suites(tmp_path: Path, monkeypatch) -> Path:
    """Two suites on disk, and a measurement nobody had to run.

    The pipeline is what costs five seconds a suite; the payload's shape is
    what a subprocess measurement parses, and it is the shape under test.
    `_cmd_bench` imports `measure_all` when it is called, so replacing the
    module attribute is enough.
    """
    corpus = tmp_path / "bp"
    make_suite(corpus / "flask", ONE_OF_EACH)
    make_suite(corpus / "django", ONE_OF_EACH)
    monkeypatch.setattr(
        "thot.bench.run.measure_all",
        lambda path, **kwargs: ([FLASK, DJANGO], combine([FLASK, DJANGO])),
    )
    return corpus


def test_the_json_is_the_shape_a_subprocess_measurement_parses(two_suites, capsys):
    """A contract, not a display choice: `measure_out_of_process` reads this
    to decide whether a change to Thot is kept, and a renamed key fails as
    «bench en échec» with nothing on the screen saying which one moved."""
    from thot import cli

    assert cli.main(["bench", str(two_suites), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert set(payload) == {"corpus", "floor", "match", "suites", "total"}
    assert [one["suite"] for one in payload["suites"]] == ["flask", "django"]
    assert payload["floor"] == "medium"
    assert payload["match"] == "cwe"
    assert Score.from_dict(payload["total"]).by_category["sqli"] == Tally(5, 1, 15, 19)


def test_what_the_command_prints_is_what_the_gate_turns_into_numbers(
    two_suites, capsys, monkeypatch
):
    """Producer and consumer held against each other. The gate never scores
    anything itself — it re-reads this text — so the two drifting apart is a
    silent failure on both sides."""
    from thot import cli
    from thot.bench.run import measure_out_of_process

    assert cli.main(["bench", str(two_suites), "--json"]) == 0
    printed = capsys.readouterr().out

    class Done:
        returncode = 0
        stdout = printed
        stderr = ""

    monkeypatch.setattr("thot.bench.run.subprocess.run",
                        lambda *args, **kwargs: Done())
    numbers = measure_out_of_process(two_suites, hold_out="django")

    assert numbers["youden"] == pytest.approx(FLASK.youden)
    assert numbers["youden_holdout"] == pytest.approx(DJANGO.youden)


def test_the_verification_of_the_labels_is_said_where_it_cannot_corrupt_the_payload(
    two_suites, capsys
):
    """A benchmark whose labels moved under a measurement is worse than no
    benchmark: every number since is wrong and nothing says so. Which is why
    it is printed under `--json` too — on the other stream."""
    from thot import cli

    assert cli.main(["bench", str(two_suites), "--json"]) == 0
    captured = capsys.readouterr()

    assert "flask" in captured.err
    assert "django" in captured.err
    json.loads(captured.out)


def test_a_corpus_that_is_not_one_leaves_stdout_empty_rather_than_half_a_payload(
    tmp_path, capsys
):
    """`measure_out_of_process` reads a traceback here as «the change broke
    Thot», which is the one wrong answer available to it."""
    from thot import cli

    assert cli.main(["bench", str(tmp_path / "nowhere"), "--json"]) == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert "corpus" in captured.err.lower()


def test_a_held_out_suite_that_does_not_exist_is_refused_before_anything_is_audited(
    two_suites, capsys
):
    """Auditing three suites costs fifteen seconds, and a typo should not."""
    from thot import cli

    assert cli.main(["bench", str(two_suites), "--hold-out", "fastapi"]) == 2
    assert "fastapi" in capsys.readouterr().err
