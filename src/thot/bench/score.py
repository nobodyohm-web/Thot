"""Youden's J: what Thot catches, minus what it invents.

`J = TPR − FPR`. Zero is a coin flip, +100 is perfect, and **negative is a
rule that is wrong on purpose** — it flags the safe half and misses the
vulnerable half. That last case is not hypothetical: `xml_unsafe_parse`
measured −100 % here, on a hundred cases, for as long as it existed.

Precision and recall would not have said so. A rule with no true positives
has undefined precision, prints as a blank, and reads as *no data* — which
is exactly how an inverted rule survives. J has no such hole: every rule
gets a number, and the sign carries the verdict.

Two things make the score hard to game, and both matter because a loop
optimises whatever it is scored on:

- **Finding less is punished.** The old guard watched `provenance`, a ratio
  over Thot's own findings, and raising a threshold until the report emptied
  moved it the right way. Here, a threshold that drops a finding drops a
  true positive with it and TPR falls.
- **Guessing more is punished.** Flagging every file scores TPR 100 %,
  FPR 100 %, J = 0. The corpus is balanced 50/50 precisely so that this is
  worth nothing.

Categories are averaged rather than pooled, so `xxe` at −100 % over fifty
cases is not diluted by the six thousand around it. On a balanced corpus the
two agree; when they diverge, the macro average is the one that notices the
small broken thing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from thot.bench.corpus import Suite

# How many failing cases a report carries per category. Three of each is
# enough to see the shape of what is being missed and small enough that the
# JSON stays readable.
SAMPLES = 6


@dataclass(frozen=True)
class Tally:
    """The four counts, and what follows from them."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        return self.fp + self.tn

    @property
    def tpr(self) -> float:
        """Of the vulnerable cases, the share Thot named. 0.0 with none."""
        return self.tp / self.positives if self.positives else 0.0

    @property
    def fpr(self) -> float:
        """Of the safe cases, the share Thot flagged anyway."""
        return self.fp / self.negatives if self.negatives else 0.0

    @property
    def youden(self) -> float:
        return self.tpr - self.fpr

    def __add__(self, other: "Tally") -> "Tally":
        return Tally(self.tp + other.tp, self.fp + other.fp,
                     self.fn + other.fn, self.tn + other.tn)


@dataclass(frozen=True)
class Score:
    """One suite measured, whole and by category.

    `missed` and `invented` are why this returns more than four numbers. A
    goal that says "xss scores 0 %" is unactionable — the agent reading it
    can only guess. A goal that hands over three files Thot walked past, and
    three it flagged for nothing, is a problem someone can actually solve.
    Counts diagnose; cases are what a fix is written against.
    """

    suite: str
    by_category: dict[str, Tally] = field(default_factory=dict)
    seconds: float = 0.0
    # category -> case keys that were vulnerable and went unflagged
    missed: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # category -> case keys that were safe and were flagged anyway
    invented: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # category -> the CWE its cases are labelled for
    cwe: dict[str, int] = field(default_factory=dict)
    # category -> vulnerable cases Thot flagged under *some* class
    #
    # A silent category has three possible causes and only this number tells
    # the third from the other two. `tp == 0` says the labelled class was
    # never named; `seen > 0` says Thot nonetheless fired on those very
    # files, calling the weakness something else. That is not a rule waiting
    # to be written — it is a rule that works and a taxonomy that disagrees,
    # and on BenchProctor it is nine of the thirty-seven silent categories.
    seen: dict[str, int] = field(default_factory=dict)

    @property
    def flat(self) -> Tally:
        """Every case pooled — the count, not the average."""
        total = Tally()
        for tally in self.by_category.values():
            total = total + tally
        return total

    @property
    def tpr(self) -> float:
        """Macro-averaged: each category counts once, whatever its size."""
        if not self.by_category:
            return 0.0
        return sum(t.tpr for t in self.by_category.values()) / len(self.by_category)

    @property
    def fpr(self) -> float:
        if not self.by_category:
            return 0.0
        return sum(t.fpr for t in self.by_category.values()) / len(self.by_category)

    @property
    def youden(self) -> float:
        return self.tpr - self.fpr

    def worst(self, limit: int = 10, *,
              prefer: "Callable[[str], bool] | None" = None
              ) -> list[tuple[str, Tally]]:
        """The categories costing the most, worst first.

        Sorted by J first, so an inverted rule outranks a missing one: a
        category at −100 % is actively losing points, a category at 0 % is
        only failing to earn them.

        `prefer` breaks the ties, and on this corpus the ties are almost the
        whole list — 54 of 61 categories sit at exactly 0/0, all equally at
        zero. Without a tie-break the order falls out of dictionary order,
        which is alphabetical in practice: the loop would spend every round
        on `argument_injection` and `authnfailure` and never reach `xss`,
        `ssrf` or `pathtraver`. `goals_from_bench` passes a `prefer` that
        asks whether some rule already claims the class — measured, 7 of the
        54 are cases where the rule exists and does not fire, which is both
        the cheaper fix and the one more likely to succeed.

        The name is the last key, so the order is stable between runs. A
        loop whose targets shuffle cannot be compared with itself.
        """
        def rank(item: tuple[str, Tally]) -> tuple:
            name, tally = item
            near = bool(prefer(name)) if prefer is not None else False
            return (tally.youden, not near, -tally.positives, name)

        return sorted(self.by_category.items(), key=rank)[:limit]

    @classmethod
    def from_dict(cls, payload: dict) -> "Score":
        """Rebuilt from `as_dict` — how a subprocess measurement comes home."""
        return cls(
            suite=payload.get("suite", ""),
            by_category={
                name: Tally(cell["tp"], cell["fp"], cell["fn"], cell["tn"])
                for name, cell in (payload.get("categories") or {}).items()
            },
            seconds=float(payload.get("seconds", 0.0)),
            missed={name: tuple(cell.get("missed", ()))
                    for name, cell in (payload.get("categories") or {}).items()},
            invented={name: tuple(cell.get("invented", ()))
                      for name, cell in (payload.get("categories") or {}).items()},
            cwe={name: int(cell.get("cwe", 0))
                 for name, cell in (payload.get("categories") or {}).items()},
            seen={name: int(cell.get("seen", 0))
                  for name, cell in (payload.get("categories") or {}).items()},
        )

    def as_dict(self) -> dict:
        return {
            "suite": self.suite,
            "tpr": self.tpr,
            "fpr": self.fpr,
            "youden": self.youden,
            "seconds": self.seconds,
            "categories": {
                name: {"tp": t.tp, "fp": t.fp, "fn": t.fn, "tn": t.tn,
                       "tpr": t.tpr, "fpr": t.fpr, "youden": t.youden,
                       "cwe": self.cwe.get(name, 0),
                       "seen": self.seen.get(name, 0),
                       # Capped: a category at 0 % misses every one of its
                       # cases, and three thousand keys in a JSON report is
                       # noise. Enough to write a fix against, not a dump.
                       "missed": list(self.missed.get(name, ())[:SAMPLES]),
                       "invented": list(self.invented.get(name, ())[:SAMPLES])}
                for name, t in sorted(self.by_category.items())
            },
        }


def already_claimed(score: Score) -> Callable[[str], bool]:
    """Whether some rule already says it covers a category's weakness class.

    The distinction this draws is between *the rule exists and does not
    fire* and *there is no rule at all*, and it is worth drawing because the
    two are not the same job. Measured on the corpus: of the 54 categories
    producing nothing, 7 — `xss`, `ssrf`, `pathtraver`, `redirect`,
    `hardcodedcreds`, `weakcipher`, `cloud_ssrf_metadata` — have a rule
    mapped to their CWE that simply never matches the code. Fixing a pattern
    that is already wired in is cheaper and likelier to land than inventing a
    class of analysis from nothing, so those go first.

    Read from `report/cwe.py`, which is the same map the score itself uses to
    decide what counts as a hit. Nothing here is a guess about importance.

    It lives here rather than in `evolve` so that `bench.report` can rank
    its table the same way the loop ranks its goals. Putting it in `evolve`
    made the display import the loop — `bench → evolve → bench` — for a
    predicate that only ever reads the rule catalog.
    """
    from thot.report.cwe import all_rules, number

    # `all_rules()` and not `CWE_BY_RULE`: the latter is the forked catalogue
    # alone, and Thot's own thirteen rules carry their class on the rule and
    # arrive through `cwe_map()`. Read from the raw dict, every one of them
    # was invisible — `cookie_no_httponly` has a rule mapped to CWE-1004 and
    # was still reported as having none.
    claimed = {number(cwe) for cwes in all_rules().values() for cwe in cwes}
    return lambda name: score.cwe.get(name, 0) in claimed


def misnamed(score: Score) -> Callable[[str], bool]:
    """Whether a silent category is one Thot already fires on.

    The third silence, and the only one that is not work. `seen` counts the
    vulnerable cases Thot flagged under some other class, so a category that
    is silent *and* seen has a working rule pointing straight at it and a
    weakness class that disagrees.

    It matters most to `evolve.goals_from_bench`. All nine of these were put
    to an adversarial reading — is the corpus' class a specialisation of the
    one the rule names? — and all nine were refused: the corpus writes
    CWE-200, CWE-209 and CWE-489 on the same `JsonResponse(...,
    repr(locals()))`, and CWE-321 and CWE-798 on two files whose only
    difference is the dataflow wrapper around an identical `Fernet(...)`.
    Handed to the loop as goals, they are unreachable by any honest change,
    and the cheapest way to close one is to widen the mapping until it
    covers the label — which is the loop learning to score rather than to
    detect. They are ranked last for that reason, not because they are
    small.
    """
    return lambda name: bool(score.seen.get(name, 0))



def detected(findings: Iterable, suite: Suite) -> dict[str, set[int]]:
    """Per case, the weakness classes Thot named on it.

    A finding outside the corpus — Thot auditing its own `.thot/` directory,
    say — belongs to no case and is dropped rather than charged to one.
    """
    from thot.report.cwe import cwes, number

    hits: dict[str, set[int]] = {}
    for finding in findings:
        case = suite.case_of(finding.location.path)
        if case is None:
            continue
        classes = hits.setdefault(case.key, set())
        for cwe in cwes(finding.rule):
            classes.add(number(cwe))
    return hits


def score(findings: Iterable, suite: Suite, *, seconds: float = 0.0,
          match: str = "cwe") -> Score:
    """Findings against ground truth.

    `match="cwe"` is the honest reading and the default: the finding must
    name the class the case is labelled for. `match="filename"` credits any
    finding on the file, which measures *where* Thot looks rather than
    *what it understands* — useful to separate "the rule is missing" from
    "the rule fires and is mapped to the wrong class", and misleading as a
    headline number.
    """
    if match not in ("cwe", "filename"):
        raise ValueError("match doit être 'cwe' ou 'filename'")

    hits = detected(findings, suite)
    counts: dict[str, list[int]] = {}
    missed: dict[str, list[str]] = {}
    invented: dict[str, list[str]] = {}
    classes_of: dict[str, int] = {}
    seen: dict[str, int] = {}

    for case in sorted(suite.cases.values(), key=lambda c: c.key):
        classes = hits.get(case.key)
        if match == "cwe":
            flagged = bool(classes) and case.cwe in classes
        else:
            flagged = case.key in hits

        classes_of.setdefault(case.category, case.cwe)
        cell = counts.setdefault(case.category, [0, 0, 0, 0])
        if case.vulnerable:
            # Whatever class it named. On the safe half the same event is an
            # invention and is already counted as `fp`; reading it as "Thot
            # sees this category" would make noise look like progress.
            if classes:
                seen[case.category] = seen.get(case.category, 0) + 1
            cell[0 if flagged else 2] += 1
            if not flagged:
                missed.setdefault(case.category, []).append(case.key)
        else:
            cell[1 if flagged else 3] += 1
            if flagged:
                invented.setdefault(case.category, []).append(case.key)

    return Score(
        suite=suite.label,
        by_category={name: Tally(*cell) for name, cell in counts.items()},
        seconds=seconds,
        missed={name: tuple(keys) for name, keys in missed.items()},
        invented={name: tuple(keys) for name, keys in invented.items()},
        cwe=dict(classes_of),
        seen=seen,
    )


def combine(scores: Iterable[Score], label: str = "total") -> Score:
    """Several suites as one number, categories pooled across frameworks.

    Pooled and not averaged-of-averages: a category present in all three
    frameworks should weigh three times a category present in one, because
    it *is* three times the evidence.
    """
    merged: dict[str, Tally] = {}
    missed: dict[str, list[str]] = {}
    invented: dict[str, list[str]] = {}
    classes_of: dict[str, int] = {}
    seen: dict[str, int] = {}
    seconds = 0.0
    for one in scores:
        seconds += one.seconds
        classes_of.update(one.cwe)
        for name, count in one.seen.items():
            seen[name] = seen.get(name, 0) + count
        for name, tally in one.by_category.items():
            merged[name] = merged.get(name, Tally()) + tally
        # Qualified by suite: `BenchmarkTest01126` names a different file in
        # each framework, and an unqualified key sends a reader to whichever
        # one they happen to look in first.
        for name, keys in one.missed.items():
            missed.setdefault(name, []).extend(f"{one.suite}/{k}" for k in keys)
        for name, keys in one.invented.items():
            invented.setdefault(name, []).extend(f"{one.suite}/{k}" for k in keys)
    return Score(
        suite=label, by_category=merged, seconds=seconds,
        missed={n: tuple(v) for n, v in missed.items()},
        invented={n: tuple(v) for n, v in invented.items()},
        cwe=classes_of,
        seen=seen,
    )
