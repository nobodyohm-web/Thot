"""Running Thot over a labelled corpus, and getting a number back.

Two ways in, and the difference is not a detail.

`measure` calls the pipeline in this process: fast, and what `thot bench`
uses. `measure_out_of_process` re-launches Thot as a subprocess, which is
slower by an interpreter start and is the only one an evolution loop may
use. `evolve.thot_metrics` already learned this the hard way and says so:
Thot measuring Thot has the module under change *already imported*, so an
in-process reading reports the version loaded at startup, finds that
nothing moved, and waves every regression through. A measurement that is
fast and wrong is the one thing a self-modifying loop cannot survive.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from thot.bench.corpus import Suite, load_all
from thot.bench.score import Score, combine, score

# The corpus is third-party and large; this is where `thot bench` looks when
# no path is given. Nothing creates it — a missing corpus is reported, never
# downloaded, because a benchmark that fetches its own ground truth over the
# network is a benchmark whose ground truth can change without a commit.
DEFAULT_CORPUS = Path("~/.thot/bench").expanduser()

# 6 100 single-purpose files per suite, none of which imports another. The
# deep pass would ask a model about each candidate; the whole point of a
# corpus is that nothing here needs asking.
BUDGET = 0

# The floor `thot audit` applies when nobody passes `--min-severity`, and
# therefore the one the score has to apply too. What the pipeline computes
# and what a user is shown are not the same list: measured here, scoring the
# raw findings gives J +9.5 % and scoring the default report gives +9.0 %,
# because 85 true positives and 72 false ones sit below `medium` and never
# reach anyone. The number that means something is the second — a finding
# nobody sees has never helped anybody.
#
# It also makes the floor itself measurable, which it was not: `--floor info`
# says what those hidden findings are worth, and on this corpus the answer
# is +0.5 points. That is an argument for lowering it, and it is the first
# time there was any way to have that argument with evidence.
DEFAULT_FLOOR = "medium"


def _above(findings: list, floor: str) -> list:
    """The findings a report at this floor would actually contain."""
    from thot.contracts import Severity

    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    limit = order.index(Severity(floor))
    return [f for f in findings if order.index(f.severity) >= limit]


def audit_suite(suite: Suite, *, floor: str = DEFAULT_FLOOR) -> tuple[list, float]:
    """Every finding a default report on one suite would carry.

    No engine, so no model and no network: the score measures the analysis,
    not whichever agent happened to be installed. `require_authorization`
    is off because naming a corpus on the command line *is* the act of
    authorising it, and writing a `.thot/` into a third-party tree to say
    so would modify the thing being measured.
    """
    from thot.pipeline import run_audit

    started = time.perf_counter()
    result = run_audit(suite.code, require_authorization=False, budget=BUDGET)
    return _above(result.findings, floor), time.perf_counter() - started


def measure(suite: Suite, *, match: str = "cwe",
            floor: str = DEFAULT_FLOOR) -> Score:
    """One suite, scored in this process."""
    findings, seconds = audit_suite(suite, floor=floor)
    return score(findings, suite, seconds=seconds, match=match)


def measure_all(path: Path | str = DEFAULT_CORPUS, *, match: str = "cwe",
                floor: str = DEFAULT_FLOOR) -> tuple[list[Score], Score]:
    """Every suite under `path`, and the three of them pooled."""
    scores = [measure(suite, match=match, floor=floor) for suite in load_all(path)]
    return scores, combine(scores)


def measure_out_of_process(path: Path | str = DEFAULT_CORPUS, *,
                           root: Path | None = None,
                           hold_out: str = "",
                           floor: str = DEFAULT_FLOOR,
                           timeout: int = 1800) -> dict[str, float]:
    """The score, taken by a Thot that was started *after* the change.

    `hold_out` names a suite kept out of the headline number and reported
    separately as `youden_holdout`. That split is the only defence against
    the one way a corpus-scored loop can cheat: not by finding less or
    guessing more — a balanced corpus punishes both — but by **learning the
    corpus**. A rule keyed on what BenchmarkTest01126 happens to look like
    raises the score and helps nobody, and no property of the number itself
    can tell that apart from having genuinely got better.

    Three frameworks can. `django`, `fastapi` and `flask` express the same
    weakness in code that reads nothing alike, so a change that only moves
    the suites it was optimised against has said what it is. Guard both
    numbers and overfitting stops being invisible.

    Raises rather than returning a default: `Gate.compare` treats a missing
    measurement as a refusal, and that is the correct reading — a change
    nobody could measure is not a change that was shown to be safe.
    """
    root = Path(root or Path(__file__).resolve().parents[3])
    command = [sys.executable, "-m", "thot", "bench", str(path),
               "--json", "--floor", floor]
    done = subprocess.run(command, capture_output=True, text=True,
                          timeout=timeout, cwd=str(root))
    if done.returncode != 0:
        raise RuntimeError((done.stderr or "bench en échec").strip()[:300])
    try:
        payload = json.loads(done.stdout)
    except ValueError as exc:
        raise RuntimeError(f"sortie de bench illisible : {exc}") from None

    suites = [Score.from_dict(one) for one in payload.get("suites", [])]
    if not suites:
        raise RuntimeError("bench n'a mesuré aucune suite")

    kept = [s for s in suites if s.suite != hold_out]
    held = [s for s in suites if s.suite == hold_out]
    if hold_out and not held:
        raise RuntimeError(f"la suite tenue à l'écart, {hold_out}, n'existe pas")
    if hold_out and not kept:
        raise RuntimeError(f"tenir {hold_out} à l'écart ne laisse rien à mesurer")

    trained = combine(kept)
    numbers = {
        "youden": trained.youden,
        "tpr": trained.tpr,
        "fpr": trained.fpr,
    }
    if held:
        numbers["youden_holdout"] = combine(held).youden
    return numbers
