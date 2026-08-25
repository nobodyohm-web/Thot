"""What a rule has been worth, measured — not what its severity claims.

A rule's severity says how bad it would be if true. Nothing in Thot ever said
how often it *is* true, so the deep pass ranked candidates by severity alone
and spent its budget wherever the catalog was loudest.

The ledger says what that cost. Across every run this machine has stored:
**638 distinct candidates** judged by a model, **9 confirmed**.
`sink.network` alone accounts for 171 of them and no confirmation at any
point. Three rules — `sink.network`, `sink.sql`, `sink.fs.write` — hold
396 of the 638, and between them two true positives.

Those are candidates, not rows. The same table holds 25 311 rows for
1 219 distinct findings, because `findings` is keyed `(run_id, id)` and
every run re-writes the verdicts it re-folds. Counting rows would tighten
each interval by the square root of a repetition count that measures how
often Thot was run, not how often a rule was right — and would condemn
`sink.sql` at a fabricated 0.18 % when its honest ceiling is 4.33 %. Hence
`store/db.py::rule_precision` counts `distinct id`, and a test holds it
there.

So the rate is measured, and a rule that has never paid goes last. The
measurement is a *ceiling*, not the observed rate: 0 confirmed out of 3 is
not evidence, 0 out of 171 is overwhelming, and a raw ratio cannot tell
those apart — both are exactly zero. The upper bound of a Wilson interval
can, and it moves on its own as evidence arrives. A rule nobody has judged
keeps a ceiling of 1.0 and is therefore tried *first*, which is the property
that matters most: a new rule is never buried by its own lack of history.

This is Engler's Z-ranking, and it is deliberately not a suppression. A rule
that sinks here still produces findings, still appears in the report, and
still climbs back the moment it confirms something — its ceiling jumps with
the first true positive. What changes is only what a model is paid to argue
about, and that is where every token of a deep pass goes.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field

# 95 %, one number for the whole module. Raising it makes the tool more
# forgiving of a rule with a bad record, not more accurate.
Z = 1.96

# A rule may only be called noise when its ceiling falls under this. With no
# confirmations it takes about 75 judgments to get there, which is the guard
# against condemning a rule on three unlucky candidates — no separate
# minimum-evidence constant is needed, because the interval already is one.
NOISE_CEILING = 0.05


def wilson_upper(confirmed: int, judged: int, z: float = Z) -> float:
    """The highest precision a rule could plausibly have, at 95 %.

    Wilson rather than the textbook normal interval, which degenerates to
    exactly zero width at zero successes — and zero successes is the entire
    population here.
    """
    if judged <= 0:
        return 1.0
    observed = confirmed / judged
    denominator = 1 + z * z / judged
    centre = (observed + z * z / (2 * judged)) / denominator
    spread = z * math.sqrt(
        observed * (1 - observed) / judged + z * z / (4 * judged * judged)
    ) / denominator
    return min(1.0, centre + spread)


@dataclass(frozen=True)
class Prior:
    """Per-rule (judged, confirmed), and what follows from it."""

    counts: Mapping[str, tuple[int, int]] = field(default_factory=dict)

    def evidence(self, rule: str) -> tuple[int, int]:
        return self.counts.get(rule, (0, 0))

    def ceiling(self, rule: str) -> float:
        judged, confirmed = self.evidence(rule)
        return wilson_upper(confirmed, judged)

    def noisy(self, rule: str) -> bool:
        """Measured noise: enough evidence, and a ceiling under the floor."""
        return self.ceiling(rule) < NOISE_CEILING

    def __bool__(self) -> bool:
        return bool(self.counts)

    @classmethod
    def from_store(cls, store) -> "Prior":
        """Counted from every run ever stored, pooled across repositories.

        Pooled on purpose. A rule that misfires on one tree misfires on the
        next for the same reason — it is a property of the rule, not of the
        code — and pooling is what turns 143 candidates on one repository
        into the four thousand that make the answer unarguable.

        A store that cannot answer costs the ranking, never the audit: an
        empty `Prior` ranks exactly as Thot did before this existed.
        """
        try:
            rows = store.rule_precision()
        except Exception:
            return cls()
        return cls({rule: (judged, confirmed) for rule, judged, confirmed in rows})

    @classmethod
    def from_home(cls) -> "Prior":
        """The ledger this machine keeps, opened read-only and never created.

        A deep pass gets its prior from here rather than from the store the
        caller happens to hold, because the knowledge is about rules and not
        about repositories: `audit_all` passes no store at all, and that is
        the very command whose budget this is meant to protect.
        """
        from thot.paths import run_store
        from thot.store.db import Store

        path = run_store()
        if not path.exists():
            # Opening would create it, and an empty ledger is what an empty
            # `Prior` already means.
            return cls()
        try:
            store = Store.open(path)
        except Exception:
            return cls()
        try:
            return cls.from_store(store)
        finally:
            store.close()
