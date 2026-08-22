"""Work the whole program's backlog down, one bounded round at a time.

An audit that argues twenty candidates and stops leaves the rest unjudged
for ever; a run with no budget at all is still going when you sit back down.
Neither is self-improvement. This is the middle: bounded rounds, each one
persisted, each one starting where the last stopped, run as often as you
like — by hand now, by the scheduler for ever.

Two facts make the loop converge instead of spinning:

- a refutation is remembered, so the next round's selection skips it;
- a confirmation is deliberately *not* remembered — a real defect must keep
  showing up until someone fixes it — so the loop carries its own set of
  ids judged this session. Without it, every round after the first would
  spend its whole budget re-arguing what the first one confirmed.

What it never does is edit code. "Improvement" here means the program's
judgement of itself gets sharper and cheaper: fewer unjudged candidates,
more decisions on disk, each one attributable to the agent that took it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class PartRound:
    """What one round did to one tree."""

    part: str
    findings: int = 0
    judged: int = 0  # decided this round
    refuted: int = 0
    confirmed: int = 0
    # A refutation a second agent would not stand behind. Worth its own
    # number: it is the one outcome that means the program caught itself
    # about to bury something, and burying is the expensive mistake.
    contested: int = 0
    # Tasks whose agent never answered — a timeout, a crashed CLI, a
    # subscription that ran out mid-pass. Counted apart from a model that
    # simply would not commit: the two look identical in the finding and
    # mean opposite things about whether running again is worth anything.
    failed: int = 0
    backlog: int = 0  # still unjudged after this round
    error: str = ""

    @property
    def quiet(self) -> bool:
        """Nothing judged, nothing left — and nothing went wrong doing it."""
        return not self.judged and not self.backlog and not self.failed

    def line(self) -> str:
        if self.error:
            return f"{self.part:<8} — {self.error}"
        # "0 jugé(s) · 0 en attente" is what a settled tree prints, and it is
        # also, word for word, what the nightly loop printed while its PATH
        # was broken and it could not reach a single agent. Unattended, that
        # line is the only thing anyone sees; it has to name which one it is.
        if self.quiet:
            if not self.findings:
                return f"{self.part:<8} aucun finding à juger"
            return (f"{self.part:<8} rien à juger — "
                    f"{self.findings} finding(s), tous déjà décidés")
        detail = f"{self.refuted} réfuté · {self.confirmed} confirmé"
        if self.contested:
            detail += f" · {self.contested} réfutation(s) contestée(s)"
        if self.failed:
            detail += f" · {self.failed} échec(s)"
        return (
            f"{self.part:<8} {self.judged:>3} jugé(s) ({detail}) · "
            f"{self.backlog} en attente"
        )


@dataclass
class Session:
    """Every round of one `thot improve` invocation."""

    rounds: list[list[PartRound]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    # A refutation is housekeeping; a confirmation is news. Kept whole rather
    # than counted, because "3 confirmé" sends the reader to grep the log —
    # which is what happened, every time, for a day.
    news: list = field(default_factory=list)

    @property
    def judged(self) -> int:
        return sum(part.judged for run in self.rounds for part in run)

    @property
    def failed(self) -> int:
        return sum(part.failed for run in self.rounds for part in run)

    @property
    def settled(self) -> int:
        """Decisions that actually decided something."""
        return sum(
            part.refuted + part.confirmed for run in self.rounds for part in run
        )

    @property
    def backlog(self) -> int:
        """What the last round left behind, across every tree."""
        return sum(part.backlog for part in self.rounds[-1]) if self.rounds else 0

    def summary(self) -> str:
        refuted = sum(p.refuted for run in self.rounds for p in run)
        confirmed = sum(p.confirmed for run in self.rounds for p in run)
        contested = sum(p.contested for run in self.rounds for p in run)
        detail = f"{refuted} réfuté · {confirmed} confirmé"
        if contested:
            detail += f" · {contested} réfutation(s) contestée(s)"
        if self.failed:
            detail += f" · {self.failed} échec(s)"
        line = (
            f"{len(self.rounds)} tour(s) · {self.judged} jugement(s) "
            f"({detail}) · {self.backlog} candidat(s) encore sans décision"
        )
        if not self.judged and not self.backlog and not self.failed:
            total = sum(p.findings for run in self.rounds for p in run)
            line += (
                f"\nRien à juger : les {total} finding(s) portent tous une "
                "décision. La boucle reprendra quand du code changera — un "
                "verdict expire avec le corps qu'il visait."
            )
        if self.failed and not self.settled:
            line += (
                "\nAucun verdict : toutes les tâches ont échoué. Regarde la "
                "raison au-dessus — un quota épuisé ou un agent absent se "
                "règle avant de relancer."
            )
        return line


def backlog_of(findings: list) -> int:
    """How many candidates a further round could still judge.

    Measured with the selector the deep pass itself uses, so the number is
    the real remaining work rather than a count of everything on screen.
    """
    from thot.analysis.probe import select_for_analysis

    return len(select_for_analysis(findings, limit=len(findings) or 1))


def _is_news(finding) -> bool:
    """What a reader has to act on: a confirmation, or a refutation refused.

    The second belongs here as much as the first — it is the program saying
    it caught itself about to bury something, which nobody should have to
    find in a log.
    """
    from thot.contracts import Confidence

    if finding.confidence is Confidence.CONFIRMED:
        return True
    return bool((finding.provenance or {}).get("réfutation contestée"))


def one_round(
    *,
    budget: int,
    parallel: int,
    engine_name: str = "",
    seen: set[str] | None = None,
    on_decided: Callable | None = None,
    news: list | None = None,
) -> list[PartRound]:
    """One bounded pass over every tree of the fused program."""
    from thot.contracts import Confidence
    from thot.fusion.audit import audit_all

    seen = seen if seen is not None else set()
    decided: dict[str, list] = {}

    def record(part: str, finding) -> None:
        decided.setdefault(part, []).append(finding)
        seen.add(finding.id)
        if news is not None and _is_news(finding):
            news.append((part, finding))
        if on_decided is not None:
            on_decided(finding)

    done = audit_all(
        deep=True,
        engine_name=engine_name,
        budget=budget,
        parallel=parallel,
        skip=seen,
        on_decided=record,
    )

    rounds: list[PartRound] = []
    for part in done:
        if not part.ok:
            rounds.append(PartRound(part=part.name, error=part.error))
            continue
        mine = decided.get(part.name, [])
        rounds.append(
            PartRound(
                part=part.name,
                findings=len(part.result.findings),
                judged=len(mine),
                refuted=sum(
                    1 for f in mine if f.confidence is Confidence.REFUTED
                ),
                confirmed=sum(
                    1 for f in mine if f.confidence is Confidence.CONFIRMED
                ),
                contested=sum(
                    1 for f in mine
                    if (f.provenance or {}).get("réfutation contestée")
                ),
                failed=sum(
                    1 for f in mine
                    if (f.provenance or {}).get("erreur")
                    or (f.provenance or {}).get("réfutation")
                ),
                backlog=backlog_of(part.result.findings),
            )
        )
    return rounds


def improve(
    *,
    rounds: int = 1,
    budget: int = 20,
    parallel: int = 4,
    engine_name: str = "",
    on_round: Callable[[int, list[PartRound]], None] | None = None,
    on_decided: Callable | None = None,
) -> Session:
    """Run bounded rounds until the budget stops buying anything.

    Stops early on a round that settled nothing — an empty backlog, an
    engine that cannot decide these candidates, or a subscription that ran
    out mid-pass. All three make the next identical round worthless.
    """
    session = Session()
    for index in range(max(1, rounds)):
        done = one_round(
            budget=budget,
            parallel=parallel,
            engine_name=engine_name,
            seen=session.seen,
            on_decided=on_decided,
            news=session.news,
        )
        session.rounds.append(done)
        if on_round is not None:
            on_round(index + 1, done)
        # Stops on "nothing was decided", not on "nothing was looked at".
        # A round where every task failed leaves findings judged and nothing
        # settled; running the same round again buys the same nothing.
        if not any(part.refuted + part.confirmed for part in done):
            break
    return session
