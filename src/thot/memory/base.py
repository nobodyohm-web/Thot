"""What Thot remembers between audits, and the port that stores it.

The expensive part of an audit is not finding candidates — the deterministic
phases do that in seconds, for free. It is deciding what they mean. Losing
those decisions between runs is what makes security tooling unbearable: the
same forty dismissals, every week, forever, until nobody reads the report.

The pivot is the key. A verdict is stored against `Finding.compute_id`, which
hashes rule + file + symbol + the *normalised* AST of that symbol. Reformat
the file, move the function, rename a local — the verdict holds. Change what
the code actually does and the id changes with it, so the verdict expires by
construction. A dismissal can never outlive the code it was about, which is
the one property that makes remembering dismissals safe at all.

The provider contract is adapted from Hermes Agent's MemoryProvider ABC
(MIT, Copyright (c) 2025 Nous Research), narrowed to what an auditor needs:
durable decisions rather than conversational recall.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from thot.contracts import Confidence, Finding, Severity


class Decision(str, Enum):
    """What a human — or an adversarial pass — concluded about a finding."""

    REFUTED = "refuted"    # not a real defect; stop reporting it
    ACCEPTED = "accepted"  # real, and the risk is knowingly carried
    FIXED = "fixed"        # was real, was corrected; seeing it again is news

    @classmethod
    def parse(cls, word: str) -> "Decision | None":
        """Accept what someone actually types at a prompt.

        Nobody types the past participle. Refusing `refute` because the enum
        member is `refuted` is the kind of friction that stops a decision
        being recorded at all — and an unrecorded decision gets asked again
        next week.
        """
        return _ALIASES.get(word.strip().lower().rstrip("."))


_ALIASES: dict[str, Decision] = {
    **{w: Decision.REFUTED for w in
       ("refute", "refuted", "refuter", "réfute", "réfuté", "réfuter",
        "ecarte", "écarte", "ecarter", "écarter", "faux", "fp", "no")},
    **{w: Decision.ACCEPTED for w in
       ("accept", "accepted", "accepte", "accepté", "accepter",
        "assume", "assumé", "risque", "ok")},
    **{w: Decision.FIXED for w in
       ("fix", "fixed", "corrige", "corrigé", "corriger", "fait", "done")},
}


@dataclass(frozen=True)
class Verdict:
    finding_id: str
    decision: Decision
    reason: str = ""
    author: str = ""
    rule: str = ""
    path: str = ""
    symbol: str = ""
    ast_hash: str = ""
    decided_at: str = ""

    @staticmethod
    def of(
        finding: Finding,
        decision: Decision,
        reason: str = "",
        author: str = "",
    ) -> "Verdict":
        return Verdict(
            finding_id=finding.id,
            decision=decision,
            reason=reason,
            author=author,
            rule=finding.rule,
            path=finding.location.path,
            symbol=finding.location.symbol or "",
            ast_hash=finding.location.ast_hash or "",
            decided_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )


class Memory(Protocol):
    """Where verdicts live. One implementation ships; the port allows others."""

    name: str

    def is_available(self) -> bool: ...
    def remember(self, verdict: Verdict) -> None: ...
    def recall(self, finding_id: str) -> Verdict | None: ...
    def all_verdicts(self) -> list[Verdict]: ...
    def forget(self, finding_id: str) -> bool: ...


def apply_memory(findings: list[Finding], memory: Memory) -> list[Finding]:
    """Fold past decisions into a fresh run.

    Nothing is ever removed. A dismissed finding stays in the report as
    `refuted` with the reason attached — an audit that silently drops what it
    was told to ignore cannot be reviewed, and a reviewer must be able to see
    what was dismissed and by whom.
    """
    out: list[Finding] = []
    for finding in findings:
        verdict = memory.recall(finding.id)
        if verdict is None:
            out.append(finding)
            continue
        out.append(_fold(finding, verdict))
    return out


# The key `_fold` stamps on a finding it has decided. Named, because
# `select_for_analysis` reads it to keep the model away from decided
# findings: a bare string in two files is a coupling nobody can see.
DECISION_KEY = "mémoire"


def carries_decision(finding: Finding) -> bool:
    """True when a recorded verdict has already been folded into this finding."""
    return bool((finding.provenance or {}).get(DECISION_KEY))


def _fold(finding: Finding, verdict: Verdict) -> Finding:
    provenance = dict(finding.provenance or {})
    provenance[DECISION_KEY] = verdict.decision.value
    if verdict.author:
        provenance["décidé par"] = verdict.author
    if verdict.decided_at:
        provenance["décidé le"] = verdict.decided_at

    reason = verdict.reason or "sans raison consignée"

    if verdict.decision is Decision.REFUTED:
        # Severity is impact × reach × confidence, and refuted confidence
        # scores zero. Leaving a dismissed finding at HIGH would keep it at
        # the top of every report, which is the opposite of dismissing it.
        return replace(
            finding,
            confidence=Confidence.REFUTED,
            severity=Severity.INFO,
            failure_scenario=f"{finding.failure_scenario}\n\nÉcarté : {reason}",
            provenance=provenance,
        )

    if verdict.decision is Decision.ACCEPTED:
        return replace(
            finding,
            severity=Severity.INFO,
            failure_scenario=f"{finding.failure_scenario}\n\nRisque accepté : {reason}",
            provenance=provenance,
        )

    # FIXED, and here it is again with the same normalised body: the fix was
    # reverted or never landed. That is worth interrupting someone for.
    provenance["régression"] = True
    return replace(
        finding,
        severity=Severity.HIGH if finding.severity is Severity.INFO else finding.severity,
        confidence=Confidence.CONFIRMED,
        failure_scenario=(
            f"{finding.failure_scenario}\n\nRÉGRESSION : marqué corrigé "
            f"({reason}), le code est revenu à son état d'avant."
        ),
        provenance=provenance,
    )


def record_verdicts(
    findings: list[Finding], memory: Memory, *, author: str = "thot"
) -> int:
    """Persist what an adversarial pass concluded. Returns how many were kept.

    Only refutations. A refutation costs two model calls and answers a
    question whose answer does not change until the code does — exactly the
    thing worth caching. Confirmations are deliberately not stored: a
    confirmed defect must keep showing up until someone fixes it.
    """
    kept = 0
    for finding in findings:
        if finding.confidence is not Confidence.REFUTED:
            continue
        if memory.recall(finding.id) is not None:
            continue  # a human decision outranks a machine one
        # The review stage runs only for findings that matter, and exists to
        # catch a wrong refutation before it silences a live defect. When it
        # could not run — quota, timeout, agent absent — the refutation stands
        # for this run's report but is not cached: an unverified refutation
        # must not gain the permanence of a verified one. Left uncached, the
        # next round argues it again, which is what "we do not know whether
        # the refutation holds" means.
        if (finding.provenance or {}).get("relecture impossible"):
            continue
        reason = _reason_from(finding)
        # On a panel the refuter is not the arguer, and the verdict belongs
        # to the one who refuted. `author` stays the fallback for a single
        # engine, which records nothing in provenance.
        provenance = finding.provenance or {}
        decided_by = str(
            provenance.get("second contradicteur")
            or provenance.get("contradicteur")
            or provenance.get("moteur")
            or author
        )
        verdict = Verdict.of(finding, Decision.REFUTED, reason, decided_by)
        memory.remember(verdict)
        _announce(verdict)
        kept += 1
    return kept


def _announce(verdict: Verdict) -> None:
    """Tell the plugins a decision was taken. Imported late: the core must
    stay importable without the plugin machinery behind it."""
    try:
        from thot.plugins import notify_verdict
    except ImportError:
        return
    notify_verdict(verdict)


# The reason is the whole value of a stored verdict — `/verdict` refuses to
# record a decision without one, on the grounds that it will be read back in
# six months. A cap of 300 characters cut 27 of 28 machine refutations
# mid-word, ending them on "Mais la s". Generous, and never mid-sentence.
MAX_REASON = 4000


def _reason_from(finding: Finding) -> str:
    """The argument that settled this finding.

    Two shapes reach here. A two-stage refutation carries the marker and its
    reason after it; a probe that refuted on its own carries the argument as
    the scenario itself, with no marker — and that second path is the common
    one, which is why the cap mattered so much.
    """
    marker = "Réfuté :"
    scenario = finding.failure_scenario
    if marker in scenario:
        return _trim(scenario.split(marker, 1)[1].strip())
    return _trim(scenario.strip())


def _trim(text: str, limit: int = MAX_REASON) -> str:
    """Cut on a sentence, or failing that on a word. Never inside one."""
    if len(text) <= limit:
        return text

    window = text[:limit]
    for stop in (". ", "; ", ".\n"):
        cut = window.rfind(stop)
        if cut > limit // 2:
            return window[: cut + 1] + " […]"
    cut = window.rfind(" ")
    return (window[:cut] if cut > limit // 2 else window) + " […]"
