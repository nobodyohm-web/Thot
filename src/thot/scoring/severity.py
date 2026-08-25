"""severity = impact x accessibility x confidence.

Accessibility comes from the call graph, not from a judgement call: a defect
that no entry point can reach is discounted automatically. This is the single
most effective false-positive filter in real audits.

It is also the most dangerous, because "the graph found no path" and "there
is no path" are not the same sentence. Two cases are therefore separated
from genuine unreachability: a repository where no entry point was found at
all, and a symbol that is handed around by name rather than called. Both get
a mild penalty instead of a burial.
"""

from __future__ import annotations

from thot.contracts import Confidence, Severity
from thot.scoring.role import Role, role_weight

_IMPACT_SCORE = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

_CONFIDENCE_SCORE = {
    Confidence.CONFIRMED: 1.0,
    Confidence.PLAUSIBLE: 0.6,
    Confidence.REFUTED: 0.0,
}


def accessibility_weight(
    distance: int | None, *, entrypoints_known: bool = True,
    escapes: bool = False,
) -> float:
    """Closeness to a public entry point, as a multiplier.

    `distance is None` carries two very different meanings, and conflating
    them is dangerous. When the graph has entry points, unreachable really
    means unreachable and the discount is the point of this whole function.
    When it has none — a library, a framework Thot does not recognise, a
    partial checkout — reach is simply unknown, and discounting on that
    ignorance buries real defects below the default threshold. Unknown gets a
    mild penalty, not a burial.
    """
    if distance is None:
        # A symbol handed around by name — put in a dispatch table, passed
        # to a framework, decorated — is reached by a route the graph
        # cannot follow. That is unknown reach, not absence of reach, and
        # it is the ordinary case in any web application.
        #
        # `entrypoints_known` is repository-wide, and entry-point detection
        # is Python-only — `scope.detect._python_entrypoints` is its sole
        # producer. So a repository holding one Python `main()` and nine
        # hundred TypeScript files answers True here for its TypeScript
        # symbols too. The per-language answer is `escapes`, decided by
        # `CodeGraph.reach_unknown`, which reports unknown reach for every
        # symbol outside the language the entry points describe.
        #
        # This comment used to claim the gap cost nothing, having measured
        # that no severity moved on the two shipped trees. That measurement
        # was wrong: `sink.js.exec` and `sink.js.spawn` carry CRITICAL
        # impact, and 1.0 x 0.8 x 0.6 = 0.48 against 1.0 x 0.2 x 0.6 = 0.12
        # crosses two thresholds. Re-measured, on hermes/ alone three
        # JavaScript findings move from low to medium — from hidden to shown
        # at the default threshold — one of them in `electron/terminal-ipc`.
        if escapes:
            return 0.8
        return 0.2 if entrypoints_known else 0.8
    if distance == 0:
        return 1.0
    if distance <= 2:
        return 0.8
    return 0.5


def compute_severity(
    impact: Severity,
    distance: int | None,
    confidence: Confidence,
    *,
    entrypoints_known: bool = True,
    escapes: bool = False,
    role: Role = Role.PRODUCTION,
    reachable: bool = False,
) -> Severity:
    """`role` is the fourth term the graph cannot supply.

    Reachability answers "can an entry point get here". It has nothing to say
    about a file that is not an attack surface at all — a test, a fixture, an
    example — and on the two programs Thot ships with, half the HIGH findings
    were exactly that.
    """
    # `reachable` is for a finding that is a property of the line rather than
    # of a path to it — a pattern match. There is no route to discount,
    # because the rule never claimed one.
    score = (
        _IMPACT_SCORE[impact]
        * (1.0 if reachable else
           accessibility_weight(distance, entrypoints_known=entrypoints_known,
                                escapes=escapes))
        * _CONFIDENCE_SCORE[confidence]
        * role_weight(role)
    )
    if score >= 0.7:
        return Severity.CRITICAL
    if score >= 0.45:
        return Severity.HIGH
    if score >= 0.25:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
