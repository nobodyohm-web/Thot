"""severity = impact x accessibility x confidence.

Accessibility comes from the call graph, not from a judgement call: a defect
that no entry point can reach is discounted automatically. This is the single
most effective false-positive filter in real audits.
"""

from __future__ import annotations

from thot.contracts import Confidence, Severity

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
    distance: int | None, *, entrypoints_known: bool = True
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
) -> Severity:
    score = (
        _IMPACT_SCORE[impact]
        * accessibility_weight(distance, entrypoints_known=entrypoints_known)
        * _CONFIDENCE_SCORE[confidence]
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
