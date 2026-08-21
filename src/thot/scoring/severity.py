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


def accessibility_weight(distance: int | None) -> float:
    """Closeness to a public entry point, as a multiplier."""
    if distance is None:
        return 0.2
    if distance == 0:
        return 1.0
    if distance <= 2:
        return 0.8
    return 0.5


def compute_severity(
    impact: Severity, distance: int | None, confidence: Confidence
) -> Severity:
    score = (
        _IMPACT_SCORE[impact]
        * accessibility_weight(distance)
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
