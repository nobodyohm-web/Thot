from thot.contracts import Confidence, Severity
from thot.scoring.severity import accessibility_weight, compute_severity


def test_entrypoint_distance_has_full_weight():
    assert accessibility_weight(0) == 1.0


def test_unreachable_code_is_heavily_discounted():
    assert accessibility_weight(None) < 0.3


def test_critical_and_reachable_stays_critical():
    assert compute_severity(Severity.CRITICAL, 0, Confidence.CONFIRMED) == Severity.CRITICAL


def test_critical_but_unreachable_is_downgraded():
    result = compute_severity(Severity.CRITICAL, None, Confidence.PLAUSIBLE)
    assert result in {Severity.LOW, Severity.INFO}


def test_refuted_finding_is_always_info():
    assert compute_severity(Severity.CRITICAL, 0, Confidence.REFUTED) == Severity.INFO
