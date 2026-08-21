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


# -- unknown accessibility is not low accessibility --------------------------
# When no entry point was detected at all, the graph knows nothing about reach.
# Discounting on that ignorance buried a real RCE under the default threshold,
# which is the worst failure an audit tool has.


def test_unreachable_is_discounted_when_entrypoints_exist():
    assert accessibility_weight(None, entrypoints_known=True) == 0.2


def test_unknown_reach_is_not_treated_as_unreachable():
    assert accessibility_weight(None, entrypoints_known=False) > 0.5


def test_a_critical_sink_stays_visible_without_entrypoints():
    severity = compute_severity(
        Severity.CRITICAL, None, Confidence.PLAUSIBLE, entrypoints_known=False
    )
    assert severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def test_a_critical_sink_is_buried_when_provably_unreachable():
    severity = compute_severity(
        Severity.CRITICAL, None, Confidence.PLAUSIBLE, entrypoints_known=True
    )
    assert severity is Severity.LOW


def test_known_distances_are_unaffected_by_the_flag():
    for distance in (0, 1, 2, 5):
        assert accessibility_weight(distance, entrypoints_known=False) == (
            accessibility_weight(distance, entrypoints_known=True)
        )
