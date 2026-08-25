import pytest

from thot.contracts import Confidence, Severity
from thot.scoring.role import Role
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


# -- unknown reach is not absence of reach ------------------------------------


def test_an_escaping_symbol_is_not_discounted_like_a_dead_one():
    from thot.contracts import Confidence, Severity
    from thot.scoring.severity import accessibility_weight, compute_severity

    assert accessibility_weight(None, entrypoints_known=True) == 0.2
    assert accessibility_weight(None, entrypoints_known=True, escapes=True) == 0.8

    buried = compute_severity(Severity.HIGH, None, Confidence.PLAUSIBLE,
                              entrypoints_known=True)
    kept = compute_severity(Severity.HIGH, None, Confidence.PLAUSIBLE,
                            entrypoints_known=True, escapes=True)

    # 0.75 x 0.8 x 0.6 = 0.36 — a rung up, and out of the noise floor a
    # default report hides. Not HIGH: reach is unknown, not established.
    assert buried is Severity.LOW
    assert kept is Severity.MEDIUM

    critical = compute_severity(Severity.CRITICAL, None, Confidence.CONFIRMED,
                                entrypoints_known=True, escapes=True)
    assert critical is Severity.CRITICAL


def test_a_reachable_symbol_is_unaffected_by_the_escape_signal():
    from thot.scoring.severity import accessibility_weight

    for distance in (0, 1, 5):
        assert accessibility_weight(distance) == \
            accessibility_weight(distance, escapes=True)


# -- what the flag is fed with -----------------------------------------------
#
# The primitive above is right and unchanged; what lied was its input.
# `entrypoints_known` is repository-wide and `escapes` is per symbol, so the
# two tests below score a real graph instead of a literal: they are the only
# place where the whole chain — one `main()` somewhere, a proven path
# elsewhere — is followed from the tree to the rank a reader sees.


def _scored(root, symbol: str, impact: Severity) -> Severity:
    """Score one symbol exactly as `pipeline.findings_from_graph` does."""
    from thot.codemap.graph import CodeGraph
    from thot.codemap.index import index_files
    from thot.scope.detect import detect_scope

    manifest = detect_scope(root)
    graph = CodeGraph.build(index_files(root, manifest.files), manifest.entrypoints)
    return compute_severity(
        impact,
        graph.distance_from_entrypoints(symbol),
        Confidence.PLAUSIBLE,
        entrypoints_known=bool(graph.entrypoints),
        escapes=graph.reach_unknown(symbol),
    )


def test_an_unrelated_python_entrypoint_does_not_bury_a_typescript_sink(tmp_path):
    """1.0 x 0.8 x 0.6 = 0.48 against 1.0 x 0.2 x 0.6 = 0.12 — two thresholds.

    No TypeScript symbol is reachable from a Python `main()` by construction,
    so answering "unreachable" for one is a verdict from a graph that never
    covered it. At the default threshold the finding does not drop a rung, it
    leaves the report.
    """
    (tmp_path / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    (tmp_path / "named.ts").write_text(
        'import { exec } from "child_process";\n'
        "export function handle(req: any) {\n"
        '  exec("ping " + req.query.host);\n'
        "}\n",
        encoding="utf-8",
    )

    assert _scored(tmp_path, "named.handle", Severity.CRITICAL) is Severity.HIGH


def test_an_unrelated_main_does_not_bury_a_helper_on_a_proven_path(tmp_path):
    """The decorated view is marked escaped; the helper it calls is not.

    Being called is exactly why the helper appears in nobody's `references`,
    and the proven `request.args` -> `conn.execute` path was ranked below the
    unproven pattern rule for it.
    """
    (tmp_path / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    (tmp_path / "web.py").write_text(
        "import sqlite3\n\n"
        "from flask import Flask, request\n\n"
        "app = Flask(__name__)\n\n\n"
        "def lookup(uid):\n"
        '    conn = sqlite3.connect("app.db")\n'
        '    return conn.execute("SELECT * FROM users WHERE id = " + uid)\n\n\n'
        '@app.route("/u")\n'
        "def user_view():\n"
        '    return lookup(request.args.get("id"))\n',
        encoding="utf-8",
    )

    assert _scored(tmp_path, "web.lookup", Severity.HIGH) is Severity.MEDIUM


# -- what a file is for --------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("packages/ai/test/stream.test.ts", Role.TEST),
        ("tests/conftest.py", Role.TEST),
        ("hermes_cli/test_helpers.py", Role.TEST),
        ("src/core/clipboard.ts", Role.PRODUCTION),
        ("packages/coding-agent/examples/extensions/sandbox/index.ts", Role.EXAMPLE),
        # A directory wins over a filename: this is an example whose helper
        # happens to be named like a test.
        ("examples/foo/test_helper.py", Role.EXAMPLE),
        # Segments, never substrings.
        ("src/latest/handler.py", Role.PRODUCTION),
        ("contest.py", Role.PRODUCTION),
        ("src/protests/model.py", Role.PRODUCTION),
    ],
)
def test_the_role_of_a_path(path, expected):
    from thot.scoring.role import role_of

    assert role_of(path) is expected


def test_a_test_file_is_demoted_not_buried():
    """It still runs on developer machines and in CI — that is a real
    surface, just not one an adversary reaches."""
    from thot.scoring.role import Role

    production = compute_severity(
        Severity.CRITICAL, None, Confidence.PLAUSIBLE, entrypoints_known=False
    )
    in_test = compute_severity(
        Severity.CRITICAL, None, Confidence.PLAUSIBLE,
        entrypoints_known=False, role=Role.TEST,
    )
    assert production is Severity.HIGH
    assert in_test is Severity.MEDIUM
    assert in_test is not Severity.INFO, "démotion, pas suppression"


def test_production_code_is_untouched_by_the_role_term():
    from thot.scoring.role import Role

    for distance in (0, 1, 3, None):
        assert compute_severity(
            Severity.HIGH, distance, Confidence.CONFIRMED
        ) is compute_severity(
            Severity.HIGH, distance, Confidence.CONFIRMED, role=Role.PRODUCTION
        )
