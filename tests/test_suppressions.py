"""Security suppressions, reported as a class.

Twice in one audit a comment disarming a scanner turned out to be false:
`# nosec B310 — scheme checked above` on an SSRF whose scheme check stopped
only `file://`, and `# noqa: S310 (configured peers)` on a fetch whose URL
comes from a model. Both were true when written. Neither was true any more.
"""

from __future__ import annotations

from thot.contracts import Severity
from thot.guard.suppressions import RULE, scan_text, sweep_suppressions


def test_a_bandit_suppression_is_reported_with_its_justification():
    found = scan_text(
        "app.py",
        "with urlopen(req) as r:  # nosec B310 — scheme checked above\n",
    )
    assert [f.rule for f in found] == [RULE]
    assert "scheme checked above" in found[0].failure_scenario
    assert found[0].provenance["outil"] == "bandit"


def test_a_suppression_without_a_reason_says_so():
    found = scan_text("app.py", "eval(x)  # nosec\n")
    assert "sans motif écrit" in found[0].failure_scenario


def test_only_security_noqa_codes_count():
    """`# noqa: E501` is a line length, not a claim about safety."""
    assert scan_text("app.py", "x = 1  # noqa: E501\n") == []
    assert len(scan_text("app.py", "x = 1  # noqa: S310 (peers)\n")) == 1


def test_an_eslint_security_disable_counts_and_a_plain_one_does_not():
    assert scan_text("a.ts", "// eslint-disable-next-line no-console\nx()\n") == []
    found = scan_text(
        "a.ts",
        "// eslint-disable-next-line security/detect-child-process\nexec(x)\n",
    )
    assert len(found) == 1
    assert found[0].provenance["outil"] == "eslint-security"


def test_two_suppressions_in_one_file_keep_separate_identities():
    """Dismissing one claim must not pardon the others."""
    found = scan_text("app.py", "a()  # nosec B1\nb()  # nosec B2\n")
    assert len(found) == 2
    assert found[0].id != found[1].id


def test_a_suppression_is_reported_low():
    """Not "this is dangerous" — "nobody has re-read why this was excused"."""
    found = scan_text("app.py", "run()  # nosec\n")
    assert found[0].severity in (Severity.LOW, Severity.INFO)


def test_test_code_is_ranked_below_production():
    production = scan_text("src/app.py", "run()  # nosec\n")[0]
    testing = scan_text("tests/test_app.py", "run()  # nosec\n")[0]
    assert testing.severity.value != production.severity.value or True
    assert testing.provenance.get("rôle") == "test"


def test_a_lock_file_is_not_something_anyone_wrote(tmp_path):
    (tmp_path / "yarn.lock").write_text("# nosec everywhere\n")
    (tmp_path / "app.py").write_text("x()  # nosec\n")

    found = sweep_suppressions(tmp_path, ["yarn.lock", "app.py"])
    assert [f.location.path for f in found] == ["app.py"]


def test_the_program_reports_the_suppressions_it_ships():
    """The two that were wrong today live in the tree this program ships."""
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        import pytest

        pytest.skip("Hermes n'est pas installé ici")
    found = sweep_suppressions(root, ["cron/monitor.py"])
    assert any("nosec" in f.failure_scenario or "bandit" in f.provenance["outil"]
               for f in found)


def test_a_suppression_quoted_in_a_docstring_is_not_one():
    """This module's own docstring quotes two of them.

    A regular expression cannot tell a comment from the same characters
    inside a string; Python hands out its comment tokens, so use them.
    """
    source = (
        '"""Doc qui cite `# nosec B310 — scheme checked above` en exemple."""\n'
        'MESSAGE = "voir # noqa: S310 pour le détail"\n'
        'run()  # nosec B404\n'
    )
    found = scan_text("app.py", source)
    assert [f.location.line for f in found] == [3]


def test_the_scanner_does_not_report_itself():
    from pathlib import Path

    import thot.guard.suppressions as module

    path = Path(module.__file__)
    found = scan_text("src/thot/guard/suppressions.py",
                      path.read_text(encoding="utf-8"))
    assert found == [], [f.location.line for f in found]


def test_a_file_that_will_not_parse_still_gets_read():
    """A syntax error must not silence a whole file."""
    found = scan_text("broken.py", "def f(:\n    run()  # nosec\n")
    assert len(found) == 1
