import json

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.report.json_report import render_json
from thot.report.markdown_report import render_markdown
from thot.scope.manifest import ScopeManifest


def sample():
    ref = CodeRef(path="src/app.py", line=10, symbol="src.app.run", ast_hash="abc")
    finding = Finding(
        id="deadbeef",
        rule="sink.os.system",
        severity=Severity.CRITICAL,
        confidence=Confidence.PLAUSIBLE,
        location=ref,
        taint_path=(ref,),
        failure_scenario="sys.argv[1] reaches os.system unfiltered",
    )
    manifest = ScopeManifest(
        root="/repo", files=("src/app.py",), languages={"python": 1},
        entrypoints=("src.app.main",), test_command="pytest",
    )
    return [finding], manifest


def test_json_is_parseable_and_carries_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule"] == "sink.os.system"
    assert payload["summary"]["by_severity"]["critical"] == 1


def test_json_never_contains_absolute_paths_in_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert not payload["findings"][0]["location"]["path"].startswith("/")


def test_markdown_has_a_heading_and_the_finding():
    findings, manifest = sample()
    text = render_markdown(findings, manifest, elapsed=1.5)
    assert text.startswith("# ")
    assert "src/app.py:10" in text
    assert "sink.os.system" in text


def test_empty_report_says_so_explicitly():
    _, manifest = sample()
    text = render_markdown([], manifest, elapsed=0.2)
    assert "Aucun" in text


# -- what the reader is told the findings are --------------------------------


def _finding(confidence, severity=Severity.LOW):
    location = CodeRef(path="src/app.py", line=3, symbol="run", ast_hash="h")
    return Finding(
        id=Finding.compute_id("sink.eval", location),
        rule="sink.eval",
        severity=severity,
        confidence=confidence,
        location=location,
    )


def test_a_static_only_report_says_everything_is_plausible():
    from thot.console import _confidence_note

    note = _confidence_note([_finding(Confidence.PLAUSIBLE)])
    assert "PLAUSIBLE" in note


def test_an_argued_report_does_not_call_its_verdicts_plausible():
    """The last line outranks the table; it must not contradict it."""
    from thot.console import _confidence_note

    note = _confidence_note([
        _finding(Confidence.REFUTED, Severity.INFO),
        _finding(Confidence.CONFIRMED, Severity.HIGH),
    ])
    assert "réfuté" in note
    assert "confirmé" in note
    assert "Chaque finding est PLAUSIBLE" not in note


def test_a_mixed_report_keeps_the_caveat_for_the_unproven_half():
    from thot.console import _confidence_note

    note = _confidence_note([
        _finding(Confidence.REFUTED, Severity.INFO),
        _finding(Confidence.PLAUSIBLE),
    ])
    assert "réfuté" in note
    assert "plausible" in note
    assert "pas encore prouvé" in note


def test_a_report_says_which_languages_it_only_pattern_scanned():
    """912 TypeScript files and 23 Python ones got very different analyses.
    A file count alone let a reader assume they got the same."""
    from thot.console import _pattern_only

    said = _pattern_only({"python": 23, "typescript": 912, "javascript": 3})
    assert "typescript 912" in said
    assert "python" not in said


def test_an_all_python_repository_says_nothing_extra():
    from thot.console import _pattern_only

    assert _pattern_only({"python": 162}) == ""


def test_the_summary_names_every_stage_of_the_cascade():
    """The escalation is the step the panel exists for.

    A summary that stopped at the first attacker made the third agent's work
    invisible — and that agent is the one who decides whether a finding is
    reported at all.
    """
    from thot.console import _panel_note
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    finding = Finding(
        id="1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED, location=location,
        provenance={
            "moteur": "claude-cli",
            "contradicteur": "prime",
            "second contradicteur": "hermes",
        },
    )

    note = _panel_note([finding])

    assert "Argumenté par claude-cli 1" in note
    assert "attaqué par prime 1" in note
    assert "puis par hermes 1" in note


def test_a_deterministic_run_has_nothing_to_say_about_judges():
    from thot.console import _panel_note
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    finding = Finding(
        id="1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE, location=location,
    )
    assert _panel_note([finding]) == ""


def test_every_format_shows_who_judged_the_finding():
    """The JSON report carried the panel's stages; Markdown and HTML did not.

    Two of the four ways of reading an audit hid its entire point — and a
    stage added to the cascade would have drifted into one format only.
    """
    from pathlib import Path

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.report.html_report import audit_page
    from thot.report.json_report import render_json
    from thot.report.markdown_report import render_markdown
    from thot.scope.manifest import ScopeManifest

    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    finding = Finding(
        id="1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED, location=location,
        failure_scenario="argv atteint le shell",
        provenance={"moteur": "claude-cli", "contradicteur": "prime",
                    "second contradicteur": "hermes"},
    )
    manifest = ScopeManifest(root=Path("."), files=("a.py",),
                             languages={"python": 1}, entrypoints=())

    as_json = render_json([finding], manifest, 1.0)
    as_markdown = render_markdown([finding], manifest, 1.0)

    for name in ("claude-cli", "prime", "hermes"):
        assert name in as_json
        assert name in as_markdown

    class _Result:
        findings = [finding]
        elapsed = 1.0

    _Result.manifest = manifest
    as_html = audit_page(_Result(), root=".").html
    for name in ("claude-cli", "prime", "hermes"):
        assert name in as_html


def test_a_deterministic_finding_shows_no_judgement():
    """Nobody was asked, which is not the same as nobody having anything to say."""
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.report import judgement

    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    finding = Finding(
        id="1", rule="r", severity=Severity.LOW,
        confidence=Confidence.PLAUSIBLE, location=location,
    )
    assert judgement(finding) == []


def test_the_report_states_the_depth_it_actually_reached():
    """The tiers drifted once already, in the wrong direction.

    The JavaScript taint engine was written and the language list was not
    updated, so for an afternoon every report told its reader that TypeScript
    had no taint engine while it had one. A claim about depth is worth as
    much as the code behind it.
    """
    from thot.console import _pattern_only

    deep = _pattern_only({"python": 10})
    assert deep == "", "le langage le plus couvert n'a rien à signaler"

    shallow = _pattern_only({"typescript": 912})
    assert "au fichier près" in shallow
    assert "sans moteur de teinte" not in shallow

    blind = _pattern_only({"yaml": 4})
    assert "motifs seuls" in blind


def test_the_three_tiers_are_consistent_with_each_other():
    """Deeper implies shallower: a language cannot cross files without being
    tainted at all, nor be tainted without being indexed."""
    from thot.codemap import (
        DEEP_TAINT_LANGUAGES,
        INDEXED_LANGUAGES,
        TAINTED_LANGUAGES,
    )

    assert set(DEEP_TAINT_LANGUAGES) <= set(TAINTED_LANGUAGES)
    assert set(TAINTED_LANGUAGES) <= set(INDEXED_LANGUAGES)
