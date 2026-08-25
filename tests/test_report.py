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


# --- deux appels dangereux dans une fonction sont deux findings ------------
#
# `Finding.compute_id` intègre `site` précisément pour que cinq `httpx.get`
# dans un même corps soient cinq findings, et qu'un verdict sur l'un ne parle
# pas pour les quatre autres. Le JSON exportait `path`, `line` et `symbol`
# mais pas `site` : deux findings au même endroit y étaient indiscernables,
# distingués seulement par un identifiant opaque. Mesuré sur Hermes,
# `sink.js.path` apparaît deux fois à `ui-tui/src/lib/memory.ts:219`, et 362
# findings portent un site.


def _sited(site):
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    location = CodeRef(path="a.ts", line=219, symbol="load", ast_hash="h",
                       site=site)
    return Finding(
        id=Finding.compute_id("sink.js.path", location),
        rule="sink.js.path", severity=Severity.LOW,
        confidence=Confidence.PLAUSIBLE, location=location,
        failure_scenario="une valeur atteint join",
    )


def _rendered(findings):
    import json

    from thot.report.json_report import render_json
    from thot.scope.detect import ScopeManifest

    manifest = ScopeManifest(root=".", files=["a.ts"],
                             languages={"typescript": 1},
                             entrypoints=(), test_command="")
    return json.loads(render_json(findings, manifest, 0.1))


def test_two_findings_at_one_line_are_distinguishable_in_json():
    body = _rendered([_sited("join#0"), _sited("join#1")])

    sites = [f["location"].get("site") for f in body["findings"]]

    assert sites == ["join#0", "join#1"], body["findings"]


def test_a_location_without_a_site_says_nothing_extra():
    body = _rendered([_sited(None)])

    # Absente, pas présente à None : sinon la clé apparaît dans tous les
    # emplacements et la mutation qui l'exporte inconditionnellement passe.
    assert "site" not in body["findings"][0]["location"]


# --- le JSON doit dire si un panel a tourné --------------------------------
#
# Le résumé compte `total`, `by_severity` et `hidden_below_threshold` — rien
# sur la confiance ni sur le moteur. Après une passe `--deep`, un
# consommateur en intégration continue ne peut donc pas distinguer un audit
# déterministe d'un audit argumenté, ni savoir ce que le panel a décidé.
# `AuditResult` porte les deux informations ; elles n'étaient pas exportées.


def test_a_deterministic_run_says_no_engine_argued():
    body = _rendered([_sited(None)])

    assert body["summary"]["engine"] is None
    assert body["summary"]["by_confidence"] == {"plausible": 1}


def test_an_argued_run_reports_what_the_panel_decided():
    import json

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.report.json_report import render_json
    from thot.scope.detect import ScopeManifest

    def one(identifier, severity, confidence):
        return Finding(
            id=identifier, rule="sink.js.exec", severity=severity,
            confidence=confidence,
            location=CodeRef(path="a.ts", line=1, symbol="s", ast_hash="h"),
            failure_scenario="x",
        )

    kept = [one("k", Severity.HIGH, Confidence.PLAUSIBLE)]
    judged = kept + [one("r", Severity.INFO, Confidence.REFUTED)]
    manifest = ScopeManifest(root=".", files=["a.ts"],
                             languages={"typescript": 1},
                             entrypoints=(), test_command="")

    body = json.loads(render_json(kept, manifest, 0.1, hidden=1,
                                  judged=judged, engine="panel"))

    assert body["summary"]["engine"] == "panel"
    assert body["summary"]["by_confidence"]["refuted"] == 1
    assert body["summary"]["by_confidence"]["plausible"] == 1


def test_the_markdown_header_says_a_panel_argued(tmp_path):
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.report.markdown_report import render_markdown
    from thot.scope.detect import ScopeManifest

    def one(identifier, severity, confidence):
        return Finding(
            id=identifier, rule="sink.js.exec", severity=severity,
            confidence=confidence,
            location=CodeRef(path="a.ts", line=1, symbol="s", ast_hash="h"),
            failure_scenario="x",
        )

    kept = [one("k", Severity.HIGH, Confidence.PLAUSIBLE)]
    judged = kept + [one("r", Severity.INFO, Confidence.REFUTED)]
    manifest = ScopeManifest(root=".", files=["a.ts"],
                             languages={"typescript": 1},
                             entrypoints=(), test_command="")

    text = render_markdown(kept, manifest, 0.1, hidden=1,
                           judged=judged, engine="panel")

    assert "panel" in text
    assert "1 réfuté" in text


def test_a_deterministic_markdown_report_claims_no_panel(tmp_path):
    from thot.report.markdown_report import render_markdown
    from thot.scope.detect import ScopeManifest

    manifest = ScopeManifest(root=".", files=["a.ts"],
                             languages={"typescript": 1},
                             entrypoints=(), test_command="")

    text = render_markdown([_sited(None)], manifest, 0.1)

    # Pas seulement l'absence du mot : la ligne entière ne doit pas paraître,
    # sinon elle s'affiche « Jugé par None : » sur un audit déterministe.
    assert "Jugé par" not in text, text


def test_the_json_carries_the_rule_that_started_the_path():
    """A CI gate re-ranking findings needs the fact the rank came from, not
    a French sentence to parse."""
    import json

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.report.json_report import render_json

    finding = Finding(
        id="x", rule="sink.fs.read", severity=Severity.LOW,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="a.py", line=1, symbol="main"),
        failure_scenario="peu importe",
        provenance={"source_rule": "source.argv"},
    )
    from pathlib import Path

    from thot.scope.manifest import ScopeManifest

    manifest = ScopeManifest(root=Path("."), files=(), languages={},
                             entrypoints=())
    payload = json.loads(render_json([finding], manifest, 0.0))

    assert payload["findings"][0]["source_rule"] == "source.argv"
