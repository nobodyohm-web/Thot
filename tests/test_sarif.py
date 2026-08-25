"""SARIF — the format the rest of the industry already reads.

A report nobody's pipeline can ingest is a report that lives in one terminal.
GitHub code scanning, GitLab, Azure DevOps and the editors all speak SARIF
2.1.0, and two of Thot's own properties matter more here than anywhere else:
a finding's identity is stable across line moves, which is exactly what a
fingerprint is for, and a taint path is a sequence of locations, which is
exactly what a code flow renders.
"""

from __future__ import annotations

import json
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.report.sarif_report import render_sarif
from thot.scope.manifest import ScopeManifest


def _manifest(root=".") -> ScopeManifest:
    return ScopeManifest(root=Path(root), files=(), languages={}, entrypoints=())


def _finding(rule="sink.os.system", severity=Severity.HIGH, **kwargs) -> Finding:
    location = kwargs.pop("location", CodeRef(path="src/app.py", line=7,
                                              symbol="src.app.main"))
    return Finding(
        id=kwargs.pop("id", "abc123"), rule=rule, severity=severity,
        confidence=kwargs.pop("confidence", Confidence.PLAUSIBLE),
        location=location,
        failure_scenario=kwargs.pop("failure_scenario", "une valeur atteint un sink"),
        **kwargs,
    )


def _render(findings, **kwargs) -> dict:
    return json.loads(render_sarif(findings, _manifest(), 0.5, **kwargs))


def test_it_is_a_sarif_document(): 
    payload = _render([_finding()])

    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert len(payload["runs"]) == 1
    assert payload["runs"][0]["tool"]["driver"]["name"] == "Thot"


def test_each_rule_is_declared_once_and_referenced_by_index():
    payload = _render([
        _finding(id="a"), _finding(id="b"),
        _finding(rule="sink.fs.read", severity=Severity.LOW, id="c"),
    ])
    run = payload["runs"][0]

    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "sink.os.system", "sink.fs.read"
    ]
    assert [r["ruleIndex"] for r in run["results"]] == [0, 0, 1]


def test_severity_becomes_a_level_a_pipeline_can_gate_on():
    levels = [
        _render([_finding(severity=s, id=str(i))])["runs"][0]["results"][0]["level"]
        for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                               Severity.LOW, Severity.INFO])
    ]

    assert levels == ["error", "error", "warning", "note", "note"]


def test_a_fingerprint_survives_a_line_moving():
    """The one thing that stops a code-scanning dashboard from reopening
    every finding the moment somebody adds an import at the top of a file.
    Thot's identity is rule + file + symbol + body hash, never the line."""
    here = _render([_finding()])["runs"][0]["results"][0]
    moved = _render([_finding(
        location=CodeRef(path="src/app.py", line=112, symbol="src.app.main"),
    )])["runs"][0]["results"][0]

    assert here["partialFingerprints"] == moved["partialFingerprints"]
    assert here["partialFingerprints"]["thotFindingId/v1"] == "abc123"


def test_the_taint_path_becomes_a_code_flow():
    path = (
        CodeRef(path="src/app.py", line=3, symbol="src.app.read"),
        CodeRef(path="src/app.py", line=7, symbol="src.app.main"),
    )
    result = _render([_finding(taint_path=path)])["runs"][0]["results"][0]

    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["physicalLocation"]["region"]["startLine"]
            for s in steps] == [3, 7]


def test_a_finding_without_a_path_carries_no_empty_flow():
    """An empty `codeFlows` renders in GitHub as a taint path with no steps,
    which reads as a broken analysis rather than a pattern match."""
    assert "codeFlows" not in _render([_finding()])["runs"][0]["results"][0]


def test_paths_are_relative_to_the_repository():
    """A report naming `/Users/dev/...` is a report that cannot be shared,
    and one that no scanning service can map to a file in the checkout."""
    payload = _render([_finding()])
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"] \
        ["artifactLocation"]["uri"]

    assert uri == "src/app.py"
    assert not uri.startswith("/")


def test_the_severity_a_scanning_service_reads_is_carried_too():
    """GitHub ranks by `security-severity`, a number, and ignores `level`
    for that purpose. Without it every finding lands in the same bucket."""
    critical = _render([_finding(severity=Severity.CRITICAL)])
    low = _render([_finding(severity=Severity.LOW)])

    def score(payload):
        return float(payload["runs"][0]["tool"]["driver"]["rules"][0]
                     ["properties"]["security-severity"])

    assert score(critical) > score(low)


def test_the_source_rule_travels_as_a_property():
    result = _render([_finding(provenance={"source_rule": "source.argv"})])
    assert result["runs"][0]["results"][0]["properties"]["source_rule"] == "source.argv"


def test_a_refuted_finding_says_so_rather_than_disappearing():
    """A panel argued it away; hiding it would leave a dashboard unable to
    tell `nobody looked` from `somebody looked and decided`."""
    result = _render([_finding(confidence=Confidence.REFUTED)])["runs"][0]["results"][0]

    assert result["properties"]["confidence"] == "refuted"
    assert result["suppressions"][0]["kind"] == "external"


def test_the_cli_routes_both_the_flag_and_the_suffix(tmp_path):
    """`--out rapport.sarif` has to work without also typing `--sarif`: a
    request for a file answered with a different format is the same bug as
    one answered with no file at all."""
    from thot.cli import build_parser, _output_format

    parser = build_parser()
    by_flag = parser.parse_args(["audit", ".", "--sarif"])
    by_suffix = parser.parse_args(["audit", ".", "--out", str(tmp_path / "r.sarif")])

    assert _output_format(by_flag) == "sarif"
    assert _output_format(by_suffix) == "sarif"


def test_no_absolute_path_reaches_the_document(tmp_path):
    """The whole document, not only the location: a shared SARIF file that
    names somebody's home directory is a leak and an unresolvable path at
    the same time."""
    payload = render_sarif(
        [_finding(taint_path=(CodeRef(path="src/a.py", line=1, symbol="f"),))],
        _manifest(), 0.1,
    )

    assert "/Users/" not in payload
    assert '"uri": "/' not in payload


def test_a_real_audit_produces_a_conformant_document(toy_repo):
    """Conformance checked on a document the tool actually produced, not on
    one the test built. The invariants are the ones a consumer breaks on:
    `ruleIndex` pointing at a different rule than `ruleId` names, a `level`
    outside the enum, a fingerprint that is not a string."""
    from thot.pipeline import run_audit
    from thot.scope.authorization import write_authorization

    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    payload = json.loads(
        render_sarif(result.findings, result.manifest, result.elapsed)
    )

    run = payload["runs"][0]
    declared = run["tool"]["driver"]["rules"]
    assert run["results"], "l'audit du dépôt jouet ne trouve plus rien"

    for entry in run["results"]:
        assert entry["level"] in {"none", "note", "warning", "error"}
        assert entry["message"]["text"]
        assert declared[entry["ruleIndex"]]["id"] == entry["ruleId"]
        assert all(isinstance(v, str)
                   for v in entry["partialFingerprints"].values())
        for step in entry.get("codeFlows", []):
            for flow in step["threadFlows"]:
                assert flow["locations"], "un flux sans étape ne se rend pas"
    assert len({rule["id"] for rule in declared}) == len(declared)


# -- the weakness class, without which nothing can be scored ------------------
#
# Every labelled corpus states its ground truth as a CWE. A report that names
# only `sink.sql` matches on nothing: a scorer reports a true-positive rate of
# zero for a wiring reason and the rule looks worthless when it may not be.


def test_a_rule_carries_the_weakness_class_it_belongs_to():
    doc = _render([_finding(rule="sink.sql")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["cwe"] == ["CWE-89"]


def test_the_tag_is_padded_the_way_scanning_services_read_it():
    """`external/cwe/cwe-089`, three digits — and no wider for a four-digit one."""
    doc = _render([_finding(rule="sink.sql"), _finding(rule="sink.js.prototype",
                                                       id="def456")])
    tags = {r["id"]: r["properties"]["tags"]
            for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "external/cwe/cwe-089" in tags["sink.sql"]
    assert "external/cwe/cwe-1321" in tags["sink.js.prototype"]


def test_the_taxonomy_declares_every_class_a_rule_points_at():
    """A relationship whose target is not declared is a dangling reference:
    a strict reader rejects the document, a lenient one drops the mapping
    silently — and the silent failure surfaces as a score of zero."""
    doc = _render([_finding(rule="sink.sql"),
                   _finding(rule="sink.eval", id="def456"),
                   _finding(rule="sink.network", id="ghi789")])
    run = doc["runs"][0]
    declared = {taxon["id"] for taxon in run["taxonomies"][0]["taxa"]}
    targets = {relationship["target"]["id"]
               for rule in run["tool"]["driver"]["rules"]
               for relationship in rule.get("relationships", [])}
    assert targets, "aucune relation émise"
    assert targets <= declared


def test_only_the_classes_this_run_used_are_declared():
    """The taxonomy is not a copy of MITRE — it is what this report needs."""
    doc = _render([_finding(rule="sink.sql")])
    taxa = doc["runs"][0]["taxonomies"][0]["taxa"]
    assert [taxon["name"] for taxon in taxa] == ["CWE-89"]


def test_a_rule_with_no_honest_class_gets_none_invented():
    """`pattern.github_actions_workflow` warns that a workflow file is being
    edited. That is a reminder, not a weakness class, and handing it a CWE
    would put a wrong answer in front of a scorer that trusts it."""
    doc = _render([_finding(rule="pattern.github_actions_workflow")])
    run = doc["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert "cwe" not in rule["properties"]
    assert "relationships" not in rule
    assert "taxonomies" not in run


def test_every_mapped_rule_names_a_rule_that_exists():
    """A mapping keyed on a rule nobody emits is a typo that never shows up."""
    from thot.codemap.catalog import active as python_catalog
    from thot.guard.patterns import SECURITY_PATTERNS
    from thot.report.cwe import CWE_BY_RULE
    from thot.taint.js_catalog import active as javascript_catalog

    js = javascript_catalog()
    known = {rule.id for rule in python_catalog().sinks}
    known |= {rule.id for rule in (*js.sinks, *js.assignment_sinks,
                                   js.prototype_sink)}
    known |= {f"pattern.{rule['ruleName']}" for rule in SECURITY_PATTERNS
              if rule.get("ruleName")}
    assert set(CWE_BY_RULE) <= known, sorted(set(CWE_BY_RULE) - known)


def test_a_new_rule_cannot_slip_in_without_a_weakness_class():
    """The complement of the test above, and the one that ages well.

    Adding a rule is easy; remembering that a scorer keys on CWE is not. This
    fails the day someone adds a sink without one, and the fix is either a
    mapping or an explicit line here saying why the rule has no class.
    """
    from thot.codemap.catalog import active as python_catalog
    from thot.guard.patterns import SECURITY_PATTERNS
    from thot.report.cwe import CWE_BY_RULE
    from thot.taint.js_catalog import active as javascript_catalog

    js = javascript_catalog()
    known = {rule.id for rule in python_catalog().sinks}
    known |= {rule.id for rule in (*js.sinks, *js.assignment_sinks,
                                   js.prototype_sink)}
    known |= {f"pattern.{rule['ruleName']}" for rule in SECURITY_PATTERNS
              if rule.get("ruleName")}

    # Editing a workflow file is a reminder, not a weakness class.
    deliberate = {"pattern.github_actions_workflow"}
    assert known - set(CWE_BY_RULE) == deliberate
