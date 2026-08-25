"""SARIF 2.1.0 — the format the rest of the industry already reads.

A report nobody's pipeline can ingest lives in one terminal. GitHub code
scanning, GitLab, Azure DevOps and the editors all speak this, and two of
Thot's own properties matter more here than in any other renderer.

A finding's identity is rule + file + symbol + body hash, never the line —
which is exactly what `partialFingerprints` is for. A dashboard fed line
numbers reopens every finding the moment somebody adds an import at the top
of a file; fed this, it does not.

And a taint path is a sequence of locations, which is exactly what a code
flow renders: the reader clicks from the source to the sink instead of
taking the tool's word for it. A finding with no path carries no `codeFlows`
key at all — an empty one renders as a taint path with no steps, which reads
as a broken analysis rather than as a pattern match.
"""

from __future__ import annotations

import json

from thot.contracts import Confidence, Finding, Severity
from thot.report.cwe import cwe_tags, cwes, number

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
HOMEPAGE = "https://github.com/thot-audit/thot"

# SARIF has three levels and Thot has five. Critical and high are both
# `error`: a gate that trips on one has to trip on the other, and a scanning
# service ranks within a level by `security-severity` below.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# What GitHub actually ranks by. `level` decides whether a finding is an
# alert; this decides where it sits among them, on the CVSS 0–10 scale the
# service expects. Without it every alert lands in one bucket.
_SCORE = {
    Severity.CRITICAL: "9.3",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.1",
    Severity.INFO: "1.0",
}


CWE_TAXONOMY = "CWE"
# Stable across runs: a viewer keys the taxonomy component on this guid,
# and a fresh one each run would read as a different taxonomy every time.
CWE_GUID = "b1a2c3d4-0000-4000-8000-000000000cwe".replace("cwe", "c3e")


def _describe(rule_id: str) -> str:
    """One line for a rule, from whichever catalogue defines it."""
    from thot.codemap.catalog import active as python_catalog
    from thot.taint.js_catalog import active as javascript_catalog

    for rule in python_catalog().sinks:
        if rule.id == rule_id:
            return rule.description
    js = javascript_catalog()
    for rule in (*js.sinks, *js.assignment_sinks, js.prototype_sink):
        if rule.id == rule_id:
            return rule.description
    if rule_id.startswith("pattern."):
        from thot.guard.patterns import SECURITY_PATTERNS

        wanted = rule_id[len("pattern."):]
        for rule in SECURITY_PATTERNS:
            if rule.get("ruleName") == wanted:
                first = str(rule.get("reminder", "")).strip().splitlines()
                if first:
                    return first[0].lstrip("⚠️ ").strip()
    return rule_id


def _location(ref) -> dict:
    region: dict = {"startLine": max(1, int(ref.line or 1))}
    # A bare relative URI and no `uriBaseId`. That is what a scanning
    # service resolves against the checkout it already has, and it is the one
    # form that cannot leak `/Users/dev` into a document meant to be shared.
    physical = {"artifactLocation": {"uri": ref.path}, "region": region}
    return {"physicalLocation": physical}


def _rule(rule_id: str, severity: Severity) -> dict:
    """One rule descriptor, carrying the weakness class it belongs to.

    The CWE is emitted three ways because three kinds of consumer read three
    different fields: `properties.cwe` for a benchmark scorer, the
    `external/cwe/cwe-089` tag for GitHub code scanning, and `relationships`
    for a SARIF viewer that resolves the taxonomy properly. They are one
    mapping rendered three times, never three mappings.
    """
    text = _describe(rule_id)
    identifiers = cwes(rule_id)
    properties: dict = {
        "security-severity": _SCORE[severity],
        "tags": ["security", rule_id.split(".")[0], *cwe_tags(rule_id)],
    }
    if identifiers:
        properties["cwe"] = list(identifiers)
    rule: dict = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": text},
        "fullDescription": {"text": text},
        "defaultConfiguration": {"level": _LEVEL[severity]},
        "properties": properties,
        "helpUri": HOMEPAGE,
    }
    if identifiers:
        rule["relationships"] = [{
            "target": {
                "id": str(number(identifier)),
                "toolComponent": {"name": CWE_TAXONOMY, "guid": CWE_GUID},
            },
            "kinds": ["superset"],
        } for identifier in identifiers]
    return rule


def _taxonomy(rule_ids) -> dict | None:
    """The CWE component, listing only the classes this run actually used.

    A `relationships` target that resolves to nothing is a dangling
    reference: a strict reader rejects the document, a lenient one drops the
    mapping without a word, and the second failure is the one that would go
    unnoticed until a scorer reported zero.
    """
    used = sorted({identifier for rule_id in rule_ids
                   for identifier in cwes(rule_id)}, key=number)
    if not used:
        return None
    return {
        "name": CWE_TAXONOMY,
        "guid": CWE_GUID,
        "organization": "MITRE",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
        "isComprehensive": False,
        "taxa": [{"id": str(number(identifier)),
                  "name": identifier,
                  "shortDescription": {"text": identifier}} for identifier in used],
    }


def render_sarif(findings: list[Finding], manifest, elapsed: float,
                 hidden: int = 0, judged=None, engine: str = "") -> str:
    from thot import __version__

    rules: list[dict] = []
    index_of: dict[str, int] = {}
    results: list[dict] = []

    for finding in findings:
        if finding.rule not in index_of:
            index_of[finding.rule] = len(rules)
            rules.append(_rule(finding.rule, finding.severity))

        properties: dict = {"confidence": finding.confidence.value}
        for key, value in (finding.provenance or {}).items():
            properties[key] = value
        if finding.location.site:
            properties["site"] = finding.location.site

        result: dict = {
            "ruleId": finding.rule,
            "ruleIndex": index_of[finding.rule],
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.failure_scenario or finding.rule},
            "locations": [_location(finding.location)],
            # Prefixed and versioned: a fingerprint scheme that changes
            # without saying so silently reopens every alert it ever filed.
            "partialFingerprints": {"thotFindingId/v1": finding.id},
            "properties": properties,
        }
        if finding.taint_path:
            result["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [
                        {"location": _location(ref)} for ref in finding.taint_path
                    ]
                }]
            }]
        if finding.confidence is Confidence.REFUTED:
            # Kept and marked rather than dropped. A dashboard that never
            # sees it cannot tell "nobody looked" from "somebody looked and
            # decided", and the second is the whole point of the panel.
            result["suppressions"] = [{
                "kind": "external",
                "justification": "réfuté par le panel — voir `thot verdicts`",
            }]
        results.append(result)

    run: dict = {
        "tool": {"driver": {
            "name": "Thot",
            "version": __version__,
            "informationUri": HOMEPAGE,
            "rules": rules,
        }},
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "properties": {
                "elapsed_seconds": round(elapsed, 3),
                "files_scanned": len(manifest.files),
                "hidden_below_threshold": hidden,
                **({"engine": engine} if engine else {}),
            },
        }],
    }
    taxonomy = _taxonomy(index_of)
    if taxonomy is not None:
        run["taxonomies"] = [taxonomy]
    return json.dumps({"$schema": SCHEMA, "version": VERSION, "runs": [run]},
                      indent=2, ensure_ascii=False)
