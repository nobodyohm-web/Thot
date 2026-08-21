"""Machine-readable report. SARIF export lands in a later milestone."""

from __future__ import annotations

import json

from thot.contracts import Finding, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]


def summarise(findings: list[Finding]) -> dict:
    by_severity = {s.value: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity.value] += 1
    return {"total": len(findings), "by_severity": by_severity}


def render_json(findings: list[Finding], manifest, elapsed: float) -> str:
    payload = {
        "schema_version": 1,
        "scope": {
            "files": len(manifest.files),
            "languages": manifest.languages,
            "entrypoints": list(manifest.entrypoints),
            "test_command": manifest.test_command,
        },
        "summary": summarise(findings),
        "elapsed_seconds": round(elapsed, 3),
        "findings": [
            {
                "id": f.id,
                "rule": f.rule,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "location": {
                    "path": f.location.path,
                    "line": f.location.line,
                    "symbol": f.location.symbol,
                },
                "taint_path": [
                    {"path": r.path, "line": r.line, "symbol": r.symbol}
                    for r in f.taint_path
                ],
                "failure_scenario": f.failure_scenario,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
