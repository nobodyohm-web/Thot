"""Machine-readable report. SARIF export lands in a later milestone."""

from __future__ import annotations

import json

from thot.contracts import Finding, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]


def summarise(findings: list[Finding], hidden: int = 0) -> dict:
    by_severity = {s.value: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity.value] += 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "hidden_below_threshold": hidden,
    }


def render_json(
    findings: list[Finding], manifest, elapsed: float, hidden: int = 0
) -> str:
    payload = {
        "schema_version": 1,
        "scope": {
            "files": len(manifest.files),
            "languages": manifest.languages,
            "entrypoints": list(manifest.entrypoints),
            "test_command": manifest.test_command,
        },
        "summary": summarise(findings, hidden),
        "elapsed_seconds": round(elapsed, 3),
        "findings": [
            {
                "id": f.id,
                "rule": f.rule,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                # `site` travels with the location because it is what makes
                # two findings at one line two findings: `compute_id` folds it
                # in so a verdict on one dangerous call does not speak for the
                # four others in the same body. Without it a consumer sees two
                # identical rows told apart only by an opaque id — and a human
                # reading that sees a duplicate, which looks like a bug in
                # Thot. Measured on Hermes: `sink.js.path` twice at
                # `ui-tui/src/lib/memory.ts:219`, and 362 findings carry one.
                "location": {
                    "path": f.location.path,
                    "line": f.location.line,
                    "symbol": f.location.symbol,
                    **({"site": f.location.site} if f.location.site else {}),
                },
                "taint_path": [
                    {"path": r.path, "line": r.line, "symbol": r.symbol}
                    for r in f.taint_path
                ],
                "failure_scenario": f.failure_scenario,
                **({"jugement": _judgement(f)} if _judgement(f) else {}),
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _judgement(finding: Finding) -> dict:
    """Who argued this, who attacked it, who read the refutation.

    Omitted entirely when no agent ran: a deterministic pass claiming an
    empty judgement would read as "nobody found anything to say", when the
    truth is that nobody was asked. Reads the shared list of stages, so a
    stage added to the cascade appears in every format at once — the JSON
    report knew about two attackers and the others knew about none.
    """
    from thot.report import JUDGEMENT_KEYS

    provenance = finding.provenance or {}
    return {
        key: provenance[key]
        for key, _ in JUDGEMENT_KEYS
        if provenance.get(key)
    }
