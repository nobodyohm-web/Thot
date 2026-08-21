"""Run a scheduled audit, and report only what is new.

A nightly audit that repeats the same three hundred findings every night gets
filtered to a folder nobody opens. The value of running unattended is entirely
in the diff: what appeared since last time, above a threshold, minus whatever
has already been judged not to matter.
"""

from __future__ import annotations

from pathlib import Path

from thot.contracts import Confidence, Finding, Severity

_RANK = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def new_since_last_run(
    findings: list[Finding],
    previous_ids: set[str],
    threshold: Severity = Severity.MEDIUM,
) -> list[Finding]:
    """What deserves waking someone up for.

    Refuted findings are never news, whether a human dismissed them or an
    adversarial pass killed them — that is the entire point of remembering.
    """
    floor = _RANK.index(threshold)
    return [
        finding
        for finding in findings
        if finding.id not in previous_ids
        and finding.confidence is not Confidence.REFUTED
        and _RANK.index(finding.severity) >= floor
    ]


def run_job(job, *, store=None, memory=None) -> tuple[list[Finding], int]:
    """Audit one repository. Returns (what is new, how many findings in total)."""
    from thot.pipeline import run_audit
    from thot.plugins import discover, invoke_hook

    root = Path(job.root)
    previous = store.previous_finding_ids(str(root)) if store is not None else set()

    result = run_audit(
        root, store=store, require_authorization=False, memory=memory
    )
    fresh = new_since_last_run(
        result.findings, previous, Severity(job.threshold)
    )

    if fresh:
        invoke_hook(
            discover(root), "post_audit", result=result, root=root, new_findings=fresh
        )
    return fresh, len(result.findings)
