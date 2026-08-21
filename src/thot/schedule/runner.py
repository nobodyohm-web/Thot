"""Run a scheduled audit, and report only what is new.

A nightly audit that repeats the same three hundred findings every night gets
filtered to a folder nobody opens. The value of running unattended is entirely
in the diff: what appeared since last time, above a threshold, minus whatever
has already been judged not to matter.
"""

from __future__ import annotations

import sys
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


def roots_for(job) -> list[Path]:
    """The trees this job audits: one directory, or the whole fused program."""
    if getattr(job, "whole_program", False):
        from thot.fusion.audit import parts

        return [root for _, root in parts()]
    return [Path(job.root)]


def _engine_for(job, root: Path):
    """The agent a deep job argues with, or None with the reason on stderr.

    `deep` used to be recorded and never read: the flag existed, the JSON
    said `true`, and the nightly run was a plain deterministic sweep. A job
    that cannot build its engine still runs — a shallow audit beats a
    skipped one — but it says so rather than quietly downgrading.
    """
    if not getattr(job, "deep", False):
        return None
    from thot.engine.factory import NoEngine, build_engine

    try:
        return build_engine(
            root, max_parallel=getattr(job, "parallel", 4)
        )
    except NoEngine as exc:
        print(f"[thot] {job.name} : analyse assistée impossible — {exc}",
              file=sys.stderr)
        return None


def run_job(job, *, store=None, memory=None) -> tuple[list[Finding], int]:
    """Audit what the job targets. Returns (what is new, how many in total)."""
    from thot.pipeline import run_audit
    from thot.plugins import discover, invoke_hook

    fresh: list[Finding] = []
    total = 0

    for root in roots_for(job):
        previous = (
            store.previous_finding_ids(str(root)) if store is not None else set()
        )
        engine = _engine_for(job, root)
        try:
            result = run_audit(
                root,
                store=store,
                require_authorization=False,
                memory=memory,
                engine=engine,
                budget=getattr(job, "budget", 20),
            )
        except Exception as exc:  # one tree must never cost the others
            print(f"[thot] {job.name} : {root} — {exc}", file=sys.stderr)
            continue

        new = new_since_last_run(
            result.findings, previous, Severity(job.threshold)
        )
        total += len(result.findings)
        fresh.extend(new)

        if new:
            invoke_hook(
                discover(root), "post_audit",
                result=result, root=root, new_findings=new,
            )

    return fresh, total
