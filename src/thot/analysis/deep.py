"""One deep pass, for every caller that runs one.

There are two: `run_audit` and the interactive session. They were written
apart and drifted apart, four times in one day — the tripwire landed on one,
the failure ledger on one, the demotion of walled candidates on one. Every
time, nothing failed: the two simply stopped doing the same thing, and the
comment claiming they did the same thing stayed where it was.

So the pass lives here and both call it. What a caller keeps is what is
genuinely its own: how to show progress, and what to do with the result.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class DeepResult:
    findings: list
    # Files the pass itself changed. Empty is the normal answer, and the only
    # one worth trusting: two of the three agents can write.
    touched: tuple[str, ...] = ()
    engine: str = ""


def run_deep_pass(
    root: Path,
    findings: list,
    engine,
    *,
    files,
    memory=None,
    limit: int,
    skip: set[str] | None = None,
    on_decided: Callable | None = None,
) -> DeepResult:
    """Argue, attack, escalate — and leave the ledger and the tripwire right.

    Everything a deep pass owes whoever called it, in one place: verdicts
    written as they land, failures counted rather than remembered, walled
    candidates pushed back, and proof that the code was not touched.
    """
    from thot.analysis import attempts, tripwire
    from thot.analysis.probe import analyse
    from thot.memory.base import record_verdicts

    root = Path(root)
    engine_name = engine.capabilities.name
    before = tripwire.snapshot(root, files)

    def settled(finding) -> None:
        if memory is not None:
            record_verdicts([finding], memory, author=engine_name)
        provenance = finding.provenance or {}
        if provenance.get("erreur") or provenance.get("réfutation"):
            attempts.record_failure(finding.id)
        else:
            attempts.clear(finding.id)
        if on_decided is not None:
            on_decided(finding)

    judged = analyse(
        root, findings, engine,
        limit=limit, on_decided=settled, skip=skip, demote=attempts.demoted(),
    )
    touched = tripwire.touched(before, tripwire.snapshot(root, files))
    return DeepResult(findings=judged, touched=touched, engine=engine_name)
