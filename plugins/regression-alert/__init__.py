"""Make a regression look like a regression.

Verdict memory already knows: a finding whose stored decision was `fixed`
and which is back gets `provenance["régression"] = True`. Knowing it in a
dictionary nobody reads is not the same as saying it, so this raises the
severity to the top and writes the fact into the scenario, where it lands
in the report and in the session log.
"""

from __future__ import annotations

from dataclasses import replace

from thot.contracts import Severity

MARK = "RÉGRESSION"


def on_finding(*, finding=None, **_: object):
    """Return an annotated copy, or None to leave the finding alone."""
    if finding is None:
        return None
    provenance = finding.provenance or {}
    if not provenance.get("régression"):
        return None
    if MARK in (finding.failure_scenario or ""):
        return None  # already annotated: hooks must be idempotent

    decided = provenance.get("décidé le", "")
    when = f" (corrigé le {decided[:10]})" if decided else ""
    scenario = (
        f"{MARK} — ce défaut avait été marqué corrigé{when} et il est de "
        f"retour.\n{finding.failure_scenario or ''}"
    ).strip()
    return replace(finding, severity=Severity.CRITICAL, failure_scenario=scenario)
