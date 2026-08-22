"""Known-vulnerable dependencies, as findings like any other.

The point of producing `Finding` objects rather than a separate report:
everything Thot already does then applies. Verdict memory can dismiss a
dependency finding, the scheduler reports only new ones, the gateway
pushes them, `--fail-on` gates CI on them.

And the identity trick pays off exactly here. A finding's id hashes the
rule, path, symbol and `ast_hash`; for a dependency, `ast_hash` is the
pinned version and the advisory id. Bump the version and the id changes,
so a dismissal cannot silently outlive the version it was about — the
same guarantee taint findings get from the AST of the accused function.

Calibration, stated rather than assumed: an advisory matching an exact
pinned version is a fact from a database, so it is not a guess. But
whether your code ever reaches the vulnerable function is *not* analysed
here, so these stay PLAUSIBLE. Malware advisories are the exception —
`MAL-*` means the package itself is the payload, and reachability is not
the question.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.supply.discover import Component, discover
from thot.supply.osv import Advisory, OsvClient

SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # Reported, but never blocking on its own: an advisory nobody has rated
    # is still worth reading and is not evidence of impact.
    "UNKNOWN": Severity.LOW,
}


@dataclass(frozen=True)
class SupplyResult:
    findings: list[Finding]
    components: int
    checked: bool           # whether the lookup actually happened
    error: str = ""
    # Directories `.thotignore` put out of scope that hold dependencies of
    # their own. Often deliberate — on the shipped tree `hermes/` and `prime/`
    # are audited separately — but never something to leave unsaid: a scope
    # that stays quiet reads as a whole scope.
    skipped: tuple[str, ...] = ()

    def _aside(self) -> str:
        if not self.skipped:
            return ""
        return (f"\n{len(self.skipped)} dossier(s) hors périmètre, avec leurs "
                f"propres dépendances : {', '.join(self.skipped)} — "
                f"`thot deps {self.skipped[0]}` pour les auditer.")

    def summary(self) -> str:
        if not self.checked:
            return (f"{self.components} dépendance(s) — non vérifiées : "
                    f"{self.error}") + self._aside()
        if not self.findings:
            return (f"{self.components} dépendance(s), aucune vulnérabilité "
                    f"connue.") + self._aside()
        return (f"{self.components} dépendance(s), {len(self.findings)} "
                f"vulnérable(s).") + self._aside()


def _finding(component: Component, advisory: Advisory) -> Finding:
    severity = (Severity.CRITICAL if advisory.malware
                else SEVERITY.get(advisory.severity, Severity.LOW))

    if advisory.malware:
        scenario = (
            f"{advisory.id} — ce paquet est signalé comme MALVEILLANT en "
            f"version {component.version}. Le paquet est la charge utile ; "
            f"il n'y a pas de question d'atteignabilité. "
            f"{advisory.summary}".strip()
        )
    else:
        fix = (f" Corrigé en {', '.join(advisory.fixed)}."
               if advisory.fixed else " Aucune version corrigée publiée.")
        scenario = (
            f"{advisory.id} — {component.label()} est couvert par cet avis. "
            f"{advisory.summary}{fix} "
            f"Atteignabilité depuis ce dépôt non analysée."
        ).strip()

    location = CodeRef(
        path=component.source,
        line=component.line,
        symbol=component.name,
        # The version *and* the advisory: two advisories on one package are
        # two findings, and a version bump expires both.
        ast_hash=f"{component.version}|{advisory.id}",
    )
    rule = f"supply.{component.ecosystem.lower()}"
    return Finding(
        id=Finding.compute_id(rule, location),
        rule=rule,
        severity=severity,
        confidence=Confidence.CONFIRMED if advisory.malware
        else Confidence.PLAUSIBLE,
        location=location,
        failure_scenario=scenario,
        provenance={"avis": advisory.id, "source": "osv.dev",
                    "paquet": component.label()},
    )


def audit_dependencies(root: Path | str, *,
                       client: OsvClient | None = None) -> SupplyResult:
    """Look up every pinned dependency of this repository against OSV."""
    from thot.supply.discover import skipped_manifest_dirs

    components = discover(root)
    aside = skipped_manifest_dirs(root)
    if not components:
        return SupplyResult([], 0, checked=True, skipped=aside)

    owned = client is None
    client = client or OsvClient()
    try:
        hits = client.query(components)
        if not hits and client.last_error:
            return SupplyResult([], len(components), checked=False,
                                error=client.last_error, skipped=aside)

        every_id = [i for ids in hits.values() for i in ids]
        advisories = client.details(every_id)

        findings = [
            _finding(component, advisories.get(identifier, Advisory(id=identifier)))
            for component, ids in hits.items()
            for identifier in ids
        ]
    finally:
        if owned:
            client.close()

    findings.sort(key=lambda f: (-_rank(f.severity), f.location.symbol))
    return SupplyResult(findings, len(components), checked=True, skipped=aside)


_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
          Severity.CRITICAL)


def _rank(severity: Severity) -> int:
    return _ORDER.index(severity)
