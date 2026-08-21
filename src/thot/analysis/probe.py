"""Turn deterministic candidates into audited findings.

The deterministic phases answer "could data flow from here to there?". That
question is cheap and exhaustive, and it is not the question an auditor is
paid to answer. This module asks the expensive one — "is it actually
exploitable, and what breaks?" — of only the candidates that earned it.

Two passes, deliberately adversarial. The probe argues the case; the refuter
is then asked to destroy it, with the burden of proof reversed. A finding
survives only if a second, hostile reading of the same code fails to kill it.
That asymmetry is what separates an audit from a linter with opinions.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.engine.base import AgentResult, AgentTask, Engine

# How many candidates a run will spend a model on unless told otherwise.
DEFAULT_LIMIT = 20

# Worst first: a budget spent on the top of the list is a budget well spent.
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

PROBE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "plausible", "refuted"]},
        "scenario": {"type": "string"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
    },
    "required": ["verdict", "scenario", "severity"],
}

REFUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "refuted": {"type": "boolean"},
        "raison": {"type": "string"},
    },
    "required": ["refuted", "raison"],
}


def select_for_analysis(findings: list[Finding], limit: int = DEFAULT_LIMIT) -> list[Finding]:
    """The candidates worth a model, worst first.

    Already-refuted findings are dropped: paying twice to reach the same
    conclusion is the easiest waste to avoid.
    """
    live = [f for f in findings if f.confidence is not Confidence.REFUTED]
    ranked = sorted(live, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return ranked[:limit]


def excerpt(root: Path, ref: CodeRef, radius: int = 12) -> str:
    """The lines around a location, numbered. Empty when unreadable."""
    try:
        lines = (Path(root) / ref.path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, ref.line - radius - 1)
    end = min(len(lines), ref.line + radius)
    return "\n".join(f"{n + 1:5d}  {lines[n]}" for n in range(start, end))


def _path_summary(finding: Finding) -> str:
    if not finding.taint_path:
        return "(chemin non reconstruit)"
    return "\n".join(f"  {i + 1}. {ref}" for i, ref in enumerate(finding.taint_path))


def _probe_task(root: Path, finding: Finding) -> AgentTask:
    context = (
        f"Règle déclenchée : {finding.rule}\n"
        f"Emplacement : {finding.location}\n"
        f"Sévérité calculée (accessibilité × impact) : {finding.severity.value}\n"
        f"Chemin de teinte reconstruit :\n{_path_summary(finding)}\n\n"
        f"Code autour de l'emplacement :\n{excerpt(root, finding.location)}"
    )
    instructions = (
        "Une analyse statique signale ce candidat. Détermine s'il est "
        "réellement exploitable dans ce code, tel qu'il est écrit.\n\n"
        "Un candidat est `confirmed` si tu peux décrire une entrée concrète "
        "qui atteint le point dangereux. Il est `refuted` si une validation, "
        "une constante, un type ou le contexte d'appel l'empêchent. Sinon "
        "`plausible`.\n\n"
        "`scenario` : une ou deux phrases, l'entrée précise et ce qu'elle "
        "provoque. Pas de généralités sur la classe de vulnérabilité.\n\n"
        "Réponds uniquement par un objet JSON : "
        '{"verdict": "...", "scenario": "...", "severity": "..."}'
    )
    return AgentTask(
        id=f"probe:{finding.id}",
        instructions=instructions,
        context=context,
        schema=PROBE_SCHEMA,
        tier="standard",
    )


def _refute_task(root: Path, finding: Finding, scenario: str) -> AgentTask:
    context = (
        f"Emplacement : {finding.location}\n"
        f"Scénario d'exploitation avancé :\n{scenario}\n\n"
        f"Code :\n{excerpt(root, finding.location)}"
    )
    instructions = (
        "Ta tâche est de DÉTRUIRE ce scénario, pas de le confirmer. Cherche "
        "activement ce qui l'invalide : une validation en amont, un appelant "
        "qui ne passe que des constantes, un type qui interdit l'entrée "
        "supposée, une garde, un contexte d'exécution qui rend l'entrée "
        "inatteignable.\n\n"
        "En cas de doute, réfute : un faux positif livré coûte plus cher à "
        "l'auditeur qu'un vrai positif manqué.\n\n"
        "Réponds uniquement par un objet JSON : "
        '{"refuted": true|false, "raison": "..."}'
    )
    return AgentTask(
        id=f"refute:{finding.id}",
        instructions=instructions,
        context=context,
        schema=REFUTE_SCHEMA,
        tier="deep",
    )


def _severity(value: str, fallback: Severity) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return fallback


def _verdict(value: str) -> Confidence:
    try:
        return Confidence(str(value).lower())
    except ValueError:
        return Confidence.PLAUSIBLE


def analyse(
    root: Path,
    findings: list[Finding],
    engine: Engine,
    limit: int = DEFAULT_LIMIT,
) -> list[Finding]:
    """Probe, then refute. Returns every finding, analysed ones replaced."""
    root = Path(root)
    selected = select_for_analysis(findings, limit)
    if not selected:
        return list(findings)

    probes = engine.fan_out([_probe_task(root, f) for f in selected])
    by_id: dict[str, Finding] = {}
    to_refute: list[tuple[Finding, str]] = []

    for finding, result in zip(selected, probes):
        updated = _apply_probe(finding, result, engine)
        by_id[finding.id] = updated
        if updated.confidence is Confidence.CONFIRMED:
            to_refute.append((updated, updated.failure_scenario))

    if to_refute:
        refutations = engine.fan_out(
            [_refute_task(root, f, scenario) for f, scenario in to_refute]
        )
        for (finding, _), result in zip(to_refute, refutations):
            by_id[finding.id] = _apply_refutation(finding, result)

    return [by_id.get(f.id, f) for f in findings]


def _apply_probe(finding: Finding, result: AgentResult, engine: Engine) -> Finding:
    engine_name = engine.capabilities.name
    if not result.ok or not result.data:
        return replace(
            finding,
            provenance={"moteur": engine_name, "erreur": result.error or "réponse vide"},
        )

    data = result.data
    return replace(
        finding,
        confidence=_verdict(data.get("verdict", "")),
        severity=_severity(data.get("severity", ""), finding.severity),
        failure_scenario=str(data.get("scenario") or finding.failure_scenario),
        provenance={"moteur": engine_name, "phase": "sonde"},
    )


def _apply_refutation(finding: Finding, result: AgentResult) -> Finding:
    provenance = dict(finding.provenance or {})
    if not result.ok or not result.data:
        provenance["réfutation"] = result.error or "réponse vide"
        return replace(finding, provenance=provenance)

    provenance["phase"] = "réfutée" if result.data.get("refuted") else "confirmée"
    reason = str(result.data.get("raison") or "")
    if result.data.get("refuted"):
        return replace(
            finding,
            confidence=Confidence.REFUTED,
            failure_scenario=f"{finding.failure_scenario}\n\nRéfuté : {reason}",
            provenance=provenance,
        )
    provenance["contre-argument écarté"] = reason
    return replace(finding, confidence=Confidence.CONFIRMED, provenance=provenance)
