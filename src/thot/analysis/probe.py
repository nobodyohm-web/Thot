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

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.engine.base import AgentResult, AgentTask, Engine
from thot.memory.base import carries_decision

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


def select_for_analysis(
    findings: list[Finding],
    limit: int = DEFAULT_LIMIT,
    skip: set[str] | None = None,
) -> list[Finding]:
    """The candidates worth a model, worst first.

    `skip` is for a caller running several rounds against the same tree. A
    confirmed finding is deliberately never written to memory — it must keep
    showing up until someone fixes it — which means without `skip` a second
    round would spend its whole budget re-arguing what the first round just
    confirmed, and never reach anything new.

    Anything already decided is dropped. Refuted, because paying twice to
    reach the same conclusion is the easiest waste to avoid — and accepted or
    fixed for a harder reason: the probe replaces confidence, severity,
    scenario and provenance wholesale, so re-arguing a decided finding does
    not merely cost money, it overwrites the decision and erases who took it.
    A regression is the one thing a deep pass must never be allowed to
    silence: it has already been judged real once.
    """
    skip = skip or set()
    live = [
        f
        for f in findings
        if f.confidence is not Confidence.REFUTED
        and not carries_decision(f)
        and f.id not in skip
    ]
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


def _refute_task(
    root: Path, finding: Finding, scenario: str, *, again: bool = False
) -> AgentTask:
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
    if again:
        # It survived one attacker. Saying so is not a hint to agree: an
        # attacker told nothing would rehearse the first attack's angles,
        # and the value of a second attacker is entirely in the angles the
        # first one missed.
        instructions = (
            "Ce scénario a déjà résisté à une tentative de réfutation par un "
            "autre agent. Cherche ce que cette première attaque a manqué, pas "
            "ce qu'elle a déjà couvert.\n\n" + instructions
        )
    return AgentTask(
        id=f"refute2:{finding.id}" if again else f"refute:{finding.id}",
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
    on_decided: Callable[[Finding], None] | None = None,
    skip: set[str] | None = None,
) -> list[Finding]:
    """Probe, attack, and attack again what survived — in batches.

    Three phases rather than two, and the third is the point of running more
    than one agent. A finding that survives its attacker is the one that will
    be reported to a human, so it is the one worth spending a second,
    independent attacker on — a different agent, which has seen neither the
    argument being built nor the first attack being written.

    The escalation is deliberately one-sided. A refutation is never
    re-examined: the prompt tells the attacker to refute when in doubt, so a
    refutation is already the cautious answer and re-litigating it would
    manufacture false positives. Only survivors climb.

    Batched because these runs are long. Three hundred candidates on a large
    repository is hours of wall clock, and `fan_out` only returns once every
    task in it has finished — so a single pass over the whole selection meant
    an interruption at minute 90 threw away all ninety minutes. A batch is
    decided, persisted through `on_decided`, and only then is the next one
    started: what an interruption costs is one batch, not the run.
    """
    root = Path(root)
    selected = select_for_analysis(findings, limit, skip)
    if not selected:
        return list(findings)

    by_id: dict[str, Finding] = {}
    size = _batch_size(engine)
    for start in range(0, len(selected), size):
        _analyse_batch(root, selected[start : start + size], engine, by_id,
                       on_decided)

    return [by_id.get(f.id, f) for f in findings]


def _batch_size(engine: Engine) -> int:
    """As wide as the engine can run at once, and no wider.

    Wider would buy nothing — the extra tasks would queue anyway — and would
    widen exactly what an interruption destroys.
    """
    return max(1, engine.capabilities.max_parallel)


def _analyse_batch(
    root: Path,
    batch: list[Finding],
    engine: Engine,
    by_id: dict[str, Finding],
    on_decided: Callable[[Finding], None] | None,
) -> None:
    """One batch through all three phases. Every finding leaves it settled."""

    def settle(finding: Finding) -> None:
        by_id[finding.id] = finding
        if on_decided is not None:
            on_decided(finding)

    probes = engine.fan_out([_probe_task(root, f) for f in batch])
    to_refute: list[tuple[Finding, str]] = []

    for finding, result in zip(batch, probes):
        updated = _apply_probe(finding, result, engine)
        by_id[finding.id] = updated
        if updated.confidence is Confidence.CONFIRMED:
            to_refute.append((updated, updated.failure_scenario))
        else:
            settle(updated)

    survivors: list[tuple[Finding, str]] = []
    if to_refute:
        refutations = engine.fan_out(
            [_refute_task(root, f, scenario) for f, scenario in to_refute]
        )
        for (finding, scenario), result in zip(to_refute, refutations):
            attacked = _apply_refutation(finding, result, engine)
            by_id[finding.id] = attacked
            if attacked.confidence is Confidence.CONFIRMED:
                survivors.append((attacked, scenario))
            else:
                settle(attacked)

    # The cascade. Skipped when the panel has no third voice: an agent that
    # already argued or already attacked this finding would be reviewing its
    # own work, which is the failure this whole arrangement exists to avoid.
    if survivors and _can_escalate(engine):
        second = engine.fan_out(
            [_refute_task(root, f, scenario, again=True)
             for f, scenario in survivors]
        )
        for (finding, _), result in zip(survivors, second):
            settle(_apply_refutation(finding, result, engine, again=True))
    else:
        for finding, _ in survivors:
            settle(finding)


def _can_escalate(engine: Engine) -> bool:
    """Whether a third, untainted agent exists to attack the survivors."""
    return len(getattr(engine, "names", ())) >= 3


def _attribute(engine: Engine, task_id: str) -> str:
    """Which backend actually answered this task.

    A panel routes each task to one of its members, so asking it for its own
    name would file every finding under "panel" and lose the one fact worth
    keeping: who argued, and who attacked.
    """
    who = getattr(engine, "who", None)
    if callable(who):
        return str(who(task_id) or engine.capabilities.name)
    return engine.capabilities.name


def _apply_probe(finding: Finding, result: AgentResult, engine: Engine) -> Finding:
    engine_name = _attribute(engine, result.task_id)
    # Merged, not replaced: what got the finding here — which rule fired,
    # which catalogue it came from — is not the probe's to throw away.
    provenance = dict(finding.provenance or {})
    provenance["moteur"] = engine_name

    if not result.ok or not result.data:
        provenance["erreur"] = result.error or "réponse vide"
        return replace(finding, provenance=provenance)

    data = result.data
    provenance["phase"] = "sonde"
    confidence = _verdict(data.get("verdict", ""))
    # A probe can refute outright, without the second pass. When it does, the
    # answer is the same answer, so it must carry the same weight: refuted
    # confidence scores zero, and severity is impact × reach × confidence.
    severity = (
        Severity.INFO
        if confidence is Confidence.REFUTED
        else _severity(data.get("severity", ""), finding.severity)
    )
    return replace(
        finding,
        confidence=confidence,
        severity=severity,
        failure_scenario=str(data.get("scenario") or finding.failure_scenario),
        provenance=provenance,
    )


def _apply_refutation(
    finding: Finding, result: AgentResult, engine: Engine, *, again: bool = False
) -> Finding:
    provenance = dict(finding.provenance or {})
    # Named separately from `moteur`: on a panel these are two different
    # agents, and "who tried to destroy this and failed" is the sentence
    # that makes a confirmation worth trusting. The second attacker gets its
    # own key so a survivor can name both, and so nothing overwrites the
    # record of who already tried.
    key = "second contradicteur" if again else "contradicteur"
    provenance[key] = _attribute(engine, result.task_id)
    if not result.ok or not result.data:
        provenance["réfutation"] = result.error or "réponse vide"
        return replace(finding, provenance=provenance)

    survived = "confirmée (2 attaques)" if again else "confirmée"
    provenance["phase"] = "réfutée" if result.data.get("refuted") else survived
    reason = str(result.data.get("raison") or "")
    if result.data.get("refuted"):
        # Severity is impact × reach × confidence, and refuted confidence
        # scores zero. Leaving it where the probe put it made a refutation
        # reached this run rank above one remembered from last week, for the
        # same finding and the same reason.
        return replace(
            finding,
            confidence=Confidence.REFUTED,
            severity=Severity.INFO,
            failure_scenario=f"{finding.failure_scenario}\n\nRéfuté : {reason}",
            provenance=provenance,
        )
    provenance["contre-argument écarté"] = reason
    return replace(finding, confidence=Confidence.CONFIRMED, provenance=provenance)
