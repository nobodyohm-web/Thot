"""Human-readable report."""

from __future__ import annotations

from thot.contracts import Finding
from thot.report import judgement
from thot.report.json_report import SEVERITY_ORDER, summarise


def render_markdown(
    findings: list[Finding], manifest, elapsed: float, hidden: int = 0,
    judged=None, engine: str | None = None,
) -> str:
    summary = summarise(findings, hidden, judged, engine)
    languages = ", ".join(f"{k} ({v})" for k, v in manifest.languages.items()) or "—"
    lines = [
        "# Rapport d'audit Thot",
        "",
        f"- Fichiers analysés : **{len(manifest.files)}**",
        f"- Langages : {languages}",
        f"- Points d'entrée : **{len(manifest.entrypoints)}**",
        f"- Durée : {elapsed:.2f} s",
        f"- Findings : **{summary['total']}**"
        + (f" _({hidden} masqués sous le seuil)_" if hidden else ""),
        "",
    ]

    # What the pass decided, when something argued. A markdown report is what
    # gets attached to a ticket, and a reader who is not told a panel ran
    # takes it for a raw static scan — the same misreading the terminal note
    # produced until the whole pass was handed to it. Refutations land on INFO
    # by construction, so they are always among the hidden ones.
    argued = {
        key: count for key, count in (summary.get("by_confidence") or {}).items()
        if key != "plausible"
    }
    if engine and argued:
        said = {"refuted": "réfuté", "confirmed": "confirmé",
                "plausible": "plausible"}
        decided = " · ".join(
            f"{count} {said.get(key, key)}(s)" for key, count in sorted(argued.items())
        )
        lines.insert(
            len(lines) - 1,
            f"- Jugé par **{engine}** : {decided}",
        )

    if not findings:
        lines.append("Aucun chemin de teinte détecté sur ce périmètre.")
        lines.append("")
        lines.append(
            "_Analyse déterministe uniquement : l'absence de finding n'est pas une "
            "preuve d'absence de défaut._"
        )
        return "\n".join(lines)

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for finding in sorted(findings, key=lambda f: (order[f.severity], f.location.path)):
        lines.append(f"## `{finding.rule}` — {finding.severity.value.upper()}")
        lines.append("")
        lines.append(f"**Emplacement :** `{finding.location.pinpoint()}`")
        if finding.location.symbol:
            lines.append(f"**Symbole :** `{finding.location.symbol}`")
        lines.append(f"**Confiance :** {finding.confidence.value}")
        stages = judgement(finding)
        if stages:
            lines.append(
                "**Jugement :** "
                + " · ".join(f"{label} {value}" for label, value in stages)
            )
        if finding.failure_scenario:
            lines.append(f"**Scénario :** {finding.failure_scenario}")
        if finding.taint_path:
            lines.append("")
            lines.append("**Chemin :**")
            for step in finding.taint_path:
                suffix = f" — `{step.symbol}`" if step.symbol else ""
                lines.append(f"1. `{step}`{suffix}")
        lines.append("")

    return "\n".join(lines)
