"""Human-readable report."""

from __future__ import annotations

from thot.contracts import Finding
from thot.report.json_report import SEVERITY_ORDER, summarise


def render_markdown(
    findings: list[Finding], manifest, elapsed: float, hidden: int = 0
) -> str:
    summary = summarise(findings, hidden)
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
        lines.append(f"**Emplacement :** `{finding.location}`")
        if finding.location.symbol:
            lines.append(f"**Symbole :** `{finding.location.symbol}`")
        lines.append(f"**Confiance :** {finding.confidence.value}")
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
