"""Terminal rendering. The only module in Thot allowed to print a report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from thot.contracts import Confidence, Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]

console = Console()


def print_report(result, hidden: int = 0) -> None:
    """Render an AuditResult as a terminal report."""
    console.print()
    console.rule("[bold]Thot — rapport d'audit")

    languages = " · ".join(
        f"{name} {count}" for name, count in result.manifest.languages.items()
    )
    console.print(
        f"[dim]{len(result.manifest.files)} fichiers"
        + (f" ({languages})" if languages else "")
        + f" · {len(result.manifest.entrypoints)} points d'entrée"
        + f" · {result.elapsed:.2f} s[/dim]"
    )
    shallow = _pattern_only(result.manifest.languages)
    if shallow:
        console.print(f"[dim]{shallow}[/dim]")
    console.print()

    if not result.findings:
        if hidden:
            console.print(
                f"[green]Aucun finding au-dessus du seuil.[/green] "
                f"[dim]({hidden} sous le seuil — `--all` pour les voir)[/dim]"
            )
            return
        console.print("[green]Aucun chemin de teinte détecté.[/green]")
        console.print(
            "[dim]Analyse déterministe uniquement — l'absence de finding n'est "
            "pas une preuve d'absence de défaut.[/dim]"
        )
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Sévérité", no_wrap=True)
    table.add_column("Règle", no_wrap=True)
    # Folded, not ellipsised. Rich truncates by default, and this column was
    # the only one left at that default — so `packages/coding-agent/src/tools/
    # terminal/session-runner.ts:412` printed as `packages/codi…` while the
    # symbol beside it wrapped in full. The one field a reader needs in order
    # to open the file was the one being cut.
    table.add_column("Emplacement", overflow="fold")
    table.add_column("Symbole", overflow="fold")

    rank = {severity: index for index, severity in enumerate(_ORDER)}
    for finding in sorted(
        result.findings, key=lambda f: (rank[f.severity], f.location.path)
    ):
        table.add_row(
            f"[{_STYLE[finding.severity]}]{finding.severity.value.upper()}[/]",
            finding.rule,
            finding.location.pinpoint(),
            finding.location.symbol or "—",
        )

    console.print(table)
    console.print()

    counts = {severity: 0 for severity in _ORDER}
    for finding in result.findings:
        counts[finding.severity] += 1
    breakdown = " · ".join(
        f"[{_STYLE[s]}]{counts[s]} {s.value}[/]" for s in _ORDER if counts[s]
    )
    suffix = (
        f" [dim]· {hidden} masqués sous le seuil (`--all`)[/dim]" if hidden else ""
    )
    console.print(
        f"[bold]{len(result.findings)}[/bold] finding(s) — {breakdown}{suffix}"
    )
    console.print(_confidence_note(result.findings))
    panel = _panel_note(result.findings)
    if panel:
        console.print(panel)


def _panel_note(findings) -> str:
    """Who argued, and who tried to destroy the argument.

    Without this the report of a panel run is indistinguishable from the
    report of a single agent, which is the whole difference the panel buys.
    Silent when nothing was argued: a deterministic run has no judges.
    """
    from collections import Counter

    # Every stage, not just the first two. The escalation is the step the
    # panel exists for, and a summary that stopped at the first attacker
    # made the third agent's work — the one that decides whether a finding
    # is reported at all — invisible.
    stages = (
        ("moteur", "Argumenté par {}"),
        ("contradicteur", "attaqué par {}"),
        ("second contradicteur", "puis par {}"),
        ("relecture", "réfutation relue par {}"),
    )

    counts: dict[str, Counter] = {key: Counter() for key, _ in stages}
    for finding in findings:
        provenance = finding.provenance or {}
        for key, _ in stages:
            who = provenance.get(key)
            if who:
                counts[key][who] += 1

    if not counts["moteur"]:
        return ""

    def tally(counter) -> str:
        return " · ".join(f"{name} {count}" for name, count in counter.most_common())

    parts = [
        shape.format(tally(counts[key]))
        for key, shape in stages if counts[key]
    ]
    return "[dim]" + " — ".join(parts) + "[/dim]"


def _pattern_only(languages: dict) -> str:
    """Name the languages that got the pattern rules and nothing else.

    Thot indexes Python: AST, call graph, taint, reachability. Everything
    else in scope is scanned by the pattern rules, which is a real analysis
    but a shallower one. Printing a file count without that distinction let
    a reader assume 912 TypeScript files had been analysed the same way as
    23 Python ones.
    """
    from thot.codemap import (
        DEEP_TAINT_LANGUAGES,
        INDEXED_LANGUAGES,
        TAINTED_LANGUAGES,
    )

    def named(subset: dict) -> str:
        return " · ".join(f"{n} {c}" for n, c in sorted(subset.items()))

    blind = {
        name: count for name, count in languages.items()
        if name not in INDEXED_LANGUAGES and count
    }
    shallow = {
        name: count for name, count in languages.items()
        if name in TAINTED_LANGUAGES
        and name not in DEEP_TAINT_LANGUAGES and count
    }
    mapped = {
        name: count for name, count in languages.items()
        if name in INDEXED_LANGUAGES and name not in TAINTED_LANGUAGES and count
    }

    lines = []
    if shallow:
        lines.append(
            f"teinte au fichier près, pas au-delà : {named(shallow)}"
        )
    if mapped:
        lines.append(
            f"indexés et cartographiés, sans moteur de teinte : {named(mapped)}"
        )
    if blind:
        lines.append(f"motifs seuls, sans index ni graphe : {named(blind)}")
    return "\n".join(lines)


def _confidence_note(findings) -> str:
    """Say what the findings actually are.

    This line is the last thing a reader sees, so it outranks the table above
    it. Printing "everything here is plausible" unconditionally was true when
    Thot only ran static analysis; after `--deep`, or after a single
    remembered verdict, it told the reader the opposite of what had happened —
    and buried minutes of argued analysis under a disclaimer.
    """
    confirmed = sum(1 for f in findings if f.confidence is Confidence.CONFIRMED)
    refuted = sum(1 for f in findings if f.confidence is Confidence.REFUTED)
    plausible = len(findings) - confirmed - refuted

    if not confirmed and not refuted:
        return (
            "[dim]Chaque finding est PLAUSIBLE : détecté par analyse statique, "
            "pas encore prouvé par exécution.[/dim]"
        )

    parts = []
    if confirmed:
        parts.append(f"[{_STYLE[Severity.HIGH]}]{confirmed} confirmé(s)[/]")
    if refuted:
        parts.append(f"[dim]{refuted} réfuté(s)[/dim]")
    if plausible:
        parts.append(f"[dim]{plausible} plausible(s)[/dim]")
    tail = (
        " [dim]— un plausible est détecté par analyse statique, pas encore "
        "prouvé.[/dim]"
        if plausible
        else ""
    )
    return " · ".join(parts) + tail


def print_paths(result) -> None:
    """Print the full taint path of every finding, deepest severity first."""
    rank = {severity: index for index, severity in enumerate(_ORDER)}
    for finding in sorted(
        result.findings, key=lambda f: (rank[f.severity], f.location.path)
    ):
        console.print()
        console.print(
            f"[{_STYLE[finding.severity]}]{finding.severity.value.upper()}[/] "
            f"[bold]{finding.rule}[/bold]"
        )
        for index, step in enumerate(finding.taint_path):
            arrow = "  " if index == 0 else "  ↓ "
            symbol = f" [dim]{step.symbol}[/dim]" if step.symbol else ""
            console.print(f"{arrow}{step}{symbol}")
