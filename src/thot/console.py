"""Terminal rendering. The only module in Thot allowed to print a report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from thot.contracts import Severity

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
    table.add_column("Emplacement")
    table.add_column("Symbole", overflow="fold")

    rank = {severity: index for index, severity in enumerate(_ORDER)}
    for finding in sorted(
        result.findings, key=lambda f: (rank[f.severity], f.location.path)
    ):
        table.add_row(
            f"[{_STYLE[finding.severity]}]{finding.severity.value.upper()}[/]",
            finding.rule,
            str(finding.location),
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
    console.print(
        "[dim]Chaque finding est PLAUSIBLE : détecté par analyse statique, pas "
        "encore prouvé par exécution.[/dim]"
    )


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
