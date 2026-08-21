"""The opening sweep: what is here, before anyone types anything.

This is Thot's edge. A conversational agent discovers a repository by opening
files with the model — slow, partial, and paid for by the token, every session.
Thot computes the same picture from ASTs and a call graph: complete, instant,
free. The model starts the conversation already knowing the terrain.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from thot.codemap.graph import CodeGraph
from thot.codemap.index import index_files
from thot.contracts import Finding, Symbol
from thot.scope.detect import detect_scope
from thot.scope.manifest import ScopeManifest


@dataclass
class Recon:
    """Everything known about a directory before the first prompt."""

    root: Path
    manifest: ScopeManifest
    symbols: list[Symbol] = field(default_factory=list)
    graph: CodeGraph | None = None
    findings: list[Finding] = field(default_factory=list)
    branch: str | None = None
    dirty: bool = False
    elapsed: float = 0.0

    @property
    def is_empty(self) -> bool:
        return not self.manifest.files

    @property
    def file_count(self) -> int:
        return len(self.manifest.files)


def _git_state(root: Path) -> tuple[str | None, bool]:
    def run(*args: str) -> str:
        try:
            done = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return done.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    branch = run("rev-parse", "--abbrev-ref", "HEAD") or None
    dirty = bool(run("status", "--porcelain"))
    return branch, dirty


def sweep(root: Path, *, deep: bool = True) -> Recon:
    """Scan a directory. `deep=False` skips taint analysis on huge trees."""
    import time

    root = Path(root).resolve()
    started = time.monotonic()

    manifest = detect_scope(root)
    recon = Recon(root=root, manifest=manifest)
    recon.branch, recon.dirty = _git_state(root)

    if not manifest.files:
        recon.elapsed = time.monotonic() - started
        return recon

    symbols: list[Symbol] = index_files(root, manifest.files)
    recon.symbols = symbols
    recon.graph = CodeGraph.build(symbols, manifest.entrypoints)

    if deep and symbols:
        from thot.pipeline import findings_from_graph

        recon.findings = findings_from_graph(root, recon.graph)

    if deep:
        # Same analysis the CLI runs, so /audit and `thot audit` never disagree.
        from thot.guard.scanner import sweep_patterns

        recon.findings += sweep_patterns(root, list(manifest.files))
        recon.findings = _remember(recon.findings, root)

    recon.elapsed = time.monotonic() - started
    return recon


def _remember(findings: list, root=None) -> list:
    """Fold past verdicts in. A memory that cannot be opened is not fatal."""
    if not findings:
        return findings
    try:
        from thot.memory import apply_memory, build_memory
    except ImportError:
        return findings

    try:
        memory = build_memory(root)
    except Exception:
        return findings
    try:
        return apply_memory(findings, memory)
    finally:
        getattr(memory, "close", lambda: None)()


def context_brief(recon: Recon, *, max_symbols: int = 60) -> str:
    """A compact briefing for the model's system prompt.

    Deliberately capped: the point is orientation, not a full dump. The model
    can call `find_symbol`, `callers` or `read_file` for anything deeper, and
    those calls are free because they hit the graph, not the model.
    """
    if recon.is_empty:
        return f"Répertoire de travail : {recon.root}\nIl est vide — aucun code source."

    lines = [f"Répertoire de travail : {recon.root}"]

    languages = ", ".join(
        f"{name} ({count})" for name, count in recon.manifest.languages.items()
    )
    lines.append(f"Fichiers : {recon.file_count} — {languages}")

    if recon.branch:
        state = "modifications non validées" if recon.dirty else "propre"
        lines.append(f"Git : {recon.branch}, {state}")
    if recon.manifest.test_command:
        lines.append(f"Tests : {recon.manifest.test_command}")

    if recon.manifest.entrypoints:
        shown = list(recon.manifest.entrypoints[:12])
        suffix = "…" if len(recon.manifest.entrypoints) > 12 else ""
        lines.append(f"Points d'entrée : {', '.join(shown)}{suffix}")

    top_files = _busiest_files(recon)
    if top_files:
        lines.append("Fichiers principaux : " + ", ".join(top_files))

    if recon.symbols:
        names = [s.name for s in recon.symbols if s.kind == "function"][:max_symbols]
        suffix = "…" if len(recon.symbols) > max_symbols else ""
        lines.append(f"Symboles ({len(recon.symbols)}) : {', '.join(names)}{suffix}")

    if recon.findings:
        summary = ", ".join(
            f"{f.rule} en {f.location}" for f in recon.findings[:8]
        )
        lines.append(f"Findings d'audit ({len(recon.findings)}) : {summary}")

    return "\n".join(lines)


def _busiest_files(recon: Recon, limit: int = 8) -> list[str]:
    counts: dict[str, int] = {}
    for symbol in recon.symbols:
        counts[symbol.path] = counts.get(symbol.path, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: -item[1])[:limit]
    return [f"{path} ({count})" for path, count in ranked]
