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
from thot.scope.detect import detect_scope, source_versions
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
    # Which version of the tree this map describes. Kept so a long-lived
    # process can ask whether it still holds, without re-reading the code.
    versions: tuple[tuple[str, int, int], ...] = ()

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

    # Read before the map is built, never after: a file written while the
    # sweep is running must leave the result looking stale rather than fresh.
    versions = source_versions(root)
    manifest = detect_scope(root)
    recon = Recon(root=root, manifest=manifest, versions=versions)
    recon.branch, recon.dirty = _git_state(root)

    if not manifest.files:
        recon.elapsed = time.monotonic() - started
        return recon

    symbols: list[Symbol] = index_files(root, manifest.files)
    recon.symbols = symbols
    recon.graph = CodeGraph.build(symbols, manifest.entrypoints)

    if deep:
        deepen(recon)

    recon.elapsed = time.monotonic() - started
    return recon


def deepen(recon: Recon) -> Recon:
    """The expensive half of a sweep: taint paths, pattern rules, verdicts.

    Split out from `sweep` because the two halves cost wildly different
    amounts and are wanted at different moments. Measured on `hermes/`: the
    map — files, symbols, call graph — takes about a second; this takes two
    minutes. A server that rebuilt both every time the tree moved would
    answer `code_map` at the price of a full audit, which is how a fix for a
    stale map ends up worse than the stale map.

    Idempotent: it replaces the findings rather than adding to them, so
    asking twice costs time and never doubles a report.
    """
    from functools import partial

    from thot.parallel import over_files
    from thot.pipeline import _patterns_chunk, _suppressions_chunk

    root = recon.root
    files = list(recon.manifest.files)
    findings: list[Finding] = []

    if recon.symbols and recon.graph is not None:
        from thot.pipeline import findings_from_graph

        findings += findings_from_graph(root, recon.graph)

    # Same analysis the CLI runs, so /audit and `thot audit` never disagree.
    # A rule added on one side and not the other makes this comment a lie
    # without breaking a test — which is what happened to the suppression
    # sweep, an hour after it was written.
    # Spread across cores exactly as `run_audit` does. This is the path the
    # MCP `audit` tool takes, so an agent asking about a large repository was
    # paying the whole single-core sweep — two minutes on `hermes/` — inside
    # one tool call.
    findings += over_files(_patterns_chunk, root, list(recon.manifest.swept))

    # Same arbitration as `run_audit`: a pattern that duplicates a taint sink
    # steps aside in a file the indexer read. Applied here too, or `/audit`
    # and `thot audit` would disagree — which is the failure the comment
    # above was written about.
    from thot.pipeline import defer_to_taint

    findings = defer_to_taint(findings, {symbol.path for symbol in recon.symbols})

    already = {(f.location.path, f.location.line) for f in findings}
    findings += over_files(partial(_suppressions_chunk, already), root, files)
    recon.findings = _remember(findings, root)
    return recon


def is_stale(recon: Recon) -> bool:
    """Whether the tree has been written to since this map was built.

    One pruned walk and not a single file read — cheap enough to ask before
    answering every tool call, which is the only way a map handed to an
    agent that edits code stays true past that agent's first edit.
    """
    return source_versions(recon.root) != recon.versions


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


def _count(shown, whole) -> str:
    """`(12 des 30)` when the list was cut, `(30)` when it was not.

    A model over-relies on what is in its context: a bare ellipsis lets it
    guess how much it is missing, a count tells it. The tools that fetch the
    rest are free — this line is what makes the model know to call them.
    """
    if len(shown) < len(whole):
        return f"({len(shown)} des {len(whole)})"
    return f"({len(whole)})"


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
        lines.append(f"Points d'entrée {_count(shown, recon.manifest.entrypoints)}"
                     f" : {', '.join(shown)}")

    top_files = _busiest_files(recon)
    if top_files:
        lines.append("Fichiers principaux : " + ", ".join(top_files))

    # Functions only, and counted as functions. The marker used to compare the
    # total number of *symbols* against the limit while listing only
    # functions, so it announced a cut on a file full of classes where nothing
    # had been left out.
    functions = [s.name for s in recon.symbols if s.kind == "function"]
    if functions:
        shown = functions[:max_symbols]
        lines.append(f"Fonctions {_count(shown, functions)} : {', '.join(shown)}")

    if recon.findings:
        shown = recon.findings[:8]
        summary = ", ".join(f"{f.rule} en {f.location}" for f in shown)
        lines.append(f"Findings d'audit {_count(shown, recon.findings)} : {summary}")

    return "\n".join(lines)


def _busiest_files(recon: Recon, limit: int = 8) -> list[str]:
    counts: dict[str, int] = {}
    for symbol in recon.symbols:
        counts[symbol.path] = counts.get(symbol.path, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: -item[1])[:limit]
    return [f"{path} ({count})" for path, count in ranked]
