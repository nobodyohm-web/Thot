"""Wire every deterministic phase together: scope -> map -> taint -> score."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.contracts import Confidence, Finding
from thot.scope.authorization import load_authorization
from thot.scope.detect import detect_scope
from thot.scope.manifest import ScopeManifest
from thot.scoring.severity import compute_severity
from thot.store.db import Store
from thot.taint.engine import find_candidates


@dataclass(frozen=True)
class AuditResult:
    findings: list[Finding]
    manifest: ScopeManifest
    elapsed: float
    run_id: int | None = None


def _git_commit(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return completed.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def findings_from_graph(root: Path, graph: CodeGraph) -> list[Finding]:
    """Turn taint candidates into scored findings. Shared by the CLI and the
    interactive session, so both see exactly the same analysis."""
    findings: list[Finding] = []
    for candidate in find_candidates(root, graph):
        distance = graph.distance_from_entrypoints(candidate.sink.symbol or "")
        severity = compute_severity(candidate.impact, distance, Confidence.PLAUSIBLE)
        scenario = (
            f"{candidate.description} : une valeur issue de `{candidate.source}` "
            f"atteint `{candidate.sink}` sans validation intermédiaire détectée."
        )
        findings.append(
            Finding(
                id=Finding.compute_id(candidate.rule, candidate.sink),
                rule=candidate.rule,
                severity=severity,
                confidence=Confidence.PLAUSIBLE,
                location=candidate.sink,
                taint_path=candidate.path,
                failure_scenario=scenario,
            )
        )
    return findings


def run_audit(
    root: Path, store: Store | None = None, *, require_authorization: bool = True
) -> AuditResult:
    """Run the full deterministic pipeline. Never calls a model or the network.

    `require_authorization=False` is for the interactive session: launching
    Thot inside a directory is itself the act of authorising it.
    """
    root = Path(root)
    started = time.monotonic()

    if require_authorization:
        load_authorization(root)  # raises AuthorizationError when not mandated
    manifest = detect_scope(root)

    indexer = PythonIndexer()
    symbols = []
    for relative in manifest.files:
        if relative.endswith(".py"):
            symbols.extend(indexer.index_file(root, relative))

    graph = CodeGraph.build(symbols, manifest.entrypoints)
    findings = findings_from_graph(root, graph)

    elapsed = time.monotonic() - started
    run_id = None
    if store is not None:
        run_id = store.start_run(root=str(root), commit=_git_commit(root))
        store.save_findings(run_id, findings)
        store.remember_symbols({s.name: s.ast_hash for s in symbols})

    return AuditResult(
        findings=findings, manifest=manifest, elapsed=elapsed, run_id=run_id
    )
