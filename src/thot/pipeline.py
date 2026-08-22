"""Wire every deterministic phase together: scope -> map -> taint -> score."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from thot.analysis.probe import DEFAULT_LIMIT, analyse
from thot.codemap.graph import CodeGraph
from thot.codemap.index import index_files
from thot.guard.scanner import sweep_patterns
from thot.memory.base import Memory, apply_memory, record_verdicts
from thot.errors import ScopeError
from thot.contracts import Confidence, Finding
from thot.plugins import annotate_findings
from thot.scope.authorization import load_authorization
from thot.scope.detect import detect_scope
from thot.scope.manifest import ScopeManifest
from thot.scoring.role import Role, role_of
from thot.scoring.severity import compute_severity
from thot.store.db import Store
from thot.taint.engine import find_candidates

if TYPE_CHECKING:  # the core knows the port, never an implementation
    from thot.engine.base import Engine


@dataclass(frozen=True)
class AuditResult:
    findings: list[Finding]
    manifest: ScopeManifest
    elapsed: float
    run_id: int | None = None
    engine: str | None = None  # None when the run stayed deterministic
    remembered: int = 0  # findings a stored verdict applied to
    supply_error: str = ""  # set when a dependency lookup could not happen

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence is Confidence.CONFIRMED]

    @property
    def refuted(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence is Confidence.REFUTED]


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
    entrypoints_known = bool(graph.entrypoints)

    from thot.taint import js_engine

    # Two engines, one contract. The Python one proves paths across returns
    # and parameters; the JavaScript one proves them inside a body and says
    # so. Both emit `TaintCandidate`, so scoring, roles, memory and the deep
    # pass treat them identically — a proven path is a proven path.
    candidates = list(find_candidates(root, graph))
    candidates += js_engine.find_candidates(root, list(graph.symbols.values()))

    for candidate in candidates:
        distance = graph.distance_from_entrypoints(candidate.sink.symbol or "")
        role = role_of(candidate.sink.path)
        severity = compute_severity(
            candidate.impact,
            distance,
            Confidence.PLAUSIBLE,
            entrypoints_known=entrypoints_known,
            escapes=graph.reach_unknown(candidate.sink.symbol or ""),
            role=role,
        )
        scenario = (
            f"{candidate.description} : une valeur issue de `{candidate.source}` "
            f"atteint `{candidate.sink}` sans validation intermédiaire détectée."
        )
        provenance = None
        if role is not Role.PRODUCTION:
            provenance = {"rôle": role.value}
        findings.append(
            Finding(
                id=Finding.compute_id(candidate.rule, candidate.sink),
                rule=candidate.rule,
                severity=severity,
                confidence=Confidence.PLAUSIBLE,
                location=candidate.sink,
                taint_path=candidate.path,
                failure_scenario=scenario,
                provenance=provenance,
            )
        )
    return findings


def run_audit(
    root: Path,
    store: Store | None = None,
    *,
    require_authorization: bool = True,
    engine: "Engine | None" = None,
    budget: int = DEFAULT_LIMIT,
    memory: Memory | None = None,
    dependencies: bool = False,
    on_decided: "Callable[[Finding], None] | None" = None,
    skip: set[str] | None = None,
) -> AuditResult:
    """Map, taint, score — then, if an engine is given, probe and refute.

    Without an engine the run never touches a model or the network, which is
    what makes it usable in CI and on a locked-down machine. With one, the
    worst candidates are argued and then attacked before anything is stored,
    so the persisted run holds verdicts rather than suspicions.

    `require_authorization=False` is for the interactive session: launching
    Thot inside a directory is itself the act of authorising it.
    """
    root = Path(root)
    if not root.is_dir():
        # Before anything else, and before the authorization message that
        # would otherwise tell someone to run `thot init` on a typo. A path
        # that is not there is not a repository with nothing wrong in it.
        raise ScopeError(f"Ce n'est pas un dossier : {root}")

    started = time.monotonic()

    if require_authorization:
        load_authorization(root)  # raises AuthorizationError when not mandated
    manifest = detect_scope(root)

    symbols = index_files(root, manifest.files)

    graph = CodeGraph.build(symbols, manifest.entrypoints)
    findings = findings_from_graph(root, graph)

    # Pattern rules cover what the AST indexer never reads — JavaScript, YAML,
    # CI workflows — and shapes that are dangerous without a provable path.
    findings += sweep_patterns(root, list(manifest.files))

    # A suppression is the one claim about safety that no scanner re-reads —
    # including this one, by design. Twice in a single audit a comment
    # disarming a check turned out to be false, so they are reported as a
    # class and left LOW: not "this is dangerous", but "nobody has re-read
    # the reason this was excused".
    from thot.guard.suppressions import sweep_suppressions

    findings += sweep_suppressions(root, list(manifest.files))

    # Dependencies are the one surface that needs the network, so they are
    # opt-in and imported here rather than at module level: an audit without
    # `--deps` must stay provably offline.
    supply_error = ""
    if dependencies:
        from thot.supply import audit_dependencies

        supply = audit_dependencies(root)
        findings += supply.findings
        supply_error = "" if supply.checked else supply.error

    # Past decisions land before the model does: select_for_analysis skips
    # refuted findings, so remembering a dismissal is what stops Thot paying
    # to re-litigate it every single run.
    remembered = 0
    if memory is not None and findings:
        before = findings
        findings = apply_memory(findings, memory)
        remembered = sum(
            1 for old, new in zip(before, findings) if old is not new
        )

    engine_name = None
    if engine is not None and findings:
        engine_name = engine.capabilities.name

        def settled(finding: Finding) -> None:
            # Written the moment it is decided, not at the end. A deep pass
            # over a large repository runs for hours; persisting only on the
            # way out means one interruption throws away every judgement the
            # run had already paid for. Because a remembered refutation is
            # skipped by the next `select_for_analysis`, this also makes an
            # interrupted pass resume where it stopped rather than restart.
            if memory is not None:
                record_verdicts([finding], memory, author=engine_name or "thot")
            if on_decided is not None:
                on_decided(finding)

        findings = analyse(
            root, findings, engine, limit=budget, on_decided=settled, skip=skip
        )

    # Plugins see the finished findings, before anything is written down.
    findings = annotate_findings(findings, root)

    elapsed = time.monotonic() - started
    run_id = None
    if store is not None:
        run_id = store.start_run(root=str(root), commit=_git_commit(root))
        store.save_findings(run_id, findings)
        store.remember_symbols({s.name: s.ast_hash for s in symbols})

    return AuditResult(
        findings=findings,
        manifest=manifest,
        elapsed=elapsed,
        run_id=run_id,
        engine=engine_name,
        remembered=remembered,
        supply_error=supply_error,
    )
