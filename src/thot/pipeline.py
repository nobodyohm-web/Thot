"""Wire every deterministic phase together: scope -> map -> taint -> score."""

from __future__ import annotations

from dataclasses import replace
from functools import partial

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
from thot.contracts import Confidence, Finding, Severity
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


TOUCHED_SHOWN = 10


def touched_lines(names, limit: int = TOUCHED_SHOWN) -> list[str]:
    """The files to print, and a line saying what was left out.

    Every other cut in the program marks itself — "… et N autres" in the
    session log, "(+N)" in an improve round, a dedicated line past twelve
    vulnerable dependencies. These two lists stopped at ten in silence and
    left the reader to subtract against the header, in the loudest message
    the tool produces.
    """
    shown = list(names[:limit])
    if len(names) > limit:
        shown.append(f"… et {len(names) - limit} autre(s) non listé(s)")
    return shown


@dataclass(frozen=True)
class AuditResult:
    findings: list[Finding]
    manifest: ScopeManifest
    elapsed: float
    run_id: int | None = None
    engine: str | None = None  # None when the run stayed deterministic
    remembered: int = 0  # findings a stored verdict applied to
    supply_error: str = ""  # set when a dependency lookup could not happen
    # Files the audit itself changed. Empty is the normal answer and the only
    # one worth trusting: two of the three agents can write, and no flag
    # stops them, so what cannot be prevented is made impossible to miss.
    touched: tuple[str, ...] = ()
    # Candidates a measured-noise rule produced and no model was paid to
    # argue. Never silent: `hidden` already set the precedent that anything
    # a threshold holds back is counted where the reader can see it.
    deferred: int = 0

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


_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _keep_stronger(kept: Finding, other: Finding) -> Finding:
    """Fold a second path to the same sink into the finding already held.

    `compute_id` leaves the taint path out on purpose, so a verdict survives
    a refactor of the caller — which makes two sources reaching one sink one
    finding, not two. Reported twice, they showed a reader the same row
    twice, counted twice, and let the deep pass argue one identity twice.

    The stronger score wins, because that is what a reader has to act on.
    The count is kept rather than dropped: three inputs reaching one sink is
    worth knowing.
    """
    winner = other if _RANK[other.severity] > _RANK[kept.severity] else kept
    provenance = dict(winner.provenance or {})
    provenance["chemins"] = int((kept.provenance or {}).get("chemins", 1)) + 1
    return replace(winner, provenance=provenance)


def findings_from_graph(root: Path, graph: CodeGraph) -> list[Finding]:
    """Turn taint candidates into scored findings. Shared by the CLI and the
    interactive session, so both see exactly the same analysis."""
    # Keyed by identity: two sources reaching one sink are one finding. The
    # dict carries the order too — insertion order is first sight, and
    # merging into a key already there does not move it — so a separate list
    # of identities was a second mechanism saying the same thing.
    by_id: dict[str, Finding] = {}
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
        # Naming the *kind* of source, not only the line it sits on. Since
        # the rank of a file-path finding depends on how far the value
        # travelled, a reader who cannot see which source started it cannot
        # tell a discounted finding from a quiet one — and cannot disagree.
        label = _source_label(candidate.source_rule)
        origin = (f"{label} (`{candidate.source}`)" if label
                  else f"`{candidate.source}`")
        scenario = (
            f"{candidate.description} : une valeur issue de {origin} "
            f"atteint `{candidate.sink}` sans validation intermédiaire détectée."
        )
        traced: dict = {}
        if role is not Role.PRODUCTION:
            traced["rôle"] = role.value
        if candidate.source_rule:
            # Not `source`: the pattern scanner already puts the *rule pack*
            # a rule came from under that key, and the two answers are
            # different questions with the same word.
            traced["source_rule"] = candidate.source_rule
        provenance = traced or None
        finding = Finding(
            id=Finding.compute_id(candidate.rule, candidate.sink),
            rule=candidate.rule,
            severity=severity,
            confidence=Confidence.PLAUSIBLE,
            location=candidate.sink,
            taint_path=candidate.path,
            failure_scenario=scenario,
            provenance=provenance,
        )
        held = by_id.get(finding.id)
        by_id[finding.id] = finding if held is None else _keep_stronger(
            held, finding
        )
    return list(by_id.values())


# The two sweeps below are the heaviest phases of an audit and the most
# obviously parallel: each reads one file, matches it against a fixed rule
# set, and appends to a local list. Measured on `hermes/`: 58.6 s and 11.0 s
# of the 138.5 s an audit took, on one core out of ten.
#
# Wrapped here rather than parallelised inside the guard because a spawned
# worker has to import the function it runs by name, and because the guard's
# own signature should not have to know that a pool exists.


def _patterns_chunk(root: str, relatives: list[str]) -> list:
    from thot.guard.scanner import sweep_patterns as sweep

    return sweep(Path(root), relatives)


def _suppressions_chunk(already: set, root: str, relatives: list[str]) -> list:
    """The already-flagged locations come bound in, never through a global.

    A worker is spawned, not forked: it re-imports this module from scratch,
    so a module-level variable the parent had just assigned reaches it as
    whatever the import statement produced — an empty set. `partial` carries
    the value across because it is pickled with the call.
    """
    from thot.guard.suppressions import sweep_suppressions as sweep

    return sweep(Path(root), relatives, already)


# A pattern rule that duplicates a taint sink, and the sink that proves the
# same call. `run_audit` states the division of labour below: pattern rules
# cover "what the AST indexer never reads — JavaScript, YAML, CI workflows —
# and shapes that are dangerous without a provable path". These three read
# Python the indexer does read, and match on the call's name alone.
#
# Measured against 100 labelled command-injection cases and 100 code-injection
# ones: the taint sinks scored 76 true positives and **no** false positive,
# while these three patterns added 89 false positives on top — they fire on a
# guarded call and an unguarded one alike, because a name is all they see.
# Deferring took command injection from +22 % to +82 % and eval injection from
# 0 % (a coin flip: it fired on all 100 cases) to +70 %.
#
# The price is 24 true positives the pattern caught and the taint pass did
# not, inside files it had read. That is the trade, and it is only taken
# where measured — adding an entry here means measuring it first.
DUPLICATES_A_SINK = {
    "pattern.eval_injection": "sink.eval",
    "pattern.os_system_injection": "sink.os.system",
    "pattern.python_subprocess_shell": "sink.subprocess.shell",
}


def defer_to_taint(findings: list, analysed: set[str]) -> list:
    """Drop pattern findings the taint pass was in a position to judge.

    `analysed` is the set of paths the indexer actually read. A file absent
    from it — JavaScript, a workflow, a module that failed to parse — keeps
    its pattern findings untouched, which is the whole reason the pattern
    rules exist.
    """
    return [
        finding for finding in findings
        if finding.rule not in DUPLICATES_A_SINK
        or finding.location.path not in analysed
    ]


def _source_label(rule_id: str) -> str:
    """The human name of the rule that started a path, in either language.

    Both catalogues are asked because both engines emit into one contract,
    and neither file may import the other: the two languages disagree about
    what a dangerous name looks like, which is the reason they are apart.
    """
    if not rule_id:
        return ""
    from thot.codemap.catalog import active as python_catalog
    from thot.taint.js_catalog import active as javascript_catalog

    found = python_catalog().source(rule_id) or javascript_catalog().source(rule_id)
    return found.description if found is not None else ""


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
    from thot.parallel import over_files

    # `swept`, not `files`: the pattern rules are the only thing that ever
    # reads a workflow, a compose file or a `.pem`, and they were being handed
    # the indexer's list — so the rule keyed on `.github/workflows/` could not
    # fire, and no secret rule ever saw a `.env`.
    findings += over_files(_patterns_chunk, root, list(manifest.swept))

    # A suppression is the one claim about safety that no scanner re-reads —
    # including this one, by design. Twice in a single audit a comment
    # disarming a check turned out to be false, so they are reported as a
    # class and left LOW: not "this is dangerous", but "nobody has re-read
    # the reason this was excused".
    findings = defer_to_taint(findings, {symbol.path for symbol in symbols})

    already = {(f.location.path, f.location.line) for f in findings}
    findings += over_files(
        partial(_suppressions_chunk, already), root, list(manifest.files)
    )

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
    touched_files: tuple[str, ...] = ()
    deferred = 0
    if engine is not None and findings:
        from thot.analysis.deep import run_deep_pass

        outcome = run_deep_pass(
            root, findings, engine,
            files=manifest.files, memory=memory, limit=budget, skip=skip,
            on_decided=on_decided,
        )
        findings = outcome.findings
        engine_name = outcome.engine
        touched_files = outcome.touched
        deferred = outcome.deferred

    # Plugins see the finished findings, before anything is written down.
    findings = annotate_findings(findings, root)

    elapsed = time.monotonic() - started
    run_id = None
    if store is not None:
        run_id = store.start_run(root=str(root), commit=_git_commit(root))
        store.save_findings(run_id, findings)
        # `remember_symbols` used to be called here, writing one row per
        # symbol — 101 533 of them on `hermes/`, every run — into a table
        # nothing outside the tests has ever read. It could not have been
        # read usefully either: `symbol_cache` is keyed on the symbol name
        # alone, with no path and no file version, so it cannot say whether
        # the file a symbol came from has changed. The cache that does that
        # work lives in `codemap/index.py`, keyed on (path, size, mtime_ns).

    return AuditResult(
        findings=findings,
        manifest=manifest,
        elapsed=elapsed,
        run_id=run_id,
        engine=engine_name,
        remembered=remembered,
        supply_error=supply_error,
        touched=touched_files,
        deferred=deferred,
    )
