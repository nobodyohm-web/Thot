"""Source-to-sink propagation.

Three levels of propagation, all deliberately bounded:

1. **Intra-procedural** — assignments are followed inside a single function
   body, so ``x = sys.argv[1]; os.system(x)`` is caught.
2. **Return-value** — a function that returns tainted data marks its callers'
   assignment targets as tainted, so ``x = read_input(); sink(x)`` is caught.
3. **Parameter** — a function whose parameter reaches a sink becomes a
   propagator; any caller passing tainted data into it extends the path.

Levels 2 and 3 are resolved by a small fixed-point loop bounded by
``max_depth`` iterations.

Dynamic dispatch, reflection and metaprogramming are out of reach. The result
is incomplete (false negatives), never fabricated: every reported path exists
in the call graph.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from thot.codemap.catalog import (
    active,
    is_sanitizer,
    match_entry,
    match_sink,
    match_source,
    using,
)
from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import _called_name
from thot.contracts import CodeRef, Severity, Symbol


@dataclass(frozen=True)
class TaintCandidate:
    """One source-to-sink path found without any model involvement."""

    rule: str
    source: CodeRef
    sink: CodeRef
    path: tuple[CodeRef, ...]
    impact: Severity
    description: str


def _expression_name(node: ast.AST) -> str | None:
    """Render `sys.argv`, `os.environ`, `f()` as a dotted string when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return node.attr
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    if isinstance(node, ast.Call):
        return _called_name(node)
    return None


def _referenced_names(node: ast.AST) -> set[str]:
    """Every identifier an expression reads, following composite expressions.

    Concatenations, f-strings, `%` formatting and `.format()` calls all carry
    taint — an injection almost always travels through one of them, so a
    `Name`-only view of arguments misses most real defects.

    Recursion stops at a sanitizing call: `shlex.quote(x)` reads `x` but does
    not propagate its taint.
    """
    names: set[str] = set()

    def visit(current: ast.AST) -> None:
        if isinstance(current, ast.Call):
            called = _called_name(current)
            if called and is_sanitizer(called):
                return
            if called:
                names.add(called)
            for argument in current.args:
                visit(argument)
            for keyword in current.keywords:
                visit(keyword.value)
            return
        if isinstance(current, ast.Name):
            names.add(current.id)
            return
        if isinstance(current, ast.Attribute):
            full = _expression_name(current)
            if full:
                names.add(full)
            return
        for child in ast.iter_child_nodes(current):
            visit(child)

    visit(node)
    return names


def _is_literal_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _sink_applies(rule_id: str, node: ast.Call) -> bool:
    """False when the call is in a form that cannot be injected.

    Two forms carry no injection risk and would otherwise flood a report:
    a subprocess call whose argv is a list without ``shell=True`` (no shell
    ever parses it), and a SQL call whose query is a plain literal (values
    travel as bound parameters).
    """
    first = node.args[0] if node.args else None

    if rule_id == "sink.subprocess.shell":
        # Without shell=True no shell ever parses the command, whatever the
        # argv shape — `list(args)` and `cmd + ["install"]` are as safe as a
        # literal list. Argument injection remains possible but is a different,
        # far lower-severity defect.
        return any(
            keyword.arg == "shell" and _is_literal_true(keyword.value)
            for keyword in node.keywords
        )

    if rule_id == "sink.sql":
        return not isinstance(first, ast.Constant)

    return True


@dataclass
class _Facts:
    """What one function body does with data, before cross-function resolution."""

    symbol: Symbol
    tainted: dict[str, CodeRef] = field(default_factory=dict)
    returns_taint: bool = False
    param_sinks: dict[str, list[tuple[str, CodeRef]]] = field(default_factory=dict)
    sink_calls: list[tuple[str, CodeRef, tuple[str, ...]]] = field(default_factory=list)
    calls_out: list[tuple[str, str, CodeRef]] = field(default_factory=list)
    assigns_from_call: list[tuple[str, str, CodeRef]] = field(default_factory=list)


def index_function_nodes(
    root: Path, paths: set[str]
) -> dict[tuple[str, int], ast.AST]:
    """Parse each file once and index every function body by (path, line).

    Parsing per symbol instead would re-read and re-parse a file as many times
    as it has functions — quadratic on any real repository.
    """
    index: dict[tuple[str, int], ast.AST] = {}
    for relative in paths:
        try:
            source = (root / relative).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (SyntaxError, ValueError, OSError, RecursionError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index[(relative, node.lineno)] = node
    return index


def _ordered_nodes(node: ast.AST) -> list[ast.AST]:
    """Walk the body in source order — `ast.walk` is breadth-first, which would
    let a sink be seen before the assignment that taints its argument."""
    return sorted(ast.walk(node), key=lambda n: (getattr(n, "lineno", 0),
                                                 getattr(n, "col_offset", 0)))


def _analyse_body(symbol: Symbol, node: ast.AST) -> _Facts:
    facts = _Facts(symbol=symbol)
    params = set(symbol.params)

    # A function a registry calls has no caller in this graph, so its
    # parameters would stay merely "conditionally tainted" for ever — waiting
    # on a caller that lives in a framework. When a rule says this is an
    # entry point, they are tainted outright, because the thing that fills
    # them is a model or a request and not another function here.
    entry = match_entry(symbol.name)
    if entry is not None:
        seed = CodeRef(path=symbol.path, line=symbol.lineno,
                       symbol=symbol.name, ast_hash=symbol.ast_hash)
        # Named parameters only, when the rule names any. A package-wide rule
        # that tainted every parameter would taint the `base_url` a helper
        # receives from configuration, and call it untrusted.
        untrusted = set(entry.parameters) & params if entry.parameters else params
        for name in untrusted:
            facts.tainted[name] = seed

    def is_tainted(names: set[str]) -> CodeRef | None:
        """Return where the taint came from, or None.

        The *earliest* origin when several names carry taint, and not
        whichever the set happened to yield first. Sets iterate in hash
        order, string hashing is randomised per process, and the reported
        source line therefore moved between two runs of the same audit —
        measured on Hermes: 5 findings of 417, same identities, different
        origins. A report that changes when nothing changed is a report
        nobody can diff.
        """
        carriers = [
            (facts.tainted[name].line, name) for name in names
            if name in facts.tainted
        ]
        if carriers:
            return facts.tainted[min(carriers)[1]]
        for name in sorted(names):
            if match_source(name):
                return None  # direct source: caller assigns the ref
        return None

    # How many times each call has already been seen in this body. AST order
    # is deterministic, so the count is the same on every run — and it only
    # has to hold within one version of the body, which `ast_hash` pins.
    call_ordinal: dict[str, int] = {}

    for child in _ordered_nodes(node):
        if isinstance(child, ast.Assign):
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name,
                          ast_hash=symbol.ast_hash)
            targets = [t.id for t in child.targets if isinstance(t, ast.Name)]
            refs = _referenced_names(child.value)

            origin = None
            if any(match_source(name) for name in refs):
                origin = ref
            else:
                origin = is_tainted(refs)
                if origin is None and refs & params:
                    origin = ref

            if origin is not None:
                for target in targets:
                    facts.tainted[target] = origin
            elif isinstance(child.value, ast.Call):
                called = _called_name(child.value)
                if called and not is_sanitizer(called):
                    for target in targets:
                        facts.assigns_from_call.append(
                            (target, called.rsplit(".", 1)[-1], ref)
                        )

        elif isinstance(child, ast.Return) and child.value is not None:
            refs = _referenced_names(child.value)
            if any(match_source(name) for name in refs) or is_tainted(refs):
                facts.returns_taint = True

        elif isinstance(child, ast.Call):
            called = _called_name(child)
            if not called:
                continue
            seen_before = call_ordinal.get(called, 0)
            call_ordinal[called] = seen_before + 1
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name,
                          ast_hash=symbol.ast_hash,
                          site=f"{called}#{seen_before}")

            rule = match_sink(called)

            if rule is not None and rule.dangerous_args:
                considered = [
                    child.args[index]
                    for index in rule.dangerous_args
                    if index < len(child.args)
                ]
            else:
                considered = list(child.args) + [k.value for k in child.keywords]

            argument_refs: set[str] = set()
            for argument in considered:
                argument_refs |= _referenced_names(argument)

            if rule is not None and not _sink_applies(rule.id, child):
                rule = None

            if rule is not None:
                facts.sink_calls.append((rule.id, ref, tuple(sorted(argument_refs))))
                # Sorted: this decides the insertion order of `param_sinks`,
                # the fixed point iterates it by that order, and `emit` keeps
                # the first candidate per sink — so a set's hash order was
                # choosing which origin a finding reported.
                for name in sorted(argument_refs & params):
                    facts.param_sinks.setdefault(name, []).append((rule.id, ref))
            else:
                outgoing: set[str] = set()
                for argument in child.args:
                    outgoing |= _referenced_names(argument)
                for keyword in child.keywords:
                    outgoing |= _referenced_names(keyword.value)
                # Sorted, like every other set that reaches the output. Case 2
                # emits the first caller that feeds a given sink and dedupes
                # the rest, so this order chose which origin a finding showed.
                for name in sorted(outgoing):
                    facts.calls_out.append((called.rsplit(".", 1)[-1], name, ref))

    return facts


def _impact_for(rule_id: str) -> Severity:
    for rule in active().sinks:
        if rule.id == rule_id:
            return rule.impact
    return Severity.MEDIUM


def _description_for(rule_id: str) -> str:
    for rule in active().sinks:
        if rule.id == rule_id:
            return rule.description
    return ""


def find_candidates(
    root: Path, graph: CodeGraph, max_depth: int = 3
) -> list[TaintCandidate]:
    """Return every source-to-sink path the deterministic analysis can prove.

    The repository's own rules are installed for the duration of the scan, so
    a team's shell wrapper and its validators count exactly like the built-in
    ones. Scoped, so they never leak into the next analysis.
    """
    from thot.codemap.rules import load_catalog

    root = Path(root)
    with using(load_catalog(root)):
        return _find_candidates(root, graph, max_depth)


def _find_candidates(
    root: Path, graph: CodeGraph, max_depth: int
) -> list[TaintCandidate]:

    functions = [s for s in graph.symbols.values() if s.kind == "function"]
    node_index = index_function_nodes(root, {s.path for s in functions})

    facts_by_name: dict[str, _Facts] = {}
    for symbol in functions:
        node = node_index.get((symbol.path, symbol.lineno))
        if node is None:
            continue
        facts_by_name[symbol.name] = _analyse_body(symbol, node)

    by_short: dict[str, list[str]] = {}
    for name in facts_by_name:
        by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

    def resolve(short: str, caller: str = "") -> list[_Facts]:
        """Definitions a bare call name can mean, the caller's module first.

        Matching on the short name alone across the whole tree links any two
        functions that happen to share one. Found on Hermes, and refuted by
        the panel with the reason spelled out: `agent/command_token_source.py`
        defines `_mint(command, label)` running `subprocess.run(..., shell=
        True)`, `tests/plugins/test_chronos_verify.py` defines its own
        `_mint(priv, claims)` signing a JWT, and the test calls its own. The
        engine reported a HIGH path from attacker data to a shell.

        Python resolves the local definition, so this does too; the tree-wide
        match stays as the fallback for an imported helper, which has no
        definition in the caller's module.
        """
        names = by_short.get(short, [])
        module = caller.rsplit(".", 1)[0] if "." in caller else ""
        if module:
            local = [n for n in names if n.rsplit(".", 1)[0] == module]
            if local:
                names = local
        return [facts_by_name[n] for n in names]

    # Fixed point: propagate tainted return values and tainted parameters
    # across call edges until nothing changes, bounded by max_depth.
    for _ in range(max_depth):
        changed = False
        for facts in facts_by_name.values():
            for target, callee_short, ref in facts.assigns_from_call:
                if target in facts.tainted:
                    continue
                if any(c.returns_taint for c in resolve(callee_short, facts.symbol.name)):
                    facts.tainted[target] = ref
                    changed = True

            for callee_short, arg, _ref in facts.calls_out:
                if arg not in set(facts.symbol.params):
                    continue
                for callee in resolve(callee_short, facts.symbol.name):
                    # Snapshot: a self-recursive call would otherwise mutate the
                    # very dict being iterated.
                    for sinks in list(callee.param_sinks.values()):
                        existing = facts.param_sinks.setdefault(arg, [])
                        for entry in sinks:
                            if entry not in existing:
                                existing.append(entry)
                                changed = True
        if not changed:
            break

    candidates: list[TaintCandidate] = []
    seen: set[tuple[str, str, int]] = set()

    def emit(rule_id: str, source: CodeRef, sink: CodeRef, path: tuple[CodeRef, ...]):
        key = (rule_id, sink.path, sink.line)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            TaintCandidate(
                rule=rule_id,
                source=source,
                sink=sink,
                path=path,
                impact=_impact_for(rule_id),
                description=_description_for(rule_id),
            )
        )

    # Case 1 — the source and the sink live in the same body.
    for facts in facts_by_name.values():
        for rule_id, ref, arg_names in facts.sink_calls:
            origin = None
            for arg in arg_names:
                if arg in facts.tainted:
                    origin = facts.tainted[arg]
                    break
                if match_source(arg):
                    origin = ref  # source read straight into the sink
                    break
            if origin is not None:
                emit(rule_id, origin, ref, (origin, ref))

    # Case 2 — a caller feeds tainted data into a propagating parameter.
    for facts in facts_by_name.values():
        for callee_short, arg, call_ref in facts.calls_out:
            origin = facts.tainted.get(arg)
            if origin is None and match_source(arg):
                # A source handed straight to the callee, without being stored
                # first. Case 1 has always accepted the same shape into a sink
                # in its own body — "source read straight into the sink" — and
                # the omission here made `launch(sys.argv[1])` invisible while
                # `cmd = sys.argv[1]; launch(cmd)` was reported. The inline
                # form is the more common of the two.
                origin = call_ref
            if origin is None:
                continue
            for callee in resolve(callee_short, facts.symbol.name):
                for sinks in list(callee.param_sinks.values()):
                    for rule_id, sink_ref in list(sinks):
                        emit(rule_id, origin, sink_ref, (origin, call_ref, sink_ref))

    return candidates
