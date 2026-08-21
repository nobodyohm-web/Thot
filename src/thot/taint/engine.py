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
    DEFAULT_SINKS,
    is_sanitizer,
    match_sink,
    match_source,
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


def _function_node(root: Path, symbol: Symbol) -> ast.AST | None:
    try:
        source = (root / symbol.path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (SyntaxError, ValueError, OSError):
        return None
    short = symbol.name.rsplit(".", 1)[-1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == short and node.lineno == symbol.lineno:
                return node
    return None


def _ordered_nodes(node: ast.AST) -> list[ast.AST]:
    """Walk the body in source order — `ast.walk` is breadth-first, which would
    let a sink be seen before the assignment that taints its argument."""
    return sorted(ast.walk(node), key=lambda n: (getattr(n, "lineno", 0),
                                                 getattr(n, "col_offset", 0)))


def _analyse_body(symbol: Symbol, node: ast.AST) -> _Facts:
    facts = _Facts(symbol=symbol)
    params = set(symbol.params)

    def is_tainted(names: set[str]) -> CodeRef | None:
        """Return where the taint came from, or None."""
        for name in names:
            if name in facts.tainted:
                return facts.tainted[name]
        for name in names:
            if match_source(name):
                return None  # direct source: caller assigns the ref
        return None

    for child in _ordered_nodes(node):
        if isinstance(child, ast.Assign):
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name)
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
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name)

            argument_refs: set[str] = set()
            for argument in child.args:
                argument_refs |= _referenced_names(argument)
            for keyword in child.keywords:
                argument_refs |= _referenced_names(keyword.value)

            rule = match_sink(called)
            if rule is not None:
                facts.sink_calls.append((rule.id, ref, tuple(sorted(argument_refs))))
                for name in argument_refs & params:
                    facts.param_sinks.setdefault(name, []).append((rule.id, ref))
            else:
                for name in argument_refs:
                    facts.calls_out.append((called.rsplit(".", 1)[-1], name, ref))

    return facts


def _impact_for(rule_id: str) -> Severity:
    for rule in DEFAULT_SINKS:
        if rule.id == rule_id:
            return rule.impact
    return Severity.MEDIUM


def _description_for(rule_id: str) -> str:
    for rule in DEFAULT_SINKS:
        if rule.id == rule_id:
            return rule.description
    return ""


def find_candidates(
    root: Path, graph: CodeGraph, max_depth: int = 3
) -> list[TaintCandidate]:
    """Return every source-to-sink path the deterministic analysis can prove."""
    root = Path(root)

    facts_by_name: dict[str, _Facts] = {}
    for name, symbol in graph.symbols.items():
        if symbol.kind != "function":
            continue
        node = _function_node(root, symbol)
        if node is None:
            continue
        facts_by_name[name] = _analyse_body(symbol, node)

    by_short: dict[str, list[str]] = {}
    for name in facts_by_name:
        by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

    def resolve(short: str) -> list[_Facts]:
        return [facts_by_name[n] for n in by_short.get(short, [])]

    # Fixed point: propagate tainted return values and tainted parameters
    # across call edges until nothing changes, bounded by max_depth.
    for _ in range(max_depth):
        changed = False
        for facts in facts_by_name.values():
            for target, callee_short, ref in facts.assigns_from_call:
                if target in facts.tainted:
                    continue
                if any(c.returns_taint for c in resolve(callee_short)):
                    facts.tainted[target] = ref
                    changed = True

            for callee_short, arg, _ref in facts.calls_out:
                if arg not in set(facts.symbol.params):
                    continue
                for callee in resolve(callee_short):
                    for sinks in callee.param_sinks.values():
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
            if origin is None:
                continue
            for callee in resolve(callee_short):
                for sinks in callee.param_sinks.values():
                    for rule_id, sink_ref in sinks:
                        emit(rule_id, origin, sink_ref, (origin, call_ref, sink_ref))

    return candidates
