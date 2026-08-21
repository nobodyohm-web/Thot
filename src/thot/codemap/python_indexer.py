"""Python indexer built on the stdlib `ast` module — no third-party parser."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from thot.contracts import Symbol
from thot.scope.detect import module_name


def normalized_ast_hash(node: ast.AST) -> str:
    """Hash of the AST shape, blind to formatting, comments and line numbers."""
    dumped = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(dumped.encode()).hexdigest()[:16]


def _called_name(node: ast.Call) -> str | None:
    """`os.system(x)` -> "os.system"; `f(x)` -> "f"; anything else -> None."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        current = func.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return func.attr
    return None


def _scan(node: ast.AST) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """One walk, two answers: what this scope calls and what it hands around.

    Deliberately a single traversal. Collecting calls, bound names and
    loaded names in three separate `ast.walk` passes cost 84% more time on
    a 4 400-file repository — measured, not guessed — and an analysis whose
    selling point is that it is instant cannot afford that for a signal
    this small.

    **calls** are call edges. **references** are names read as values: the
    shape a callback has. `HANDLERS = {"run_command": run_command}` makes
    no call node, so a graph built only from calls reports `run_command` as
    having no callers at all — and in a web framework every view looks like
    that, so treating it as unreachable buries the common case.

    References stay narrow, because this signal switches the reachability
    discount off and a signal that fires everywhere switches it off
    everywhere: bare names only, never the function position of a call,
    never a name this scope binds itself.
    """
    calls: dict[str, None] = {}
    loads: list[str] = []
    bound: set[str] = set()
    call_targets: set[int] = set()

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        arguments = node.args
        for group in (arguments.posonlyargs, arguments.args, arguments.kwonlyargs):
            bound.update(a.arg for a in group)
        if arguments.vararg:
            bound.add(arguments.vararg.arg)
        if arguments.kwarg:
            bound.add(arguments.kwarg.arg)

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            call_targets.add(id(child.func))
            name = _called_name(child)
            if name:
                calls[name] = None
        elif isinstance(child, ast.Name):
            if not isinstance(child.ctx, ast.Load):
                bound.add(child.id)
            elif id(child) not in call_targets:
                # `ast.walk` is breadth-first, so a Call is always seen
                # before its own `func` child — which is why one pass is
                # enough to tell "handed around" from "called".
                loads.append(child.id)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if child is not node:
                bound.add(child.name)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                bound.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(child, ast.ExceptHandler) and child.name:
            bound.add(child.name)

    references = {name: None for name in loads if name not in bound}
    return tuple(calls), tuple(references)


class PythonIndexer:
    language = "python"

    def index_file(self, root: Path, relative: str) -> list[Symbol]:
        source_path = Path(root) / relative
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (SyntaxError, ValueError, OSError):
            return []

        module = module_name(relative)
        symbols: list[Symbol] = []

        def visit(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = f"{prefix}.{child.name}"
                    calls, references = _scan(child)
                    symbols.append(
                        Symbol(
                            name=name,
                            path=relative,
                            lineno=child.lineno,
                            end_lineno=child.end_lineno or child.lineno,
                            ast_hash=normalized_ast_hash(child),
                            kind="function",
                            calls=calls,
                            params=tuple(a.arg for a in child.args.args),
                            references=references,
                        )
                    )
                    visit(child, name)
                elif isinstance(child, ast.ClassDef):
                    name = f"{prefix}.{child.name}"
                    symbols.append(
                        Symbol(
                            name=name,
                            path=relative,
                            lineno=child.lineno,
                            end_lineno=child.end_lineno or child.lineno,
                            ast_hash=normalized_ast_hash(child),
                            kind="class",
                            calls=(),
                            params=(),
                        )
                    )
                    visit(child, name)

        visit(tree, module)

        # Module scope is where dispatch tables and decorated registrations
        # live, and it was invisible: a graph that never looks at import-time
        # code cannot see the table that wires everything together.
        decorated = tuple(
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.decorator_list
        )

        top_level = [
            node for node in tree.body
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef, ast.Import, ast.ImportFrom))
        ]
        if top_level or decorated:
            wrapper = ast.Module(body=top_level, type_ignores=[])
            module_calls, module_references = _scan(wrapper)
            symbols.append(
                Symbol(
                    name=module,
                    path=relative,
                    lineno=top_level[0].lineno if top_level else 1,
                    end_lineno=getattr(top_level[-1], "end_lineno",
                                       top_level[-1].lineno) if top_level else 1,
                    ast_hash=normalized_ast_hash(wrapper),
                    kind="module",
                    calls=module_calls,
                    # A decorated function is registered at import time with
                    # whatever the decorator does — a route table, a signal,
                    # a plugin registry. That is an escape, and it is the
                    # single most common one in real applications.
                    references=module_references + decorated,
                )
            )
        return symbols
