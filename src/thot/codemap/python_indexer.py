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


def _calls_in(node: ast.AST) -> tuple[str, ...]:
    names = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _called_name(child)
            if name:
                names.append(name)
    return tuple(dict.fromkeys(names))


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
                    symbols.append(
                        Symbol(
                            name=name,
                            path=relative,
                            lineno=child.lineno,
                            end_lineno=child.end_lineno or child.lineno,
                            ast_hash=normalized_ast_hash(child),
                            kind="function",
                            calls=_calls_in(child),
                            params=tuple(a.arg for a in child.args.args),
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
        return symbols
