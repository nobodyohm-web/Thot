"""Phase 0 — discover what is in the repository and where it is entered."""

from __future__ import annotations

import ast
from pathlib import Path

from thot.scope.manifest import ScopeManifest

EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        "env", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", "site-packages", ".thot", ".next", "target", "vendor",
    }
)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
}

# Function names that make a module an entry point when defined at top level.
ENTRYPOINT_NAMES = frozenset({"main", "run", "cli", "handler", "lambda_handler"})


def module_name(relative_path: str) -> str:
    """`src/app.py` -> `src.app`, `src/pkg/__init__.py` -> `src.pkg`."""
    parts = Path(relative_path).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def iter_source_files(root: Path):
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.suffix in LANGUAGE_BY_SUFFIX:
            yield path


def _detect_test_command(root: Path) -> str | None:
    if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists():
        return "pytest"
    if (root / "package.json").exists():
        return "npm test"
    return None


def _python_entrypoints(root: Path, relative: str) -> list[str]:
    """Top-level functions carrying an entry-point name."""
    try:
        tree = ast.parse((root / relative).read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, OSError):
        return []

    found = []
    module = module_name(relative)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in ENTRYPOINT_NAMES:
                found.append(f"{module}.{node.name}")
    return found


def detect_scope(root: Path) -> ScopeManifest:
    root = Path(root)
    files: list[str] = []
    languages: dict[str, int] = {}

    for path in iter_source_files(root):
        relative = path.relative_to(root).as_posix()
        files.append(relative)
        language = LANGUAGE_BY_SUFFIX[path.suffix]
        languages[language] = languages.get(language, 0) + 1

    entrypoints: list[str] = []
    for relative in files:
        if relative.endswith(".py"):
            entrypoints.extend(_python_entrypoints(root, relative))

    return ScopeManifest(
        root=root,
        files=tuple(files),
        languages=languages,
        entrypoints=tuple(sorted(set(entrypoints))),
        test_command=_detect_test_command(root),
    )
