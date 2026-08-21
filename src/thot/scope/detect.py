"""Phase 0 — discover what is in the repository and where it is entered."""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

from thot.scope.manifest import ScopeManifest

IGNORE_FILE = ".thotignore"

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


def load_ignore(root: Path) -> tuple[str, ...]:
    """Patterns from `.thotignore`, gitignore-shaped, blank and `#` lines out.

    The built-in exclusions cover build output and dependency trees, which
    every repository has. `.thotignore` covers what only this repository
    knows: vendored documentation, generated clients, a fixtures directory
    full of deliberately broken code. Auditing those does not produce
    findings, it produces noise that hides findings.
    """
    try:
        raw = (Path(root) / IGNORE_FILE).read_text(encoding="utf-8")
    except OSError:
        return ()
    return tuple(
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def is_ignored(relative: str, patterns: tuple[str, ...]) -> bool:
    """Match a repo-relative path against one `.thotignore` pattern set.

    A pattern naming a directory covers everything under it, with or
    without the trailing slash — the shape people actually type.
    """
    for pattern in patterns:
        cleaned = pattern.rstrip("/")
        if not cleaned:
            continue
        if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(relative, cleaned):
            return True
        if relative.startswith(f"{cleaned}/"):
            return True
        if fnmatch.fnmatch(relative, f"{cleaned}/*"):
            return True
        # A bare name matches at any depth, the way gitignore does.
        if "/" not in cleaned and any(
            fnmatch.fnmatch(part, cleaned) for part in relative.split("/")
        ):
            return True
    return False


def iter_source_files(root: Path, patterns: tuple[str, ...] | None = None):
    root = Path(root)
    patterns = load_ignore(root) if patterns is None else patterns
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.suffix not in LANGUAGE_BY_SUFFIX:
            continue
        if patterns and is_ignored(path.relative_to(root).as_posix(), patterns):
            continue
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
    patterns = load_ignore(root)

    for path in iter_source_files(root, patterns):
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
