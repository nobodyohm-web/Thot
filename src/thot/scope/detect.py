"""Phase 0 — discover what is in the repository and where it is entered."""

from __future__ import annotations

import ast
import fnmatch
import os
import stat as stat_module
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

# This dict is the only place a file becomes visible to Thot at all: what is
# not here is not in `manifest.files`, so it reaches neither the indexer, nor
# the taint engines, nor the pattern rules, and is not even counted in the
# report's file total — a coverage claim the audit never earned.
#
# Three other lists describe the same JavaScript family and all three were
# wider: `ts_indexer.EXTENSIONS`, `guard.patterns._JS_EXTS`,
# `guard.suppressions.READABLE`. The narrowest one decides, so a modern ESM
# package, an explicit CommonJS one, a Vue or Svelte front end were invisible
# at 100 %. Measured on the two trees shipped here: `hermes/` collected 6924
# files out of 7080, `prime/` 938 out of 952.
#
# `.vue` and `.svelte` get labels of their own rather than `javascript`,
# because the label is what `console._pattern_only` turns into "teinte au
# fichier près : javascript N". Neither `ts_indexer` nor `js_engine` reads
# those suffixes; calling them JavaScript would announce a taint coverage
# that does not exist, which is the very lie this list was telling.
LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".svelte": "svelte",
}

# Files no indexer will ever parse, and that the pattern rules must still be
# offered. They are where credentials sit and where a CI workflow is injected:
# `guard/patterns.py` carries a `github_actions_workflow` rule keyed on
# `".github/workflows/" in path` which, until these were in scope, could not
# fire during an audit at all — and the secret rules saw neither a `.env` nor
# a `.pem` nor a `docker-compose.yml`.
#
# The price, measured before adding them: +6 files on Thot, +54 on Prime,
# +333 (4 MB) on Hermes, against 6 924 files of code.
SCANNED_SUFFIXES = frozenset({
    ".yml", ".yaml",                     # workflows, compose, k8s
    ".sh", ".bash", ".zsh",              # deploy scripts
    ".env", ".pem", ".key",              # credentials, private keys
    ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".tf", ".tfvars",                    # infrastructure
    ".json",                             # service accounts, settings
})

# Names that carry the same risk without carrying a suffix.
SCANNED_NAMES = frozenset({"Dockerfile", "Makefile", "Procfile", ".env"})


def _is_scanned(name: str) -> bool:
    return name in SCANNED_NAMES or os.path.splitext(name)[1] in SCANNED_SUFFIXES


# Function names that make a module an entry point when defined at top level.
ENTRYPOINT_NAMES = frozenset({"main", "run", "cli", "handler", "lambda_handler"})

# Decorator attributes that publish a function on an HTTP surface. Flask and
# Blueprints use `route`; FastAPI, Starlette and modern routers use the verb
# directly.
#
# This list is the most common entry point in Python and none of the five
# names above covered it. Measured, and the cost was not a ranking detail: a
# `sink.network` carries MEDIUM impact, a taint finding is PLAUSIBLE, and
# 0.5 x 0.8 x 0.6 = 0.24 against a MEDIUM threshold of 0.25. Every route
# handler in every web application was one hundredth under the line the
# default report draws — found by the engine, ranked `low`, and shown to
# nobody. On a labelled corpus that is 906 true positives reported as 292.
ROUTE_DECORATORS = frozenset({
    "route", "get", "post", "put", "patch", "delete", "head", "options",
    "websocket", "api_route",
})

# Django names the request object by convention and every tutorial, project
# and generator follows it. There is no decorator to key on — `urls.py` holds
# the routing table — so the convention is the only signal available without
# resolving the URL configuration.
DJANGO_REQUEST_ARG = "request"


def _is_route_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """`@app.route(...)`, `@router.post(...)`, `@bp.get(...)`.

    A Call is required, not a bare attribute: a route always carries a path,
    and `@app.get` without parentheses is far more likely to be a plain
    accessor being used as a decorator than a published endpoint.
    """
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        target = decorator.func
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            return True
    return False


def _is_django_view(node: ast.FunctionDef | ast.AsyncFunctionDef,
                    django: bool) -> bool:
    """A top-level function taking `request` first, in a module using Django.

    Both halves are needed. The argument name alone matches any helper that
    happens to be handed a request object; the import alone says nothing
    about which functions are views. Together they are the Django convention
    and little else.
    """
    if not django:
        return False
    args = node.args.posonlyargs + node.args.args
    return bool(args) and args[0].arg == DJANGO_REQUEST_ARG


def _imports_django(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "django":
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "django" for alias in node.names):
                return True
    return False


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


def _scan(root: Path, patterns: tuple[str, ...]):
    """`(relative, path, stat)` for every source file, pruning as it goes.

    The exclusions are applied to the *directory*, before descending it,
    which is the whole difference. Enumerating `.git`, `node_modules` and
    `.venv` in full and then dropping every entry gives the same list at a
    price nobody sees: on this repository, whose `.thotignore` sets aside
    `hermes/` and `prime/`, the walk cost 912 ms to keep 196 files. Pruned,
    it costs 177 ms — and it is now cheap enough to run on every tool call,
    which is what lets a map notice it has gone stale.

    Reading the parts of an absolute path was also wrong, not merely slow:
    a checkout living under a directory called `build` or `env` excluded
    every file in itself. Only the part below the root can decide.

    The stat is handed back because both callers need it — the manifest to
    know the file is real, the fingerprint to know which version it is —
    and asking the filesystem twice for one answer is the habit this
    function exists to break.
    """
    root_str = str(root)
    for base, dirnames, filenames in os.walk(root_str):
        relative_base = os.path.relpath(base, root_str)
        prefix = "" if relative_base == "." else (
            relative_base.replace(os.sep, "/") + "/"
        )
        dirnames[:] = [
            name for name in sorted(dirnames)
            if name not in EXCLUDED_DIRS
            and not (patterns and is_ignored(f"{prefix}{name}", patterns))
        ]
        for name in sorted(filenames):
            if (os.path.splitext(name)[1] not in LANGUAGE_BY_SUFFIX
                    and not _is_scanned(name)):
                continue
            relative = f"{prefix}{name}"
            if patterns and is_ignored(relative, patterns):
                continue
            path = Path(base) / name
            try:
                found = path.stat()
            except OSError:
                continue  # a broken symlink is not a file to read
            if not stat_module.S_ISREG(found.st_mode):
                continue
            yield relative, path, found


def iter_source_files(root: Path, patterns: tuple[str, ...] | None = None):
    root = Path(root)
    patterns = load_ignore(root) if patterns is None else patterns
    for _, path, _ in sorted(_scan(root, patterns), key=lambda item: item[0]):
        yield path


def source_versions(
    root: Path, patterns: tuple[str, ...] | None = None
) -> tuple[tuple[str, int, int], ...]:
    """Which version of the tree this is: `(relative, size, mtime_ns)` each.

    A map is only worth keeping while the thing it describes has not moved.
    Comparing this tuple is how a long-lived process — the MCP server that
    answers Hermes and Prime, the interactive session — finds out that the
    agent it serves has just edited the code underneath it, without paying
    to re-read the code to find out.

    Same key as `ts_indexer.read_masked` and the symbol cache: size and
    modification time. It cannot see a change that keeps both, and nothing
    that writes a file leaves both.
    """
    root = Path(root)
    patterns = load_ignore(root) if patterns is None else patterns
    versions = [
        (relative, found.st_size, found.st_mtime_ns)
        for relative, _, found in _scan(root, patterns)
    ]
    # `.thotignore` decides what is in scope at all, and it is not itself a
    # source file — so a tree whose ignore rules just changed would look
    # untouched while describing a different set of files entirely.
    try:
        found = (root / IGNORE_FILE).stat()
    except OSError:
        pass
    else:
        versions.append((IGNORE_FILE, found.st_size, found.st_mtime_ns))
    return tuple(sorted(versions))


def _detect_test_command(root: Path) -> str | None:
    if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists():
        return "pytest"
    if (root / "package.json").exists():
        return "npm test"
    return None


# Entry points, read once per version of a file. Finding them meant parsing
# every Python file in the tree, and `index_files` then parsed all of them
# again for the symbols: two complete syntax trees per file, per sweep, for
# a question whose answer is four function names. Measured on `hermes/`:
# 5.4 s of the 11 s it took to rebuild a map after one file had changed.
#
# Same key as the symbol cache, for the same reason — and bounded the same
# way, since a long-lived server maps whatever project it is asked about.
_ENTRYPOINT_CACHE: dict[tuple[str, int, int], tuple[str, ...]] = {}
ENTRYPOINT_CACHE_LIMIT = 20_000


def forget_entrypoints() -> None:
    """Drop the cache — for tests, and for a process that has moved on."""
    _ENTRYPOINT_CACHE.clear()


def _python_entrypoints(
    root: Path,
    relative: str,
    *,
    version: tuple[str, int, int] | None = None,
) -> list[str]:
    """Top-level functions carrying an entry-point name.

    `version` is the `(path, size, mtime_ns)` the caller already has from
    walking the tree; without it the file is stat'd here. Either way the
    answer is remembered against it, so an unchanged file is read once.
    """
    path = root / relative
    if version is None:
        try:
            found_stat = path.stat()
        except OSError:
            version = None
        else:
            version = (str(path), found_stat.st_size, found_stat.st_mtime_ns)

    if version is not None:
        remembered = _ENTRYPOINT_CACHE.get(version)
        if remembered is not None:
            return list(remembered)

    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, OSError, RecursionError):
        # RecursionError is the one that was missing, and it costs the whole
        # audit rather than one file: `y = 0 + 1 + … + 4999` builds a BinOp
        # tree five thousand deep and the parser gives out. A code generator
        # produces that, and so does a repository that would rather not be
        # read. `taint/engine` already caught it here; this site and the
        # indexer did not.
        found: tuple[str, ...] = ()
    else:
        module = module_name(relative)
        django = _imports_django(tree)
        found = tuple(
            f"{module}.{node.name}"
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and (node.name in ENTRYPOINT_NAMES
                 or _is_route_decorated(node)
                 or _is_django_view(node, django))
        )

    if version is not None:
        if len(_ENTRYPOINT_CACHE) >= ENTRYPOINT_CACHE_LIMIT:
            _ENTRYPOINT_CACHE.clear()
        _ENTRYPOINT_CACHE[version] = found
    return list(found)


def detect_scope(root: Path) -> ScopeManifest:
    root = Path(root)
    files: list[str] = []
    languages: dict[str, int] = {}
    patterns = load_ignore(root)

    entrypoints: list[str] = []

    # One walk, and the stat it already produced is handed straight to the
    # entry-point reader rather than asked for a second time.
    extra: list[str] = []

    for relative, path, found in sorted(
        _scan(root, patterns), key=lambda item: item[0]
    ):
        language = LANGUAGE_BY_SUFFIX.get(path.suffix)
        if language is None:
            # Swept, never indexed, and never counted as a language: a
            # `docker-compose.yml` is not a line of this project's code.
            extra.append(relative)
            continue
        files.append(relative)
        languages[language] = languages.get(language, 0) + 1
        if relative.endswith(".py"):
            entrypoints.extend(_python_entrypoints(
                root, relative,
                version=(str(path), found.st_size, found.st_mtime_ns),
            ))

    return ScopeManifest(
        root=root,
        extra_files=tuple(extra),
        files=tuple(files),
        languages=languages,
        entrypoints=tuple(sorted(set(entrypoints))),
        test_command=_detect_test_command(root),
    )
