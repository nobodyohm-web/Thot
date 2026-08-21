# Thot M1+M2 — Noyau déterministe — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer un binaire `thot` qui audite un dépôt Python de bout en bout — inventaire, graphe d'appels, chemins de teinte source→sink, sévérité calculée, rapport terminal et JSON — sans aucun appel à un modèle de langage.

**Architecture:** Un package Python autonome (`src/thot/`), un module par phase du pipeline, chacun testable seul. Les phases 0 à 2 de la spec (scope, carte, taint) plus le store, le calcul de sévérité et le rendu. Le port `Engine` et tout ce qui appelle un modèle sont hors périmètre de ce plan — mais rien ici ne doit les empêcher.

**Tech Stack:** Python 3.11+, `uv`, stdlib `ast` / `sqlite3` / `argparse`, `rich` (affichage terminal), `pyyaml` (fichiers de configuration), `pytest`.

**Spec:** `docs/superpowers/specs/2026-08-21-thot-design.md`

## Global Constraints

- Python 3.11+ (`requires-python = ">=3.11"`).
- **Aucune dépendance à Prime Agent ou Hermes** dans `src/thot/`. Un test le vérifie (Task 14).
- **Aucun appel réseau, aucun appel modèle** dans ce plan. Tout est déterministe et hors ligne.
- Dépendances runtime limitées à `rich` et `pyyaml`. Toute autre dépendance doit être justifiée dans le commit qui l'ajoute.
- Chemins toujours **relatifs à la racine du dépôt audité** dans les données persistées et les rapports ; jamais de chemin absolu dans un `CodeRef`.
- Aucune valeur de secret dans un log, un rapport ou la base : emplacement et type uniquement.
- Le code, les identifiants et les docstrings sont en anglais ; les messages utilisateur du CLI sont en français.
- TDD strict : le test échoue d'abord, on ne code que ce qu'il faut pour le faire passer.
- Un commit par tâche, message en anglais, préfixe conventionnel (`feat:`, `test:`, `chore:`).

---

## File Structure

```
Thot/
  pyproject.toml                    packaging, deps, entry point `thot`
  README.md                         installation + usage en 20 lignes
  src/thot/
    __init__.py                     __version__
    contracts.py                    CodeRef, Symbol, Severity, Confidence, Finding
    errors.py                       exceptions du domaine
    cli.py                          argparse, sous-commandes, codes de sortie
    console.py                      rendu terminal (rich) — le seul module qui imprime
    scope/
      __init__.py
      authorization.py              lecture/validation .thot/authorization.yaml
      detect.py                     langages, fichiers, exclusions, entrypoints
      manifest.py                   ScopeManifest
    codemap/
      __init__.py
      indexer.py                    protocole Indexer + registre
      python_indexer.py             AST Python → Symbol[]
      graph.py                      CodeGraph : arêtes d'appel, accessibilité
      catalog.py                    SinkRule / SourceRule + catalogue par défaut
      churn.py                      churn git par fichier
    taint/
      __init__.py
      engine.py                     propagation intra + inter-procédurale
    scoring/
      __init__.py
      severity.py                   impact × accessibilité × confiance
    store/
      __init__.py
      db.py                         SQLite : runs, findings, symbol_cache
    report/
      __init__.py
      json_report.py                export JSON
      markdown_report.py            export Markdown
  tests/
    conftest.py                     fixtures : dépôt jouet
    test_contracts.py
    test_authorization.py
    test_detect.py
    test_python_indexer.py
    test_graph.py
    test_catalog.py
    test_taint.py
    test_severity.py
    test_store.py
    test_report.py
    test_cli.py
    test_no_agent_dependency.py
```

Découpage par **responsabilité**, pas par couche : `taint/` contient tout ce qui concerne la propagation, `scope/` tout ce qui concerne le périmètre. `console.py` est le seul module autorisé à écrire sur stdout — tout le reste retourne des données.

---

### Task 1: Squelette du projet et CLI qui démarre

**Files:**
- Create: `pyproject.toml`, `src/thot/__init__.py`, `src/thot/cli.py`, `.gitignore`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: rien
- Produces: `thot.__version__: str`, `thot.cli.main(argv: list[str] | None = None) -> int`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
from thot import cli


def test_version_flag_prints_version_and_exits_zero(capsys):
    code = cli.main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert "thot" in captured.out.lower()


def test_no_command_shows_help_and_exits_two(capsys):
    code = cli.main([])
    captured = capsys.readouterr()
    assert code == 2
    assert "audit" in captured.out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot'`

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[project]
name = "thot"
version = "0.1.0"
description = "Proof-backed code audit engine"
requires-python = ">=3.11"
dependencies = ["rich>=13.7", "pyyaml>=6.0"]

[project.scripts]
thot = "thot.cli:run"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/thot"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]

[dependency-groups]
dev = ["pytest>=8.0"]
```

```python
# src/thot/__init__.py
"""Thot — proof-backed code audit engine."""

__version__ = "0.1.0"
```

```python
# src/thot/cli.py
"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from thot import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thot",
        description="Audit de code adossé à des preuves.",
    )
    parser.add_argument(
        "--version", action="version", version=f"thot {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command")

    audit = subparsers.add_parser("audit", help="Auditer un dépôt")
    audit.add_argument("path", nargs="?", default=".", help="Racine du dépôt")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    return 0


def run() -> None:
    sys.exit(main())
```

```
# .gitignore
__pycache__/
*.py[cod]
.venv/
dist/
build/
*.egg-info/
.pytest_cache/
.thot/store.db
```

Note : `--version` fait sortir `argparse` via `SystemExit(0)`. Le test appelle `cli.main` directement, donc il faut attraper cette sortie. Corriger `main` :

```python
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --version / --help / erreur d'argument
        return int(exc.code or 0)
    if not args.command:
        parser.print_help()
        return 2
    return 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/thot/__init__.py src/thot/cli.py tests/test_cli.py .gitignore
git commit -m "feat: project skeleton with a CLI that starts"
```

---

### Task 2: Contrats de données

**Files:**
- Create: `src/thot/contracts.py`, `src/thot/errors.py`
- Test: `tests/test_contracts.py`

**Interfaces:**
- Consumes: rien
- Produces:
  - `CodeRef(path: str, line: int, symbol: str | None, ast_hash: str | None)`, `__str__` → `"path:line"`
  - `Symbol(name, path, lineno, end_lineno, ast_hash, kind, calls: tuple[str, ...], params: tuple[str, ...])`
  - `Severity` / `Confidence` : énumérations `str`
  - `Finding(id, rule, severity, confidence, location, taint_path, failure_scenario, repro=None, patch=None, provenance=None)`
  - `Finding.compute_id(rule: str, location: CodeRef) -> str`
  - `errors.ThotError`, `errors.AuthorizationError`, `errors.ScopeError`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_contracts.py
from thot.contracts import CodeRef, Confidence, Finding, Severity


def test_coderef_renders_as_path_colon_line():
    ref = CodeRef(path="src/app.py", line=42)
    assert str(ref) == "src/app.py:42"


def test_coderef_is_hashable_and_frozen():
    ref = CodeRef(path="src/app.py", line=42)
    assert {ref: 1}[ref] == 1


def test_finding_id_is_stable_across_line_moves():
    a = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="abc")
    b = CodeRef(path="src/app.py", line=99, symbol="app.handler", ast_hash="abc")
    assert Finding.compute_id("taint.os.system", a) == Finding.compute_id(
        "taint.os.system", b
    )


def test_finding_id_changes_when_symbol_body_changes():
    a = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="abc")
    b = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="def")
    assert Finding.compute_id("taint.os.system", a) != Finding.compute_id(
        "taint.os.system", b
    )


def test_severity_and_confidence_serialise_as_strings():
    assert Severity.HIGH.value == "high"
    assert Confidence.PLAUSIBLE.value == "plausible"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_contracts.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.contracts'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/errors.py
"""Domain exceptions."""

from __future__ import annotations


class ThotError(Exception):
    """Base class for every Thot domain error."""


class AuthorizationError(ThotError):
    """Raised when the audit is not authorized for the target repository."""


class ScopeError(ThotError):
    """Raised when the target repository cannot be scoped."""
```

```python
# src/thot/contracts.py
"""Stable data contracts shared by every phase of the pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

SCHEMA_VERSION = 1


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    REFUTED = "refuted"


@dataclass(frozen=True)
class CodeRef:
    """A location in the audited repository. `path` is always repo-relative."""

    path: str
    line: int
    symbol: str | None = None
    ast_hash: str | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class Symbol:
    """A named, indexable unit of code (function, method, class)."""

    name: str
    path: str
    lineno: int
    end_lineno: int
    ast_hash: str
    kind: str
    calls: tuple[str, ...] = ()
    params: tuple[str, ...] = ()

    def to_ref(self) -> CodeRef:
        return CodeRef(
            path=self.path,
            line=self.lineno,
            symbol=self.name,
            ast_hash=self.ast_hash,
        )


@dataclass(frozen=True)
class Finding:
    """One audited defect. Identity is stable across line moves."""

    id: str
    rule: str
    severity: Severity
    confidence: Confidence
    location: CodeRef
    taint_path: tuple[CodeRef, ...] = ()
    failure_scenario: str = ""
    repro: object | None = None
    patch: object | None = None
    provenance: dict | None = None
    schema_version: int = SCHEMA_VERSION

    @staticmethod
    def compute_id(rule: str, location: CodeRef) -> str:
        """Stable identity: rule + file + symbol + body hash. Not the line."""
        material = "|".join(
            [rule, location.path, location.symbol or "", location.ast_hash or ""]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_contracts.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/contracts.py src/thot/errors.py tests/test_contracts.py
git commit -m "feat: stable data contracts for findings and code references"
```

---

### Task 3: Autorisation obligatoire

**Files:**
- Create: `src/thot/scope/__init__.py`, `src/thot/scope/authorization.py`
- Test: `tests/test_authorization.py`

**Interfaces:**
- Consumes: `thot.errors.AuthorizationError`
- Produces:
  - `Authorization(owner: str, scope: str, authorized: bool, date: str)`
  - `load_authorization(root: Path) -> Authorization` — lève `AuthorizationError` si absent, mal formé, `authorized: false`, ou si `scope` ne correspond pas à `root`
  - `write_authorization(root: Path, owner: str) -> Path` — utilisé par `thot init`
  - `AUTHORIZATION_FILENAME = ".thot/authorization.yaml"`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authorization.py
import pytest

from thot.errors import AuthorizationError
from thot.scope.authorization import load_authorization, write_authorization


def test_missing_file_is_refused(tmp_path):
    with pytest.raises(AuthorizationError, match="autorisation"):
        load_authorization(tmp_path)


def test_written_file_is_accepted(tmp_path):
    write_authorization(tmp_path, owner="Dev")
    auth = load_authorization(tmp_path)
    assert auth.owner == "Dev"
    assert auth.authorized is True


def test_authorized_false_is_refused(tmp_path):
    path = write_authorization(tmp_path, owner="Dev")
    path.write_text(path.read_text().replace("authorized: true", "authorized: false"))
    with pytest.raises(AuthorizationError, match="authorized"):
        load_authorization(tmp_path)


def test_scope_mismatch_is_refused(tmp_path):
    write_authorization(tmp_path, owner="Dev")
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / ".thot").mkdir()
    (other / ".thot" / "authorization.yaml").write_text(
        "owner: Dev\nscope: /not/this/path\nauthorized: true\ndate: '2026-08-21'\n"
    )
    with pytest.raises(AuthorizationError, match="périmètre"):
        load_authorization(other)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_authorization.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.scope'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/scope/__init__.py
"""Phase 0 — scoping and authorization."""
```

```python
# src/thot/scope/authorization.py
"""Authorization gate: Thot refuses to audit code it was not mandated to audit."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path

import yaml

from thot.errors import AuthorizationError

AUTHORIZATION_FILENAME = ".thot/authorization.yaml"


@dataclass(frozen=True)
class Authorization:
    owner: str
    scope: str
    authorized: bool
    date: str


def authorization_path(root: Path) -> Path:
    return Path(root) / AUTHORIZATION_FILENAME


def write_authorization(root: Path, owner: str) -> Path:
    """Create the authorization file for `root`. Used by `thot init`."""
    path = authorization_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "owner": owner,
        "scope": str(Path(root).resolve()),
        "authorized": True,
        "date": _dt.date.today().isoformat(),
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True))
    return path


def load_authorization(root: Path) -> Authorization:
    path = authorization_path(root)
    if not path.exists():
        raise AuthorizationError(
            f"Aucun fichier d'autorisation ({AUTHORIZATION_FILENAME}). "
            f"Lance `thot init {root}` si ce code t'appartient ou si tu es mandaté "
            f"pour l'auditer."
        )
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"Fichier d'autorisation illisible : {exc}") from exc

    if not isinstance(raw, dict):
        raise AuthorizationError("Fichier d'autorisation malformé.")
    if raw.get("authorized") is not True:
        raise AuthorizationError(
            "Le fichier d'autorisation ne déclare pas `authorized: true`."
        )

    declared = Path(str(raw.get("scope", ""))).resolve()
    actual = Path(root).resolve()
    if declared != actual:
        raise AuthorizationError(
            f"Le périmètre déclaré ({declared}) ne correspond pas au dépôt audité "
            f"({actual})."
        )

    return Authorization(
        owner=str(raw.get("owner", "")),
        scope=str(declared),
        authorized=True,
        date=str(raw.get("date", "")),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_authorization.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/scope tests/test_authorization.py
git commit -m "feat: mandatory authorization gate before any audit"
```

---

### Task 4: Détection du périmètre

**Files:**
- Create: `src/thot/scope/manifest.py`, `src/thot/scope/detect.py`, `tests/conftest.py`
- Test: `tests/test_detect.py`

**Interfaces:**
- Consumes: `CodeRef`, `ScopeError`
- Produces:
  - `ScopeManifest(root: Path, files: tuple[str, ...], languages: dict[str, int], entrypoints: tuple[str, ...], test_command: str | None)`
  - `detect_scope(root: Path) -> ScopeManifest`
  - `EXCLUDED_DIRS: frozenset[str]`

- [ ] **Step 1: Write the failing test**

```python
# tests/conftest.py
import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def toy_repo(tmp_path: Path) -> Path:
    """A small Python repo with one real taint path from argv to os.system."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        textwrap.dedent(
            """
            import os
            import sys


            def read_user_input():
                return sys.argv[1]


            def run_command(cmd):
                os.system(cmd)


            def unreachable_helper(cmd):
                os.system(cmd)


            def main():
                target = read_user_input()
                run_command(target)
            """
        ).strip()
    )
    (tmp_path / "src" / "safe.py").write_text(
        textwrap.dedent(
            """
            def add(a, b):
                return a + b
            """
        ).strip()
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("import os\nos.system('x')\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "toy"\n')
    return tmp_path
```

```python
# tests/test_detect.py
from thot.scope.detect import detect_scope


def test_python_files_are_collected(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src/app.py" in manifest.files
    assert "src/safe.py" in manifest.files


def test_excluded_directories_are_skipped(toy_repo):
    manifest = detect_scope(toy_repo)
    assert not any(f.startswith("node_modules/") for f in manifest.files)


def test_languages_are_counted(toy_repo):
    manifest = detect_scope(toy_repo)
    assert manifest.languages["python"] == 2


def test_main_is_detected_as_entrypoint(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src.app.main" in manifest.entrypoints


def test_paths_are_relative_never_absolute(toy_repo):
    manifest = detect_scope(toy_repo)
    assert all(not f.startswith("/") for f in manifest.files)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_detect.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.scope.detect'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/scope/manifest.py
"""The scope manifest: what will be audited, and how it is run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScopeManifest:
    root: Path
    files: tuple[str, ...]
    languages: dict[str, int]
    entrypoints: tuple[str, ...]
    test_command: str | None = None
```

```python
# src/thot/scope/detect.py
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
    """Top-level functions with an entry-point name, plus `if __name__` guards."""
    try:
        tree = ast.parse((root / relative).read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError):
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_detect.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/scope/manifest.py src/thot/scope/detect.py tests/conftest.py tests/test_detect.py
git commit -m "feat: repository scope detection with exclusions and entry points"
```

---

### Task 5: Indexeur Python

**Files:**
- Create: `src/thot/codemap/__init__.py`, `src/thot/codemap/indexer.py`, `src/thot/codemap/python_indexer.py`
- Test: `tests/test_python_indexer.py`

**Interfaces:**
- Consumes: `Symbol`, `scope.detect.module_name`
- Produces:
  - `Indexer` (Protocol) : `index_file(root: Path, relative: str) -> list[Symbol]`
  - `PythonIndexer` implémentant ce protocole
  - `normalized_ast_hash(node: ast.AST) -> str` — insensible au formatage et aux commentaires

- [ ] **Step 1: Write the failing test**

```python
# tests/test_python_indexer.py
import ast

from thot.codemap.python_indexer import PythonIndexer, normalized_ast_hash


def test_functions_are_indexed_with_qualified_names(toy_repo):
    symbols = PythonIndexer().index_file(toy_repo, "src/app.py")
    names = {s.name for s in symbols}
    assert "src.app.main" in names
    assert "src.app.run_command" in names


def test_calls_are_recorded(toy_repo):
    symbols = {s.name: s for s in PythonIndexer().index_file(toy_repo, "src/app.py")}
    assert "read_user_input" in symbols["src.app.main"].calls
    assert "os.system" in symbols["src.app.run_command"].calls


def test_params_are_recorded(toy_repo):
    symbols = {s.name: s for s in PythonIndexer().index_file(toy_repo, "src/app.py")}
    assert symbols["src.app.run_command"].params == ("cmd",)


def test_ast_hash_ignores_formatting_and_comments():
    a = ast.parse("def f(x):\n    return x + 1\n")
    b = ast.parse("def f(x):\n    # a comment\n    return  x  +  1\n")
    assert normalized_ast_hash(a) == normalized_ast_hash(b)


def test_ast_hash_changes_when_logic_changes():
    a = ast.parse("def f(x):\n    return x + 1\n")
    b = ast.parse("def f(x):\n    return x + 2\n")
    assert normalized_ast_hash(a) != normalized_ast_hash(b)


def test_methods_are_indexed_with_class_in_the_name(tmp_path):
    (tmp_path / "m.py").write_text("class A:\n    def go(self):\n        pass\n")
    symbols = {s.name for s in PythonIndexer().index_file(tmp_path, "m.py")}
    assert "m.A.go" in symbols


def test_syntax_error_yields_no_symbols_without_raising(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    assert PythonIndexer().index_file(tmp_path, "broken.py") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_python_indexer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.codemap'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/codemap/__init__.py
"""Phase 1 — build the map: symbols, call graph, sinks and sources."""
```

```python
# src/thot/codemap/indexer.py
"""The indexer protocol every language backend implements."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from thot.contracts import Symbol


class Indexer(Protocol):
    """Turns one source file into a flat list of symbols."""

    language: str

    def index_file(self, root: Path, relative: str) -> list[Symbol]: ...
```

```python
# src/thot/codemap/python_indexer.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_python_indexer.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/codemap tests/test_python_indexer.py
git commit -m "feat: Python indexer with formatting-blind AST hashing"
```

---

### Task 6: Graphe d'appels et accessibilité

**Files:**
- Create: `src/thot/codemap/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `Symbol`
- Produces:
  - `CodeGraph.build(symbols: list[Symbol], entrypoints: tuple[str, ...]) -> CodeGraph`
  - `graph.symbols: dict[str, Symbol]`
  - `graph.callees(name) -> set[str]` / `graph.callers(name) -> set[str]`
  - `graph.distance_from_entrypoints(name) -> int | None` — `None` si inatteignable

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph.py
from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.scope.detect import detect_scope


def build(toy_repo):
    manifest = detect_scope(toy_repo)
    symbols = []
    for relative in manifest.files:
        symbols.extend(PythonIndexer().index_file(toy_repo, relative))
    return CodeGraph.build(symbols, manifest.entrypoints)


def test_local_calls_resolve_to_qualified_names(toy_repo):
    graph = build(toy_repo)
    assert "src.app.run_command" in graph.callees("src.app.main")


def test_callers_is_the_inverse_of_callees(toy_repo):
    graph = build(toy_repo)
    assert "src.app.main" in graph.callers("src.app.run_command")


def test_entrypoint_is_at_distance_zero(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.main") == 0


def test_called_function_is_at_distance_one(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.run_command") == 1


def test_unreachable_symbol_has_no_distance(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.unreachable_helper") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.codemap.graph'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/codemap/graph.py
"""Call graph with best-effort name resolution and reachability distances."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from thot.contracts import Symbol


@dataclass
class CodeGraph:
    """Symbols plus resolved call edges.

    Resolution is deliberately best-effort: a bare call name is matched
    first inside the caller's own module, then globally by short name.
    Dynamic dispatch is not resolved — see the spec's documented limits.
    """

    symbols: dict[str, Symbol] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)
    entrypoints: tuple[str, ...] = ()

    @classmethod
    def build(
        cls, symbols: list[Symbol], entrypoints: tuple[str, ...] = ()
    ) -> CodeGraph:
        by_name = {s.name: s for s in symbols}

        # Index by short name for global fallback resolution.
        by_short: dict[str, list[str]] = {}
        for name in by_name:
            by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

        graph = cls(symbols=by_name, entrypoints=tuple(entrypoints))

        for symbol in symbols:
            resolved: set[str] = set()
            module = symbol.name.rsplit(".", 1)[0]
            for call in symbol.calls:
                short = call.rsplit(".", 1)[-1]
                candidate = f"{module}.{short}"
                if candidate in by_name and candidate != symbol.name:
                    resolved.add(candidate)
                    continue
                matches = by_short.get(short, [])
                if len(matches) == 1 and matches[0] != symbol.name:
                    resolved.add(matches[0])
            graph.edges[symbol.name] = resolved
            for target in resolved:
                graph.reverse_edges.setdefault(target, set()).add(symbol.name)

        return graph

    def callees(self, name: str) -> set[str]:
        return self.edges.get(name, set())

    def callers(self, name: str) -> set[str]:
        return self.reverse_edges.get(name, set())

    def distance_from_entrypoints(self, name: str) -> int | None:
        """Shortest hop count from any entry point, or None if unreachable."""
        if name in self.entrypoints:
            return 0
        seen = set(self.entrypoints)
        queue = deque((entry, 0) for entry in self.entrypoints)
        while queue:
            current, depth = queue.popleft()
            for callee in self.callees(current):
                if callee in seen:
                    continue
                if callee == name:
                    return depth + 1
                seen.add(callee)
                queue.append((callee, depth + 1))
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/codemap/graph.py tests/test_graph.py
git commit -m "feat: call graph with reachability distance from entry points"
```

---

### Task 7: Catalogue des sinks et des sources

**Files:**
- Create: `src/thot/codemap/catalog.py`
- Test: `tests/test_catalog.py`

**Interfaces:**
- Consumes: `Severity`
- Produces:
  - `SinkRule(id: str, patterns: tuple[str, ...], impact: Severity, description: str)`
  - `SourceRule(id: str, patterns: tuple[str, ...], description: str)`
  - `DEFAULT_SINKS: tuple[SinkRule, ...]`, `DEFAULT_SOURCES: tuple[SourceRule, ...]`
  - `match_sink(call_name: str) -> SinkRule | None`
  - `match_source(expression: str) -> SourceRule | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog.py
from thot.codemap.catalog import DEFAULT_SINKS, match_sink, match_source
from thot.contracts import Severity


def test_os_system_is_a_critical_sink():
    rule = match_sink("os.system")
    assert rule is not None
    assert rule.impact == Severity.CRITICAL


def test_bare_call_name_matches_on_the_suffix():
    assert match_sink("system") is not None


def test_unknown_call_is_not_a_sink():
    assert match_sink("json.dumps") is None


def test_sys_argv_is_a_source():
    assert match_source("sys.argv") is not None


def test_every_sink_rule_id_is_unique():
    ids = [rule.id for rule in DEFAULT_SINKS]
    assert len(ids) == len(set(ids))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_catalog.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.codemap.catalog'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/codemap/catalog.py
"""Declarative catalog of dangerous sinks and untrusted sources."""

from __future__ import annotations

from dataclasses import dataclass

from thot.contracts import Severity


@dataclass(frozen=True)
class SinkRule:
    id: str
    patterns: tuple[str, ...]
    impact: Severity
    description: str


@dataclass(frozen=True)
class SourceRule:
    id: str
    patterns: tuple[str, ...]
    description: str


DEFAULT_SINKS: tuple[SinkRule, ...] = (
    SinkRule(
        id="sink.os.system",
        patterns=("os.system", "os.popen"),
        impact=Severity.CRITICAL,
        description="Exécution d'une commande shell",
    ),
    SinkRule(
        id="sink.subprocess.shell",
        patterns=("subprocess.run", "subprocess.call", "subprocess.Popen",
                  "subprocess.check_output", "subprocess.check_call"),
        impact=Severity.CRITICAL,
        description="Lancement d'un sous-processus",
    ),
    SinkRule(
        id="sink.eval",
        patterns=("eval", "exec", "compile"),
        impact=Severity.CRITICAL,
        description="Évaluation de code arbitraire",
    ),
    SinkRule(
        id="sink.deserialization",
        patterns=("pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
                  "dill.loads"),
        impact=Severity.CRITICAL,
        description="Désérialisation de données non fiables",
    ),
    SinkRule(
        id="sink.sql",
        patterns=("execute", "executemany", "executescript"),
        impact=Severity.HIGH,
        description="Exécution d'une requête SQL",
    ),
    SinkRule(
        id="sink.fs.write",
        patterns=("open", "shutil.copy", "shutil.move", "os.remove", "os.unlink",
                  "shutil.rmtree"),
        impact=Severity.MEDIUM,
        description="Accès au système de fichiers",
    ),
    SinkRule(
        id="sink.network",
        patterns=("requests.get", "requests.post", "urllib.request.urlopen",
                  "httpx.get", "httpx.post"),
        impact=Severity.MEDIUM,
        description="Requête réseau sortante",
    ),
)

DEFAULT_SOURCES: tuple[SourceRule, ...] = (
    SourceRule(
        id="source.argv",
        patterns=("sys.argv",),
        description="Arguments de ligne de commande",
    ),
    SourceRule(
        id="source.environ",
        patterns=("os.environ", "os.getenv"),
        description="Variables d'environnement",
    ),
    SourceRule(
        id="source.stdin",
        patterns=("input", "sys.stdin.read", "sys.stdin.readline"),
        description="Entrée standard",
    ),
    SourceRule(
        id="source.http",
        patterns=("request.args", "request.form", "request.json", "request.data",
                  "request.values", "request.get_json"),
        description="Requête HTTP entrante",
    ),
    SourceRule(
        id="source.file",
        patterns=("read", "readline", "readlines"),
        description="Contenu de fichier lu",
    ),
)


def _matches(call_name: str, patterns: tuple[str, ...]) -> bool:
    short = call_name.rsplit(".", 1)[-1]
    for pattern in patterns:
        if call_name == pattern:
            return True
        if pattern.rsplit(".", 1)[-1] == short and "." not in call_name:
            return True
    return False


def match_sink(call_name: str) -> SinkRule | None:
    for rule in DEFAULT_SINKS:
        if _matches(call_name, rule.patterns):
            return rule
    return None


def match_source(expression: str) -> SourceRule | None:
    for rule in DEFAULT_SOURCES:
        if _matches(expression, rule.patterns):
            return rule
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_catalog.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/codemap/catalog.py tests/test_catalog.py
git commit -m "feat: declarative sink and source catalog"
```

---

### Task 8: Propagation de teinte

**Files:**
- Create: `src/thot/taint/__init__.py`, `src/thot/taint/engine.py`
- Test: `tests/test_taint.py`

**Interfaces:**
- Consumes: `CodeGraph`, `Symbol`, `match_sink`, `match_source`, `CodeRef`
- Produces:
  - `TaintCandidate(rule: str, source: CodeRef, sink: CodeRef, path: tuple[CodeRef, ...], impact: Severity, description: str)`
  - `find_candidates(root: Path, graph: CodeGraph, max_depth: int = 3) -> list[TaintCandidate]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_taint.py
from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.scope.detect import detect_scope
from thot.taint.engine import find_candidates


def analyse(repo):
    manifest = detect_scope(repo)
    symbols = []
    for relative in manifest.files:
        symbols.extend(PythonIndexer().index_file(repo, relative))
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return find_candidates(repo, graph)


def test_argv_to_os_system_is_found(toy_repo):
    candidates = analyse(toy_repo)
    rules = {c.rule for c in candidates}
    assert "sink.os.system" in rules


def test_candidate_carries_the_full_path(toy_repo):
    candidate = next(c for c in analyse(toy_repo) if c.rule == "sink.os.system")
    assert len(candidate.path) >= 2
    assert candidate.sink.path == "src/app.py"


def test_clean_file_produces_nothing(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "clean.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []


def test_constant_argument_is_not_tainted(tmp_path):
    (tmp_path / "const.py").write_text(
        "import os\n\n\ndef main():\n    os.system('ls -la')\n"
    )
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "const.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_taint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.taint'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/taint/__init__.py
"""Phase 2 — taint propagation from untrusted sources to dangerous sinks."""
```

```python
# src/thot/taint/engine.py
"""Source-to-sink propagation.

Two levels, both deliberately bounded:

1. Intra-procedural — assignments are followed inside a single function body,
   so `x = sys.argv[1]; os.system(x)` is caught.
2. Inter-procedural — a function whose *parameter* reaches a sink becomes a
   propagator; any caller passing a tainted value into that parameter extends
   the path, up to `max_depth` hops.

Dynamic dispatch, reflection and metaprogramming are out of reach. The result
is incomplete (false negatives), never fabricated: every reported path exists
in the graph.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from thot.codemap.catalog import match_sink, match_source
from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import _called_name
from thot.contracts import CodeRef, Severity, Symbol


@dataclass(frozen=True)
class TaintCandidate:
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


def _function_node(root: Path, symbol: Symbol) -> ast.AST | None:
    try:
        tree = ast.parse((root / symbol.path).read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, OSError):
        return None
    short = symbol.name.rsplit(".", 1)[-1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == short and node.lineno == symbol.lineno:
                return node
    return None


@dataclass
class _BodyAnalysis:
    """What one function body does with tainted data."""

    tainted_from_source: dict[str, CodeRef]      # variable -> where it came from
    sinks_hit: list[tuple[str, CodeRef, str]]    # (rule_id, ref, tainted var name)
    tainted_params: set[str]                     # params that reach a sink
    calls_with_tainted_args: list[tuple[str, int, CodeRef]]


def _analyse_body(symbol: Symbol, node: ast.AST) -> _BodyAnalysis:
    tainted: dict[str, CodeRef] = {}
    sinks_hit: list[tuple[str, CodeRef, str]] = []
    tainted_params: set[str] = set()
    calls_with_tainted_args: list[tuple[str, int, CodeRef]] = []

    # Parameters are potentially tainted — the caller decides.
    param_names = set(symbol.params)

    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            value_name = _expression_name(child.value)
            if value_name and match_source(value_name):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        tainted[target.id] = CodeRef(
                            path=symbol.path, line=child.lineno, symbol=symbol.name
                        )
            elif value_name in tainted:
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        tainted[target.id] = tainted[value_name]
            elif isinstance(child.value, ast.Call):
                called = _called_name(child.value)
                if called:
                    for index, arg in enumerate(child.value.args):
                        arg_name = _expression_name(arg)
                        if arg_name in tainted or arg_name in param_names:
                            calls_with_tainted_args.append(
                                (called, index, CodeRef(
                                    path=symbol.path,
                                    line=child.lineno,
                                    symbol=symbol.name,
                                ))
                            )

        elif isinstance(child, ast.Call):
            called = _called_name(child)
            if not called:
                continue
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name)
            rule = match_sink(called)
            for index, arg in enumerate(child.args):
                arg_name = _expression_name(arg)
                if arg_name is None:
                    continue
                is_tainted_var = arg_name in tainted
                is_param = arg_name in param_names
                if rule and (is_tainted_var or is_param):
                    sinks_hit.append((rule.id, ref, arg_name))
                    if is_param:
                        tainted_params.add(arg_name)
                elif not rule and (is_tainted_var or is_param):
                    calls_with_tainted_args.append((called, index, ref))

    return _BodyAnalysis(
        tainted_from_source=tainted,
        sinks_hit=sinks_hit,
        tainted_params=tainted_params,
        calls_with_tainted_args=calls_with_tainted_args,
    )


def find_candidates(
    root: Path, graph: CodeGraph, max_depth: int = 3
) -> list[TaintCandidate]:
    root = Path(root)
    analyses: dict[str, _BodyAnalysis] = {}
    nodes: dict[str, ast.AST] = {}

    for name, symbol in graph.symbols.items():
        if symbol.kind != "function":
            continue
        node = _function_node(root, symbol)
        if node is None:
            continue
        nodes[name] = node
        analyses[name] = _analyse_body(symbol, node)

    candidates: list[TaintCandidate] = []
    seen: set[tuple[str, str, int]] = set()

    # Case 1 — source and sink inside the same body.
    for name, analysis in analyses.items():
        for rule_id, ref, var in analysis.sinks_hit:
            origin = analysis.tainted_from_source.get(var)
            if origin is None:
                continue
            key = (rule_id, ref.path, ref.line)
            if key in seen:
                continue
            seen.add(key)
            rule = match_sink(rule_id.replace("sink.", "").replace(".", "."))
            impact = _impact_for(rule_id)
            candidates.append(
                TaintCandidate(
                    rule=rule_id,
                    source=origin,
                    sink=ref,
                    path=(origin, ref),
                    impact=impact,
                    description=_description_for(rule_id),
                )
            )

    # Case 2 — a caller feeds a source into a propagator's tainted parameter.
    propagators = {
        name: analysis
        for name, analysis in analyses.items()
        if analysis.tainted_params
    }
    for caller, analysis in analyses.items():
        for called, _index, call_ref in analysis.calls_with_tainted_args:
            short = called.rsplit(".", 1)[-1]
            for target_name, target_analysis in propagators.items():
                if target_name.rsplit(".", 1)[-1] != short:
                    continue
                for rule_id, sink_ref, _var in target_analysis.sinks_hit:
                    origins = list(analysis.tainted_from_source.values())
                    if not origins:
                        continue
                    key = (rule_id, sink_ref.path, sink_ref.line)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(
                        TaintCandidate(
                            rule=rule_id,
                            source=origins[0],
                            sink=sink_ref,
                            path=(origins[0], call_ref, sink_ref),
                            impact=_impact_for(rule_id),
                            description=_description_for(rule_id),
                        )
                    )

    return candidates


def _impact_for(rule_id: str) -> Severity:
    from thot.codemap.catalog import DEFAULT_SINKS

    for rule in DEFAULT_SINKS:
        if rule.id == rule_id:
            return rule.impact
    return Severity.MEDIUM


def _description_for(rule_id: str) -> str:
    from thot.codemap.catalog import DEFAULT_SINKS

    for rule in DEFAULT_SINKS:
        if rule.id == rule_id:
            return rule.description
    return ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_taint.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/taint tests/test_taint.py
git commit -m "feat: intra- and inter-procedural taint propagation"
```

---

### Task 9: Sévérité calculée

**Files:**
- Create: `src/thot/scoring/__init__.py`, `src/thot/scoring/severity.py`
- Test: `tests/test_severity.py`

**Interfaces:**
- Consumes: `Severity`, `Confidence`, `CodeGraph`
- Produces:
  - `accessibility_weight(distance: int | None) -> float`
  - `compute_severity(impact: Severity, distance: int | None, confidence: Confidence) -> Severity`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_severity.py
from thot.contracts import Confidence, Severity
from thot.scoring.severity import accessibility_weight, compute_severity


def test_entrypoint_distance_has_full_weight():
    assert accessibility_weight(0) == 1.0


def test_unreachable_code_is_heavily_discounted():
    assert accessibility_weight(None) < 0.3


def test_critical_and_reachable_stays_critical():
    result = compute_severity(Severity.CRITICAL, 0, Confidence.CONFIRMED)
    assert result == Severity.CRITICAL


def test_critical_but_unreachable_is_downgraded():
    result = compute_severity(Severity.CRITICAL, None, Confidence.PLAUSIBLE)
    assert result in {Severity.LOW, Severity.INFO}


def test_refuted_finding_is_always_info():
    result = compute_severity(Severity.CRITICAL, 0, Confidence.REFUTED)
    assert result == Severity.INFO
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_severity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.scoring'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/scoring/__init__.py
"""Severity computation — never an opinion, always a formula."""
```

```python
# src/thot/scoring/severity.py
"""severity = impact x accessibility x confidence.

Accessibility comes from the call graph, not from a judgement call: a defect
that no entry point can reach is discounted automatically. This is the single
most effective false-positive filter in real audits.
"""

from __future__ import annotations

from thot.contracts import Confidence, Severity

_IMPACT_SCORE = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

_CONFIDENCE_SCORE = {
    Confidence.CONFIRMED: 1.0,
    Confidence.PLAUSIBLE: 0.6,
    Confidence.REFUTED: 0.0,
}


def accessibility_weight(distance: int | None) -> float:
    """Closeness to a public entry point, as a multiplier."""
    if distance is None:
        return 0.2
    if distance == 0:
        return 1.0
    if distance <= 2:
        return 0.8
    return 0.5


def compute_severity(
    impact: Severity, distance: int | None, confidence: Confidence
) -> Severity:
    score = (
        _IMPACT_SCORE[impact]
        * accessibility_weight(distance)
        * _CONFIDENCE_SCORE[confidence]
    )
    if score >= 0.7:
        return Severity.CRITICAL
    if score >= 0.45:
        return Severity.HIGH
    if score >= 0.25:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_severity.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/scoring tests/test_severity.py
git commit -m "feat: computed severity driven by graph reachability"
```

---

### Task 10: Persistance SQLite

**Files:**
- Create: `src/thot/store/__init__.py`, `src/thot/store/db.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `Finding`, `CodeRef`, `Severity`, `Confidence`
- Produces:
  - `Store.open(path: Path) -> Store` (crée le schéma si absent)
  - `store.start_run(root: str, commit: str | None) -> int`
  - `store.save_findings(run_id: int, findings: list[Finding]) -> None`
  - `store.findings_for_run(run_id: int) -> list[Finding]`
  - `store.cached_symbol_hashes() -> dict[str, str]` / `store.remember_symbols(mapping)`
  - `store.close()`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_store.py
from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.store.db import Store


def make_finding(rule="sink.os.system"):
    ref = CodeRef(path="src/app.py", line=10, symbol="src.app.run", ast_hash="abc")
    return Finding(
        id=Finding.compute_id(rule, ref),
        rule=rule,
        severity=Severity.CRITICAL,
        confidence=Confidence.PLAUSIBLE,
        location=ref,
        taint_path=(ref,),
        failure_scenario="argv reaches os.system",
    )


def test_schema_is_created_on_open(tmp_path):
    store = Store.open(tmp_path / "s.db")
    assert store.findings_for_run(1) == []
    store.close()


def test_findings_round_trip(tmp_path):
    store = Store.open(tmp_path / "s.db")
    run_id = store.start_run(root="/repo", commit="deadbeef")
    store.save_findings(run_id, [make_finding()])
    loaded = store.findings_for_run(run_id)
    assert len(loaded) == 1
    assert loaded[0].rule == "sink.os.system"
    assert loaded[0].severity == Severity.CRITICAL
    assert loaded[0].location.line == 10
    store.close()


def test_symbol_cache_round_trips(tmp_path):
    store = Store.open(tmp_path / "s.db")
    store.remember_symbols({"src.app.main": "hash1"})
    assert store.cached_symbol_hashes()["src.app.main"] == "hash1"
    store.close()


def test_saving_the_same_finding_twice_keeps_one_row(tmp_path):
    store = Store.open(tmp_path / "s.db")
    run_id = store.start_run(root="/repo", commit=None)
    store.save_findings(run_id, [make_finding(), make_finding()])
    assert len(store.findings_for_run(run_id)) == 1
    store.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.store'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/store/__init__.py
"""Local persistence: runs, findings, symbol cache."""
```

```python
# src/thot/store/db.py
"""SQLite store. Local, volume-tolerant, never versioned."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL,
    commit_sha TEXT,
    started_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER NOT NULL,
    id TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    symbol TEXT,
    ast_hash TEXT,
    taint_path TEXT NOT NULL DEFAULT '[]',
    failure_scenario TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, id)
);

CREATE TABLE IF NOT EXISTS symbol_cache (
    symbol TEXT PRIMARY KEY,
    ast_hash TEXT NOT NULL
);
"""


class Store:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, path: Path) -> Store:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.executescript(_SCHEMA)
        connection.commit()
        return cls(connection)

    def start_run(self, root: str, commit: str | None) -> int:
        cursor = self._connection.execute(
            "INSERT INTO runs (root, commit_sha) VALUES (?, ?)", (root, commit)
        )
        self._connection.commit()
        return int(cursor.lastrowid)

    def save_findings(self, run_id: int, findings: list[Finding]) -> None:
        rows = [
            (
                run_id,
                f.id,
                f.rule,
                f.severity.value,
                f.confidence.value,
                f.location.path,
                f.location.line,
                f.location.symbol,
                f.location.ast_hash,
                json.dumps([[r.path, r.line, r.symbol] for r in f.taint_path]),
                f.failure_scenario,
            )
            for f in findings
        ]
        self._connection.executemany(
            "INSERT OR REPLACE INTO findings "
            "(run_id, id, rule, severity, confidence, path, line, symbol, "
            " ast_hash, taint_path, failure_scenario) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._connection.commit()

    def findings_for_run(self, run_id: int) -> list[Finding]:
        cursor = self._connection.execute(
            "SELECT id, rule, severity, confidence, path, line, symbol, ast_hash, "
            "taint_path, failure_scenario FROM findings WHERE run_id = ? "
            "ORDER BY severity, path, line",
            (run_id,),
        )
        findings = []
        for row in cursor.fetchall():
            path_entries = json.loads(row[8])
            findings.append(
                Finding(
                    id=row[0],
                    rule=row[1],
                    severity=Severity(row[2]),
                    confidence=Confidence(row[3]),
                    location=CodeRef(
                        path=row[4], line=row[5], symbol=row[6], ast_hash=row[7]
                    ),
                    taint_path=tuple(
                        CodeRef(path=p, line=l, symbol=s) for p, l, s in path_entries
                    ),
                    failure_scenario=row[9],
                )
            )
        return findings

    def remember_symbols(self, mapping: dict[str, str]) -> None:
        self._connection.executemany(
            "INSERT OR REPLACE INTO symbol_cache (symbol, ast_hash) VALUES (?, ?)",
            list(mapping.items()),
        )
        self._connection.commit()

    def cached_symbol_hashes(self) -> dict[str, str]:
        cursor = self._connection.execute("SELECT symbol, ast_hash FROM symbol_cache")
        return dict(cursor.fetchall())

    def close(self) -> None:
        self._connection.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_store.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/store tests/test_store.py
git commit -m "feat: SQLite store for runs, findings and the symbol cache"
```

---

### Task 11: Rapports JSON et Markdown

**Files:**
- Create: `src/thot/report/__init__.py`, `src/thot/report/json_report.py`, `src/thot/report/markdown_report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `Finding`, `ScopeManifest`
- Produces:
  - `render_json(findings, manifest, elapsed: float) -> str`
  - `render_markdown(findings, manifest, elapsed: float) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report.py
import json

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.report.json_report import render_json
from thot.report.markdown_report import render_markdown
from thot.scope.manifest import ScopeManifest


def sample():
    ref = CodeRef(path="src/app.py", line=10, symbol="src.app.run", ast_hash="abc")
    finding = Finding(
        id="deadbeef",
        rule="sink.os.system",
        severity=Severity.CRITICAL,
        confidence=Confidence.PLAUSIBLE,
        location=ref,
        taint_path=(ref,),
        failure_scenario="sys.argv[1] reaches os.system unfiltered",
    )
    manifest = ScopeManifest(
        root="/repo", files=("src/app.py",), languages={"python": 1},
        entrypoints=("src.app.main",), test_command="pytest",
    )
    return [finding], manifest


def test_json_is_parseable_and_carries_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule"] == "sink.os.system"
    assert payload["summary"]["by_severity"]["critical"] == 1


def test_json_never_contains_absolute_paths_in_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert not payload["findings"][0]["location"]["path"].startswith("/")


def test_markdown_has_a_heading_and_the_finding():
    findings, manifest = sample()
    text = render_markdown(findings, manifest, elapsed=1.5)
    assert text.startswith("# ")
    assert "src/app.py:10" in text
    assert "sink.os.system" in text


def test_empty_report_says_so_explicitly():
    _, manifest = sample()
    text = render_markdown([], manifest, elapsed=0.2)
    assert "Aucun" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.report'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/report/__init__.py
"""Phase 8 — rendering. No module here talks to the network or a model."""
```

```python
# src/thot/report/json_report.py
"""Machine-readable report. SARIF export lands in a later milestone."""

from __future__ import annotations

import json

from thot.contracts import Finding, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]


def summarise(findings: list[Finding]) -> dict:
    by_severity = {s.value: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity.value] += 1
    return {"total": len(findings), "by_severity": by_severity}


def render_json(findings: list[Finding], manifest, elapsed: float) -> str:
    payload = {
        "schema_version": 1,
        "scope": {
            "files": len(manifest.files),
            "languages": manifest.languages,
            "entrypoints": list(manifest.entrypoints),
            "test_command": manifest.test_command,
        },
        "summary": summarise(findings),
        "elapsed_seconds": round(elapsed, 3),
        "findings": [
            {
                "id": f.id,
                "rule": f.rule,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "location": {
                    "path": f.location.path,
                    "line": f.location.line,
                    "symbol": f.location.symbol,
                },
                "taint_path": [
                    {"path": r.path, "line": r.line, "symbol": r.symbol}
                    for r in f.taint_path
                ],
                "failure_scenario": f.failure_scenario,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
```

```python
# src/thot/report/markdown_report.py
"""Human-readable report."""

from __future__ import annotations

from thot.contracts import Finding
from thot.report.json_report import SEVERITY_ORDER, summarise


def render_markdown(findings: list[Finding], manifest, elapsed: float) -> str:
    summary = summarise(findings)
    lines = [
        "# Rapport d'audit Thot",
        "",
        f"- Fichiers analysés : **{len(manifest.files)}**",
        f"- Langages : {', '.join(f'{k} ({v})' for k, v in manifest.languages.items()) or '—'}",
        f"- Points d'entrée : **{len(manifest.entrypoints)}**",
        f"- Durée : {elapsed:.2f} s",
        f"- Findings : **{summary['total']}**",
        "",
    ]

    if not findings:
        lines.append("Aucun chemin de teinte détecté sur ce périmètre.")
        lines.append("")
        lines.append(
            "_Analyse déterministe uniquement : l'absence de finding n'est pas une "
            "preuve d'absence de défaut._"
        )
        return "\n".join(lines)

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for finding in sorted(findings, key=lambda f: (order[f.severity], f.location.path)):
        lines.append(f"## `{finding.rule}` — {finding.severity.value.upper()}")
        lines.append("")
        lines.append(f"**Emplacement :** `{finding.location}`")
        if finding.location.symbol:
            lines.append(f"**Symbole :** `{finding.location.symbol}`")
        lines.append(f"**Confiance :** {finding.confidence.value}")
        if finding.failure_scenario:
            lines.append(f"**Scénario :** {finding.failure_scenario}")
        if finding.taint_path:
            lines.append("")
            lines.append("**Chemin :**")
            for step in finding.taint_path:
                lines.append(f"1. `{step}`" + (f" — `{step.symbol}`" if step.symbol else ""))
        lines.append("")

    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_report.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/report tests/test_report.py
git commit -m "feat: JSON and Markdown audit reports"
```

---

### Task 12: Le pipeline de bout en bout

**Files:**
- Create: `src/thot/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: tout ce qui précède
- Produces:
  - `AuditResult(findings: list[Finding], manifest: ScopeManifest, elapsed: float, run_id: int | None)`
  - `run_audit(root: Path, store: Store | None = None) -> AuditResult`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline.py
from thot.contracts import Severity
from thot.pipeline import run_audit
from thot.scope.authorization import write_authorization


def test_end_to_end_finds_the_command_injection(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    rules = {f.rule for f in result.findings}
    assert "sink.os.system" in rules


def test_unauthorized_repo_raises(toy_repo):
    import pytest

    from thot.errors import AuthorizationError

    with pytest.raises(AuthorizationError):
        run_audit(toy_repo)


def test_findings_carry_computed_severity(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    finding = next(f for f in result.findings if f.rule == "sink.os.system")
    assert finding.severity in set(Severity)
    assert finding.failure_scenario


def test_clean_repo_produces_no_findings(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    write_authorization(tmp_path, owner="tester")
    assert run_audit(tmp_path).findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'thot.pipeline'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/pipeline.py
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
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def run_audit(root: Path, store: Store | None = None) -> AuditResult:
    root = Path(root)
    started = time.monotonic()

    load_authorization(root)  # raises AuthorizationError when not mandated
    manifest = detect_scope(root)

    indexer = PythonIndexer()
    symbols = []
    for relative in manifest.files:
        if relative.endswith(".py"):
            symbols.extend(indexer.index_file(root, relative))

    graph = CodeGraph.build(symbols, manifest.entrypoints)
    candidates = find_candidates(root, graph)

    findings: list[Finding] = []
    for candidate in candidates:
        distance = graph.distance_from_entrypoints(candidate.sink.symbol or "")
        severity = compute_severity(
            candidate.impact, distance, Confidence.PLAUSIBLE
        )
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

    elapsed = time.monotonic() - started
    run_id = None
    if store is not None:
        run_id = store.start_run(root=str(root), commit=_git_commit(root))
        store.save_findings(run_id, findings)
        store.remember_symbols({s.name: s.ast_hash for s in symbols})

    return AuditResult(
        findings=findings, manifest=manifest, elapsed=elapsed, run_id=run_id
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_pipeline.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/thot/pipeline.py tests/test_pipeline.py
git commit -m "feat: end-to-end deterministic audit pipeline"
```

---

### Task 13: CLI complet et rendu terminal

**Files:**
- Create: `src/thot/console.py`
- Modify: `src/thot/cli.py`
- Test: `tests/test_cli.py` (ajouts)

**Interfaces:**
- Consumes: `run_audit`, `write_authorization`, `render_json`, `render_markdown`
- Produces:
  - `console.print_report(result) -> None`
  - CLI : `thot init [path] [--owner NAME]`, `thot audit [path] [--json|--markdown] [--out FILE] [--fail-on SEVERITY]`
  - Codes de sortie : `0` rien à signaler, `1` findings au-delà du seuil, `2` usage, `3` refus d'autorisation

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py (ajouts)
import json

from thot import cli
from thot.scope.authorization import write_authorization


def test_init_creates_the_authorization_file(tmp_path, capsys):
    code = cli.main(["init", str(tmp_path), "--owner", "Dev"])
    assert code == 0
    assert (tmp_path / ".thot" / "authorization.yaml").exists()


def test_audit_without_authorization_exits_three(toy_repo, capsys):
    code = cli.main(["audit", str(toy_repo)])
    captured = capsys.readouterr()
    assert code == 3
    assert "autorisation" in (captured.out + captured.err).lower()


def test_audit_json_output_is_valid(toy_repo, capsys):
    write_authorization(toy_repo, owner="tester")
    code = cli.main(["audit", str(toy_repo), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["summary"]["total"] >= 1
    assert code in (0, 1)


def test_fail_on_critical_exits_one(toy_repo):
    write_authorization(toy_repo, owner="tester")
    code = cli.main(["audit", str(toy_repo), "--json", "--fail-on", "low"])
    assert code == 1


def test_out_file_is_written(toy_repo, tmp_path):
    write_authorization(toy_repo, owner="tester")
    target = tmp_path / "report.md"
    cli.main(["audit", str(toy_repo), "--markdown", "--out", str(target)])
    assert "Rapport d'audit Thot" in target.read_text()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `init` n'est pas une sous-commande connue

- [ ] **Step 3: Write minimal implementation**

```python
# src/thot/console.py
"""Terminal rendering. The only module allowed to print."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from thot.contracts import Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

console = Console()


def print_report(result) -> None:
    console.print()
    console.rule("[bold]Thot — rapport d'audit")

    console.print(
        f"[dim]{len(result.manifest.files)} fichiers · "
        f"{len(result.manifest.entrypoints)} points d'entrée · "
        f"{result.elapsed:.2f} s[/dim]"
    )
    console.print()

    if not result.findings:
        console.print("[green]Aucun chemin de teinte détecté.[/green]")
        console.print(
            "[dim]Analyse déterministe uniquement — l'absence de finding "
            "n'est pas une preuve d'absence de défaut.[/dim]"
        )
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Sévérité")
    table.add_column("Règle")
    table.add_column("Emplacement")
    table.add_column("Symbole", overflow="fold")

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    rank = {s: i for i, s in enumerate(order)}
    for finding in sorted(result.findings, key=lambda f: rank[f.severity]):
        table.add_row(
            f"[{_STYLE[finding.severity]}]{finding.severity.value.upper()}[/]",
            finding.rule,
            str(finding.location),
            finding.location.symbol or "—",
        )

    console.print(table)
    console.print()
    console.print(f"[bold]{len(result.findings)}[/bold] finding(s).")
```

```python
# src/thot/cli.py (remplacement complet)
"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from thot import __version__
from thot.contracts import Severity
from thot.errors import AuthorizationError, ThotError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNAUTHORIZED = 3

_SEVERITY_RANK = [
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thot", description="Audit de code adossé à des preuves."
    )
    parser.add_argument("--version", action="version", version=f"thot {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    init = subparsers.add_parser(
        "init", help="Déclarer l'autorisation d'auditer un dépôt"
    )
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--owner", default="", help="Propriétaire du code")

    audit = subparsers.add_parser("audit", help="Auditer un dépôt")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--json", action="store_true", help="Sortie JSON")
    audit.add_argument("--markdown", action="store_true", help="Sortie Markdown")
    audit.add_argument("--out", help="Écrire le rapport dans un fichier")
    audit.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Code de sortie 1 si un finding atteint ce seuil",
    )
    audit.add_argument(
        "--no-store", action="store_true", help="Ne pas persister le run"
    )
    return parser


def _cmd_init(args) -> int:
    from thot.scope.authorization import write_authorization

    owner = args.owner or Path.home().name
    path = write_authorization(Path(args.path), owner=owner)
    print(f"Autorisation écrite : {path}")
    print(f"Propriétaire déclaré : {owner}")
    return EXIT_OK


def _cmd_audit(args) -> int:
    from thot.console import print_report
    from thot.pipeline import run_audit
    from thot.report.json_report import render_json
    from thot.report.markdown_report import render_markdown
    from thot.store.db import Store

    root = Path(args.path).resolve()
    store = None
    if not args.no_store:
        store = Store.open(Path.home() / ".thot" / "store.db")

    try:
        result = run_audit(root, store=store)
    finally:
        if store is not None:
            store.close()

    if args.json:
        rendered = render_json(result.findings, result.manifest, result.elapsed)
    elif args.markdown:
        rendered = render_markdown(result.findings, result.manifest, result.elapsed)
    else:
        rendered = None

    if rendered is not None:
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
            print(f"Rapport écrit : {args.out}")
        else:
            print(rendered)
    else:
        print_report(result)

    if args.fail_on:
        threshold = _SEVERITY_RANK.index(Severity(args.fail_on))
        for finding in result.findings:
            if _SEVERITY_RANK.index(finding.severity) >= threshold:
                return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    try:
        if args.command == "init":
            return _cmd_init(args)
        if args.command == "audit":
            return _cmd_audit(args)
    except AuthorizationError as exc:
        print(f"Refus : {exc}", file=sys.stderr)
        return EXIT_UNAUTHORIZED
    except ThotError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE

    parser.print_help()
    return EXIT_USAGE


def run() -> None:
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/ -v`
Expected: PASS (toute la suite)

- [ ] **Step 5: Commit**

```bash
git add src/thot/cli.py src/thot/console.py tests/test_cli.py
git commit -m "feat: complete CLI with init, audit, output formats and exit codes"
```

---

### Task 14: Garde d'indépendance et README

**Files:**
- Create: `tests/test_no_agent_dependency.py`, `README.md`
- Test: `tests/test_no_agent_dependency.py`

**Interfaces:**
- Consumes: rien
- Produces: garantie exécutable que le noyau reste autonome

- [ ] **Step 1: Write the failing test**

```python
# tests/test_no_agent_dependency.py
"""The core must never depend on Prime Agent or Hermes — that is the whole
point of the Engine port. This test is the executable form of that promise."""

from pathlib import Path

FORBIDDEN = ("import hermes", "from hermes", "import prime", "from prime",
             "pi_coding_agent", "prime_agent")

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "thot"


def test_core_imports_nothing_from_the_agents():
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], f"Le noyau doit rester autonome : {offenders}"


def test_declared_dependencies_stay_minimal():
    pyproject = (SOURCE_ROOT.parents[1] / "pyproject.toml").read_text()
    for forbidden in ("hermes", "prime-agent", "anthropic", "openai"):
        assert forbidden not in pyproject
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_no_agent_dependency.py -v`
Expected: PASS immédiatement si le noyau est propre — c'est un test de garde, pas un test de fonctionnalité. S'il échoue, c'est qu'une tâche précédente a introduit une dépendance interdite : corriger avant de continuer.

- [ ] **Step 3: Write the README**

```markdown
# Thot

Audit de code adossé à des preuves. Analyse déterministe : aucun appel modèle,
aucun réseau, aucune clé API.

## Installation

    uv tool install --from . thot

## Usage

    thot init /chemin/du/repo --owner "Ton Nom"   # autorisation obligatoire
    thot audit /chemin/du/repo                    # rapport dans le terminal
    thot audit . --json --out rapport.json        # export machine
    thot audit . --markdown --out rapport.md      # export lisible
    thot audit . --fail-on high                   # code de sortie 1 en CI

## Ce qu'il fait aujourd'hui

Inventaire du dépôt, graphe d'appels, chemins de teinte source → sink,
sévérité calculée par accessibilité réelle depuis les points d'entrée.
Python uniquement pour l'instant.

## Ce qu'il ne fait pas encore

Vérification adversariale, preuve par repro exécutable, patchs testés,
export SARIF, TypeScript. Voir `docs/superpowers/specs/` et
`docs/superpowers/plans/`.

## Codes de sortie

`0` rien au-delà du seuil · `1` findings au-delà du seuil · `2` usage ·
`3` autorisation refusée
```

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -v`
Expected: PASS, toute la suite

- [ ] **Step 5: Commit**

```bash
git add tests/test_no_agent_dependency.py README.md
git commit -m "test: guard core independence; docs: usage README"
```

---

## Self-Review

**1. Couverture de la spec (périmètre M1+M2 uniquement) :**

| Exigence de la spec | Tâche |
|---|---|
| §6 Phase 0 — scope, recipe, entrypoints | Task 4 |
| §6 Phase 0 — garde-fou d'autorisation | Task 3 |
| §6 Phase 1 — AST, symboles, hash normalisé | Task 5 |
| §6 Phase 1 — graphe d'appels | Task 6 |
| §6 Phase 1 — catalogue sinks/sources | Task 7 |
| §6 Phase 2 — taint intra + inter-procédural borné | Task 8 |
| §7 — contrats de données | Task 2 |
| §8 — sévérité calculée par accessibilité | Task 9 |
| §9 — cache par hash de symbole (fondation) | Task 10 |
| §10 — store SQLite | Task 10 |
| §11 — autorisation, pas de réseau, pas de secrets en clair | Tasks 3, 14 |
| §13 — CLI | Tasks 1, 13 |
| §14 — stack, indépendance du noyau | Tasks 1, 14 |

**Hors périmètre, assumé et documenté dans le README :** churn git (§6 phase 1), OSV,
tree-sitter/TypeScript, réfutation, preuve, patch, SARIF, les trois moteurs. Chacun
relève d'un jalon ultérieur avec son propre plan.

**2. Scan de placeholders :** aucun `TODO`, aucun « similaire à la tâche N », chaque
étape de code porte son code réel.

**3. Cohérence des types :** `CodeRef`, `Symbol`, `Finding`, `ScopeManifest`,
`TaintCandidate`, `CodeGraph`, `Store` — les signatures utilisées dans les tâches 8 à 13
correspondent aux définitions des tâches 2, 4, 5, 6, 10. `Finding.compute_id(rule,
location)` est appelé avec la même signature partout. `run_audit(root, store=None)` est
cohérent entre les tâches 12 et 13.
