"""Where the three programs are, and whether each one can actually run.

A checkout carries all three. A wheel carries only Thot — the other two are
whole programs with their own toolchains, and vendoring them into a Python
wheel would be a lie about what got installed. So every answer here is
optional, and the absence of a part is reported, never guessed around.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERMES_DIRNAME = "hermes"
PRIME_DIRNAME = "prime"

# Env overrides exist for the case the layout cannot cover: a user who keeps
# Hermes checked out elsewhere and does not want a second copy.
HERMES_ENV = "THOT_HERMES_ROOT"
PRIME_ENV = "THOT_PRIME_ROOT"


@dataclass(frozen=True)
class Part:
    """One of the three programs, and what is true about it right now."""

    name: str
    root: Path | None
    version: str = ""
    ready: bool = False
    detail: str = ""

    def line(self) -> str:
        mark = "✓" if self.ready else "·"
        where = str(self.root) if self.root else "absent"
        version = f" {self.version}" if self.version else ""
        detail = f" — {self.detail}" if self.detail else ""
        return f"{mark} {self.name}{version}  {where}{detail}"


def repo_root() -> Path:
    """The checkout that holds `src/thot`, or the install directory."""
    return Path(__file__).resolve().parents[3]


def _override(variable: str) -> Path | None:
    """What the user pointed at — even when it turns out to be nothing.

    Returning None for a path that does not exist would send the caller back
    to the bundled copy: the user asks for their own checkout, gets a
    different one, and nothing on screen says so. An override that cannot be
    honoured has to surface as an absence, not as a substitution.
    """
    raw = os.environ.get(variable, "").strip()
    return Path(raw).expanduser() if raw else None


def _rooted(override: Path | None, dirname: str, marker: str) -> Path | None:
    # The marker file, not the directory: an empty `hermes/` left behind by a
    # failed checkout must not read as a working Hermes.
    candidate = override if override is not None else repo_root() / dirname
    return candidate if (candidate / marker).is_file() else None


def hermes_root() -> Path | None:
    return _rooted(_override(HERMES_ENV), HERMES_DIRNAME, "pyproject.toml")


def prime_root() -> Path | None:
    return _rooted(_override(PRIME_ENV), PRIME_DIRNAME, "package.json")


def _bindir(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def _executable(directory: Path, name: str) -> Path | None:
    candidate = directory / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def hermes_command() -> list[str] | None:
    """The entry point that runs the Hermes `hermes_root()` names, or nothing.

    PATH is not a candidate. It used to be the second try, right after
    `sys.executable`'s own directory — and Thot is normally installed as a uv
    tool, whose interpreter has no `hermes` beside it. So on any machine
    where Hermes was also installed the ordinary way, PATH won: `thot fusion`
    printed `✓ hermes  <checkout>/hermes` and `thot hermes` ran
    `~/.hermes/hermes-agent`, a different tree with a different version.

    The two candidates that do not name the root — the interpreter's own
    directory and the checkout's venv — are tried only while the root *is*
    the bundled tree. `hermes` is a workspace member, so every environment
    that installs Thot puts a `hermes` script beside `sys.executable`, and it
    would win over `THOT_HERMES_ROOT` in the one case that variable exists
    for: the same two trees on one line again, spelt differently.

    Announcing one tree and running another is worse than reporting none, so
    the last resort is Hermes's own launcher under the current interpreter:
    it runs the right code (flat layout, so `sys.path[0]` beats site-packages)
    and says so when the dependencies are missing. For an overridden root
    there is no last resort after that — `-m hermes_cli.main` would import
    the installed `hermes_cli`, which is precisely the other tree.
    """
    root = hermes_root()
    if root is None:
        return None
    bundled = root.resolve() == (repo_root() / HERMES_DIRNAME).resolve()
    directories: list[Path] = []
    if bundled:
        directories += [
            Path(sys.executable).parent,     # a workspace: one env for both
            _bindir(repo_root() / ".venv"),  # the checkout's own venv
        ]
    directories += [
        _bindir(root / "venv"),   # Hermes installed under itself
        _bindir(root / ".venv"),  # …and the way a recent checkout spells it
    ]
    for directory in directories:
        script = _executable(directory, "hermes")
        if script is not None:
            return [str(script)]
    launcher = root / "hermes"
    if launcher.is_file():
        return [sys.executable, str(launcher)]
    if not bundled:
        return None
    # Importable but not installed: the module entry point still works.
    return [sys.executable, "-m", "hermes_cli.main"]


def hermes_python() -> Path | None:
    """The interpreter that will run Hermes, or nothing when it cannot be told.

    A different question from `hermes_command()`, and the fusion depends on
    the difference. Half of what wiring buys — Hermes gaining `code_map`,
    `find_symbol`, `callers` — needs the MCP SDK importable *by the
    interpreter that runs Hermes*, which is not Thot's own: `thot` is
    documented as a uv tool install, with its own environment, and the
    console script it hands back names its interpreter on its first line.

    `#!/usr/bin/env python3` names the finder rather than the interpreter,
    and guessing which `python3` that resolves to would be inventing an
    answer. Nothing is returned instead, so the caller can say it does not
    know rather than say no.
    """
    command = hermes_command()
    if not command:
        return None
    if len(command) > 1:
        return Path(command[0])  # already an interpreter: [python, -m, …]
    try:
        with Path(command[0]).open("rb") as handle:
            first_line = handle.readline(512)
    except OSError:
        return None
    if not first_line.startswith(b"#!"):
        return None
    named = first_line[2:].strip().decode("utf-8", "replace").split()
    if not named or named[0].rsplit("/", 1)[-1] == "env":
        return None
    return Path(named[0])


def prime_entry() -> Path | None:
    """Prime's built CLI. None when the TypeScript has not been compiled."""
    root = prime_root()
    if root is None:
        return None
    built = root / "packages" / "coding-agent" / "dist" / "cli.js"
    return built if built.is_file() else None


def prime_command() -> list[str] | None:
    entry = prime_entry()
    if entry is None:
        return None
    node = shutil.which("node")
    if node is None:
        return None
    return [node, str(entry)]


def _probe(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        done = subprocess.run(
            [*command, "--version"], capture_output=True, text=True,
            timeout=60, cwd=str(cwd) if cwd else None, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (done.stdout or done.stderr).strip().splitlines()[0] if done.stdout or done.stderr else ""


def _thot_part() -> Part:
    from thot import __version__

    return Part(name="thot", root=repo_root(), version=__version__, ready=True,
                detail="audit déterministe, carte du code, mémoire des verdicts")


def _hermes_part(probe: bool) -> Part:
    root = hermes_root()
    if root is None:
        return Part(name="hermes", root=None,
                    detail=f"absent — attendu dans {repo_root() / HERMES_DIRNAME}")
    command = hermes_command()
    if command is None:
        return Part(name="hermes", root=root,
                    detail="présent mais non installé — `uv sync` à la racine")
    version = _probe(command) if probe else ""
    return Part(name="hermes", root=root, version=version.split(" (")[0] if version else "",
                ready=True, detail="agent, outils, passerelles, plugins")


def _prime_part(probe: bool) -> Part:
    root = prime_root()
    if root is None:
        return Part(name="prime", root=None,
                    detail=f"absent — attendu dans {repo_root() / PRIME_DIRNAME}")
    if shutil.which("node") is None:
        return Part(name="prime", root=root,
                    detail="Node introuvable — Prime est écrit en TypeScript")
    if prime_entry() is None:
        return Part(name="prime", root=root,
                    detail="non compilé — `npm install && npm run build` dans prime/")
    version = _probe(prime_command() or [], cwd=root) if probe else ""
    return Part(name="prime", root=root, version=version, ready=True,
                detail="agent de code, fournisseurs de modèles, TUI")


def parts(*, probe: bool = True) -> list[Part]:
    """The state of the three programs. `probe=False` skips running them."""
    return [_thot_part(), _hermes_part(probe), _prime_part(probe)]
