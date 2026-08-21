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


def _venv_script(name: str) -> Path | None:
    """A console script from the interpreter running Thot.

    Resolved next to `sys.executable` before falling back to PATH: in a
    workspace the two programs share one environment, and picking up some
    other Hermes from PATH would run a different install than the one this
    checkout builds.
    """
    here = Path(sys.executable).parent / name
    if here.is_file() and os.access(here, os.X_OK):
        return here
    found = shutil.which(name)
    return Path(found) if found else None


def hermes_command() -> list[str] | None:
    script = _venv_script("hermes")
    if script is not None:
        return [str(script)]
    if hermes_root() is None:
        return None
    # Importable but not installed: the module entry point still works.
    return [sys.executable, "-m", "hermes_cli.main"]


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
