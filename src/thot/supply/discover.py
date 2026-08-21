"""Find what a repository depends on, and at which exact version.

Ported in intent from Hermes Agent's `hermes_cli/security_audit.py`, with
the surface moved: Hermes scans its own venv, its own plugins and its own
MCP config, because it is auditing the machine it runs on. Thot scans the
**repository under audit**, because that is the code whose supply chain is
the question.

Lockfiles first, always. A manifest says `requests>=2` and OSV cannot
answer a range; a lockfile says `2.31.0` and OSV can. Where both exist the
lockfile wins, and a dependency that is only ever expressed as a range is
reported as unpinned rather than guessed at.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

PYPI = "PyPI"
NPM = "npm"

# Lockfiles, in the order they are trusted when several are present.
LOCKFILES = (
    ("uv.lock", PYPI),
    ("poetry.lock", PYPI),
    ("Pipfile.lock", PYPI),
    ("package-lock.json", NPM),
    ("yarn.lock", NPM),
    ("pnpm-lock.yaml", NPM),
)

MANIFESTS = (
    ("requirements.txt", PYPI),
    ("requirements-dev.txt", PYPI),
    ("pyproject.toml", PYPI),
    ("package.json", NPM),
)

_PINNED = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#\[]*)")
_YARN_ENTRY = re.compile(r'^"?([^@\s"][^@\s"]*)@[^\n]*:\s*$')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_PNPM_ENTRY = re.compile(r"^\s{2}/?(@?[^@\s/][^@\s]*)[@/]([0-9][^:\s(]*)")

# `npx -y @scope/pkg@1.2.3` and `uvx pkg==1.2.3`, the two shapes an MCP
# server declaration takes when it pins anything at all.
_NPX_PIN = re.compile(r"^(@?[A-Za-z0-9._\-/]+)@([0-9][A-Za-z0-9.\-+]*)$")
_UVX_PIN = re.compile(r"^([A-Za-z0-9._\-]+)==([0-9][A-Za-z0-9.\-+]*)$")


@dataclass(frozen=True)
class Component:
    """One dependency, pinned, and where the repository says so."""

    name: str
    version: str
    ecosystem: str
    source: str  # repo-relative path of the file that pinned it
    line: int = 0

    def label(self) -> str:
        return f"{self.name}=={self.version}" if self.ecosystem == PYPI \
            else f"{self.name}@{self.version}"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# -- Python ------------------------------------------------------------------


def parse_requirements(text: str, source: str) -> list[Component]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = _PINNED.match(line)
        if match:
            found.append(Component(match.group(1).lower(), match.group(2),
                                   PYPI, source, number))
    return found


def parse_uv_lock(text: str, source: str) -> list[Component]:
    """uv and poetry both write TOML with a `[[package]]` array."""
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    found = []
    for entry in data.get("package") or []:
        name, version = entry.get("name"), entry.get("version")
        if name and version:
            found.append(Component(str(name).lower(), str(version), PYPI, source))
    return found


def parse_pipfile_lock(text: str, source: str) -> list[Component]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found = []
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            version = str((entry or {}).get("version") or "").lstrip("=")
            if version:
                found.append(Component(str(name).lower(), version, PYPI, source))
    return found


def parse_pyproject(text: str, source: str) -> list[Component]:
    """Only the pins. A range is not a version and must not be guessed."""
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    declared = list((data.get("project") or {}).get("dependencies") or [])
    for group in ((data.get("dependency-groups") or {}).values()):
        if isinstance(group, list):
            declared += [item for item in group if isinstance(item, str)]
    return parse_requirements("\n".join(declared), source)


# -- JavaScript --------------------------------------------------------------


def parse_package_lock(text: str, source: str) -> list[Component]:
    try:
        data = json.loads(text)
    except ValueError:
        return []

    found: list[Component] = []
    # npm v7+ uses "packages", keyed by install path; v6 uses "dependencies".
    for path, entry in (data.get("packages") or {}).items():
        if not path or not isinstance(entry, dict):
            continue  # "" is the project itself
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if name and version:
            found.append(Component(str(name), str(version), NPM, source))

    def walk(node: dict) -> None:
        for name, entry in (node or {}).items():
            if isinstance(entry, dict) and entry.get("version"):
                found.append(Component(str(name), str(entry["version"]), NPM, source))
                walk(entry.get("dependencies") or {})

    if not found:
        walk(data.get("dependencies") or {})
    return found


def parse_yarn_lock(text: str, source: str) -> list[Component]:
    found: list[Component] = []
    name = ""
    for line in text.splitlines():
        entry = _YARN_ENTRY.match(line)
        if entry:
            name = entry.group(1)
            continue
        version = _YARN_VERSION.match(line)
        if version and name:
            found.append(Component(name, version.group(1), NPM, source))
            name = ""
    return found


def parse_pnpm_lock(text: str, source: str) -> list[Component]:
    found = []
    for line in text.splitlines():
        match = _PNPM_ENTRY.match(line)
        if match:
            found.append(Component(match.group(1), match.group(2), NPM, source))
    return found


def parse_package_json(text: str, source: str) -> list[Component]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = str(spec or "")
            if re.fullmatch(r"[0-9][0-9A-Za-z.\-+]*", version):  # an exact pin
                found.append(Component(str(name), version, NPM, source))
    return found


PARSERS = {
    "uv.lock": parse_uv_lock,
    "poetry.lock": parse_uv_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "requirements.txt": parse_requirements,
    "requirements-dev.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
}


def from_mcp_command(server: str, command: str, args) -> Component | None:
    """A pinned package behind an MCP server declaration, or nothing.

    Ported from Hermes Agent's `_extract_mcp_component`, including its
    refusal to guess: a local path, a Docker image or an unpinned `npx -y
    thing` returns None. An audit that invents a version is worse than an
    audit that stays quiet about one entry.
    """
    binary = (command or "").strip().lower()
    tokens = [str(a) for a in (args or [])]
    if not tokens:
        return None

    if binary.endswith("npx"):
        pattern, ecosystem = _NPX_PIN, NPM
    elif binary.endswith("uvx"):
        pattern, ecosystem = _UVX_PIN, PYPI
    else:
        return None

    for token in tokens:
        if token.startswith("-"):
            continue
        match = pattern.match(token)
        if match:
            return Component(match.group(1), match.group(2), ecosystem,
                             f"mcp:{server}")
        return None  # the first non-flag token is the package, pinned or not
    return None


def discover(root: Path | str) -> list[Component]:
    """Every pinned dependency this repository declares, deduplicated.

    Lockfiles are read first; a manifest only contributes what no lockfile
    already pinned, so `requirements.txt` next to `uv.lock` does not double
    every package.
    """
    root = Path(root)
    found: dict[tuple[str, str, str], Component] = {}
    from_lock: set[tuple[str, str]] = set()

    for filename, ecosystem in LOCKFILES:
        path = root / filename
        if not path.is_file():
            continue
        for component in PARSERS[filename](_read(path), filename):
            found.setdefault(
                (component.ecosystem, component.name, component.version), component
            )
            from_lock.add((component.ecosystem, component.name))

    for filename, ecosystem in MANIFESTS:
        path = root / filename
        if not path.is_file():
            continue
        for component in PARSERS[filename](_read(path), filename):
            if (component.ecosystem, component.name) in from_lock:
                continue
            found.setdefault(
                (component.ecosystem, component.name, component.version), component
            )

    return sorted(found.values(), key=lambda c: (c.ecosystem, c.name, c.version))
