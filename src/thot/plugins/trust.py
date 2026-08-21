"""Which repository plugins may be executed, and on whose say-so.

Thot already screens the two things a repository can hand it as *text*: its
skills and its commands. A plugin is the one thing it hands over as *code* —
loading it runs the module body under the user's account — and it was the
only one loaded without a question. That asymmetry is the reason this file
exists: the strictest treatment belongs to the only executable category.

Screening a plugin the way a skill is screened would be theatre. Nobody can
read a Python package with a regular expression and pronounce it harmless.
So the rule here is not "does it look safe" but "did a human say yes to
exactly these bytes" — and the fingerprint is what makes the second half of
that sentence true after an update.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path

from thot.paths import ensure_home, home

TRUST_FILENAME = "trusted-plugins.json"

# Compiled bytecode is derived, not authored; hashing it would revoke trust
# the first time Python wrote a cache file next to the source.
IGNORED_DIRS = frozenset({"__pycache__", ".git"})


def trust_file() -> Path:
    return home() / TRUST_FILENAME


def fingerprint(folder: Path) -> str:
    """A digest of everything in the plugin, path and content alike.

    Renaming a file changes the answer as surely as editing one: an import
    reads the whole directory, so the whole directory is what was approved.
    """
    digest = hashlib.sha256()
    folder = Path(folder)
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        if IGNORED_DIRS.intersection(path.relative_to(folder).parts):
            continue
        digest.update(str(path.relative_to(folder)).encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<illisible>")
        digest.update(b"\0")
    return digest.hexdigest()


def entries() -> dict[str, dict]:
    try:
        data = json.loads(trust_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict[str, dict]) -> Path:
    ensure_home()
    path = trust_file()
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path


def status(folder: Path) -> str:
    """``"trusted"``, ``"changed"`` or ``"unknown"`` — the three real cases.

    ``changed`` is deliberately not the same answer as ``unknown``: a plugin
    that was approved and then edited is worth saying out loud, because that
    is what a supply-chain update looks like from here.
    """
    record = entries().get(str(Path(folder).resolve()))
    if not isinstance(record, dict):
        return "unknown"
    return "trusted" if record.get("digest") == fingerprint(folder) else "changed"


def is_trusted(folder: Path) -> bool:
    return status(folder) == "trusted"


def trust(folder: Path) -> str:
    """Record approval of the plugin's current content. Returns the digest."""
    folder = Path(folder).resolve()
    digest = fingerprint(folder)
    data = entries()
    data[str(folder)] = {
        "digest": digest,
        "date": _dt.date.today().isoformat(),
    }
    _save(data)
    return digest


def revoke(folder: Path) -> bool:
    data = entries()
    if data.pop(str(Path(folder).resolve()), None) is None:
        return False
    _save(data)
    return True
