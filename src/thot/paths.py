"""Where Thot keeps things, in one place.

Ported from Hermes Agent's `hermes_constants.get_hermes_home`. Everything
Thot writes lives under one directory so it can be moved, backed up, or
thrown away as a unit — and so a test never touches the real one.

``THOT_HOME`` relocates all of it. Read on every call, never cached: a test
that sets it mid-run must be obeyed, and the cost is a dictionary lookup.
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "THOT_HOME"
DIRNAME = ".thot"


def home() -> Path:
    """The root of Thot's own state. Created on demand, never at import."""
    override = os.environ.get(HOME_ENV, "").strip()
    return Path(override).expanduser() if override else Path.home() / DIRNAME


def ensure_home() -> Path:
    directory = home()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def config_file() -> Path:
    return home() / "config.json"


def run_store() -> Path:
    """Findings per run: disposable evidence."""
    return home() / "store.db"


def memory_db() -> Path:
    """Verdicts: reviewed judgement, outliving any checkout."""
    return home() / "memory.db"


def sessions_db() -> Path:
    """Conversations and the audits that happened inside them."""
    return home() / "sessions.db"


def history_file() -> Path:
    return home() / "history"


def schedule_file() -> Path:
    return home() / "schedule.json"


def mcp_file() -> Path:
    return home() / "mcp.json"


def log_file(name: str) -> Path:
    return home() / f"{name}.log"


def user_dir(kind: str) -> Path:
    """``skills``, ``plugins``, ``rules`` — what you carry between repos."""
    return home() / kind
