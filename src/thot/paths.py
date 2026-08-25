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
    """The directory, private. `mode=` is not weakened by the umask.

    0700 on the directory rather than on each file: what lives here is
    `sessions.db` (whole conversations, so excerpts of the audited code and
    anything pasted into a prompt), `store.db` (where the findings of every
    audited repository are), and `memory.db` — plus the files nobody would
    think to enumerate, the `-wal`, the logs, `journal.jsonl`. The directory
    covers all of them, including the ones added later.
    """
    directory = home()
    existed = directory.exists()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if existed:
        # `mode=` is ignored for a directory that is already there, so homes
        # created before this are migrated — but only ours, and only when the
        # bits actually differ. This sits on the hot path of nearly every
        # command, and a chmod that raises on a THOT_HOME belonging to someone
        # else would take all of them down.
        try:
            state = os.stat(directory)
            if state.st_uid == os.getuid() and state.st_mode & 0o077:
                os.chmod(directory, 0o700)
        except (OSError, AttributeError):
            # AttributeError: no `getuid` on Windows, where these bits mean
            # nothing — and this function must not be the reason a command
            # cannot start.
            pass
    return directory


def _under_home(name: str) -> Path:
    """A path inside the home, with the home itself already private.

    The directory is made here, by the accessor, rather than left to whoever
    writes first. Seven writers create it themselves with a bare
    `path.parent.mkdir(parents=True, exist_ok=True)` — `memory/sqlite.py`,
    `state/store.py`, `session.py`, `harness.py`, `logs.py` and two more —
    and a bare mkdir takes the umask: measured, `thot doctor` on a fresh
    HOME left `~/.thot` at 0755 without ever reaching `ensure_home()`.
    Asking for one of these paths is what someone does before writing to it,
    so it is a place the directory can be settled once and settled right.

    Cheap enough to be unconditional: measured over a full `thot audit .` on
    this repository, every accessor here is called fewer than ten times in
    the whole run.
    """
    return ensure_home() / name


def config_file() -> Path:
    return _under_home("config.json")


def run_store() -> Path:
    """Findings per run: disposable evidence."""
    return _under_home("store.db")


def memory_db() -> Path:
    """Verdicts: reviewed judgement, outliving any checkout."""
    return _under_home("memory.db")


def sessions_db() -> Path:
    """Conversations and the audits that happened inside them."""
    return _under_home("sessions.db")


def history_file() -> Path:
    return _under_home("history")


def schedule_file() -> Path:
    return _under_home("schedule.json")


def log_file(name: str) -> Path:
    return _under_home(f"{name}.log")


def user_dir(kind: str) -> Path:
    """``skills``, ``plugins``, ``rules`` — what you carry between repos."""
    return _under_home(kind)
