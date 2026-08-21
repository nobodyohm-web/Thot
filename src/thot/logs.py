"""One place to look when something went wrong while nobody was watching.

Ported in shape from Hermes Agent's `hermes_logging.py`, reduced to what a
local audit tool needs: one rotating file under `~/.thot/logs/`, and a
console handler that only speaks up for warnings.

The reason this exists at all: a scheduled audit runs at 03:00 and a
gateway daemon runs for days. When either misbehaves, "nothing on screen"
was previously the whole diagnostic.

Never on by default for the interactive session — that terminal is the
user's, and Thot's own chatter belongs in a file.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from thot.paths import home

DIRNAME = "logs"
FILENAME = "thot.log"
MAX_BYTES = 5 * 1024 * 1024
BACKUPS = 3
FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

_configured = False


def log_dir() -> Path:
    return home() / DIRNAME


def setup(*, mode: str = "cli", level: int = logging.INFO,
          console: bool = False, force: bool = False) -> Path | None:
    """Configure logging once. Returns the file being written, if any.

    A directory that cannot be created costs the log file, not the run —
    a read-only home is a reason to run without logs, not to refuse to
    audit.
    """
    global _configured
    if _configured and not force:
        return log_dir() / FILENAME

    root = logging.getLogger("thot")
    root.setLevel(level)
    root.propagate = False
    for handler in list(root.handlers):
        root.removeHandler(handler)

    target: Path | None = None
    try:
        directory = log_dir()
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / FILENAME
        file_handler = logging.handlers.RotatingFileHandler(
            target, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(FORMAT))
        file_handler.setLevel(level)
        root.addHandler(file_handler)
    except OSError:
        target = None

    if console:
        stream = logging.StreamHandler()
        stream.setLevel(logging.WARNING)
        stream.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        root.addHandler(stream)

    if not root.handlers:
        root.addHandler(logging.NullHandler())

    _configured = True
    root.debug("journalisation démarrée (%s)", mode)
    return target


def get(name: str) -> logging.Logger:
    """A logger under the `thot` tree, so one switch controls all of them."""
    return logging.getLogger(f"thot.{name}")
