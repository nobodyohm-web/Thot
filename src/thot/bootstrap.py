"""Make the terminal able to print what Thot says, before it says anything.

Ported from Hermes Agent's `hermes_bootstrap.py`. Thot's entire interface
is French — accents everywhere — plus box-drawing characters in the report
table. On a Windows console bound to cp1252, `print("réfuté")` raises
UnicodeEncodeError before a single finding is shown.

Windows only. POSIX is left alone on purpose: those systems are already
UTF-8, and overriding `LANG`/`LC_*` that someone set deliberately would be
the same class of mistake in the other direction.

Idempotent, and imported first thing by the entry point.
"""

from __future__ import annotations

import os
import sys

IS_WINDOWS = sys.platform == "win32"
_applied = False


def apply() -> bool:
    """Force UTF-8 for this process and everything it spawns. Returns whether
    anything was changed."""
    global _applied
    if _applied or not IS_WINDOWS:
        return False

    # PEP 540 UTF-8 mode for children: the `claude` CLI, git, pytest, and
    # anything else Thot runs inherits these and stops guessing cp1252.
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass  # a redirected stream that refuses is not fatal

    _applied = True
    return True
