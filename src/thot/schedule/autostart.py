"""Bring the session scheduler back after a reboot.

The scheduler has to be started from a user session — that is the whole
reason it exists, since launchd is refused the guarded folders. Nothing
starts a user session automatically, so the scheduler dies with the machine
and the loop is permanent only until the next restart.

A line in the shell's startup file closes that gap: the first terminal
opened after a reboot revives the scheduler, with that session's access.
The check in front of it is pure shell and reads one file, so a shell that
finds the scheduler alive — every shell but the first — pays nothing.

Bounded by markers and removable, because a tool that edits a startup file
owes the reader an obvious way to undo it.
"""

from __future__ import annotations

import os
from pathlib import Path

OPEN = "# >>> thot — planificateur de session >>>"
CLOSE = "# <<< thot <<<"

BODY = """\
# macOS refuse Desktop/Documents/Downloads à un agent launchd, donc le
# planificateur d'audits ne peut démarrer que depuis une session. Ce test
# ne lit qu'un fichier : seul le premier terminal après un démarrage paie
# quelque chose. `THOT_NO_AUTOSTART=1` le désactive sans rien modifier.
if [ -z "${THOT_NO_AUTOSTART:-}" ] && \\
   ! kill -0 "$(cat "$HOME/.thot/scheduler.pid" 2>/dev/null)" 2>/dev/null; then
  (command -v thot >/dev/null 2>&1 && thot schedule start >/dev/null 2>&1 &)
fi"""


def block() -> str:
    return f"{OPEN}\n{BODY}\n{CLOSE}"


def installed(text: str) -> bool:
    return OPEN in text


def install_into(text: str) -> str:
    """Add the block, or replace the one already there.

    Replacing rather than skipping: an older Thot may have written an older
    line, and leaving it would mean the fix shipped today never reaches the
    people who installed yesterday.
    """
    if installed(text):
        text = remove_from(text)
    separator = "" if text.endswith("\n") or not text else "\n"
    return f"{text}{separator}\n{block()}\n"


def remove_from(text: str) -> str:
    """Take the block out, leaving the rest byte for byte as it was."""
    if OPEN not in text:
        return text
    head, _, rest = text.partition(OPEN)
    _, _, tail = rest.partition(CLOSE)
    return (head.rstrip("\n") + "\n" + tail.lstrip("\n")).lstrip("\n") \
        if head.strip() else tail.lstrip("\n")


def startup_file(shell: str | None = None, home: Path | None = None) -> Path:
    """The startup file of the shell that will actually run it."""
    home = Path(home or Path.home())
    name = Path(shell or os.environ.get("SHELL", "/bin/zsh")).name
    if name == "bash":
        profile = home / ".bash_profile"
        return profile if profile.exists() else home / ".bashrc"
    if name == "fish":
        return home / ".config" / "fish" / "config.fish"
    return home / ".zshrc"
