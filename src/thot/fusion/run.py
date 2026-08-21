"""Run Hermes or Prime from Thot, without pretending to be either.

The arguments are handed over untouched and the child keeps the terminal:
both are interactive programs with their own prompts, their own key
handling and their own output. Wrapping that in a translation layer would
mean maintaining a second, worse copy of two command lines that already
work. Thot dispatches; the program answers for itself.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from thot.fusion.locate import (
    hermes_command,
    hermes_root,
    prime_command,
    prime_root,
)


class NotAvailable(RuntimeError):
    """The program is not here, or not built. Say which, and what to do."""


def _hermes() -> list[str]:
    command = hermes_command()
    if command is not None:
        return command
    if hermes_root() is None:
        raise NotAvailable(
            "Hermes n'est pas dans cette installation.\n"
            "   Il vit dans `hermes/` d'un checkout de Thot, ou pointe "
            "THOT_HERMES_ROOT vers le tien."
        )
    raise NotAvailable(
        "Hermes est présent mais pas installé.\n"
        "   Lance `uv sync` à la racine du dépôt : c'est un membre du workspace."
    )


def _prime() -> list[str]:
    command = prime_command()
    if command is not None:
        return command
    root = prime_root()
    if root is None:
        raise NotAvailable(
            "Prime n'est pas dans cette installation.\n"
            "   Il vit dans `prime/` d'un checkout de Thot, ou pointe "
            "THOT_PRIME_ROOT vers le tien."
        )
    if not _node_present():
        raise NotAvailable(
            "Prime est écrit en TypeScript et Node est introuvable.\n"
            "   Installe Node 20+, puis `npm install && npm run build` dans prime/."
        )
    raise NotAvailable(
        "Prime est présent mais pas compilé.\n"
        f"   cd {root} && npm install && npm run build"
    )


def _node_present() -> bool:
    import shutil

    return shutil.which("node") is not None


def _exec(command: list[str], arguments: list[str], *, cwd: Path | None = None) -> int:
    """Hand the terminal over and return the child's exit code."""
    environment = dict(os.environ)
    # So a program launched from Thot can tell, and so a crash report says
    # where it was started from. It changes nothing about how it runs.
    environment["THOT_FUSION"] = "1"
    try:
        done = subprocess.run(
            [*command, *arguments],
            cwd=str(cwd) if cwd else None,
            env=environment,
            check=False,
        )
    except OSError as exc:
        print(f"Impossible de lancer : {exc}", file=sys.stderr)
        return 1
    return done.returncode


def run_hermes(arguments: list[str]) -> int:
    return _exec(_hermes(), arguments)


def run_prime(arguments: list[str]) -> int:
    # Prime resolves its workspace packages relative to its own tree, but the
    # project it works on is wherever the user stands. The command line runs
    # from the user's directory; the entry point is absolute.
    return _exec(_prime(), arguments)
