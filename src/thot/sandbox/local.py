"""The host. What Thot has always done, now with a name.

Naming it matters: a user who has not chosen a sandbox should be able to
see that the answer is "none", rather than discovering it when a
repository's test suite writes to their home directory.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from thot.sandbox.base import DEFAULT_TIMEOUT, Result

# A command's output is read from the bottom: the traceback, the assertion,
# the summary line. Prime Agent's limits, applied to the tail.
MAX_OUTPUT_LINES = 400
MAX_OUTPUT_BYTES = 24_000


def clip(text: str) -> str:
    """Keep the end of a command's output, and say what was dropped."""
    from thot.output import truncate_tail

    cut = truncate_tail(text.strip(), max_lines=MAX_OUTPUT_LINES,
                        max_bytes=MAX_OUTPUT_BYTES)
    return cut.rendered(tail=True)


@dataclass
class LocalSandbox:
    root: Path
    name: str = "local"

    def available(self) -> tuple[bool, str]:
        return True, ""

    def describe(self) -> str:
        return "aucune isolation — la commande tourne sous ton compte"

    def run(self, command: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        try:
            done = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=str(self.root), check=False,
            )
        except subprocess.TimeoutExpired:
            return Result(124, f"Commande interrompue après {timeout} s.",
                          sandbox=self.name, timed_out=True)
        return Result(done.returncode, clip(done.stdout + done.stderr),
                      sandbox=self.name)
