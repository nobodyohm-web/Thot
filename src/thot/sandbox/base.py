"""Where a command runs, and what it can reach from there.

Thot's `run_command` executes on the host. For an assistant working on
your own code that is correct and convenient. For an auditor, it is the
one place the whole design leaks: auditing a repository means reading code
someone else wrote, and `pytest` on a hostile repository is that code
running as you.

The port from Hermes Agent's `tools/environments/` keeps two of its eleven
environments — local and docker — because those are the two that answer
this question. The rest (Modal, Daytona, Vercel, Singularity, SSH) exist
to give an assistant more machine; Thot needs less.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# A test suite can be slow; a hostile one can be endless.
DEFAULT_TIMEOUT = 120


class SandboxError(RuntimeError):
    """The sandbox could not run the command, and did not fall back."""


@dataclass(frozen=True)
class Result:
    exit_code: int
    output: str
    sandbox: str = "local"
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@runtime_checkable
class Sandbox(Protocol):
    name: str

    def available(self) -> tuple[bool, str]:
        """(usable, why not). The reason is shown to the user, never swallowed."""

    def run(self, command: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        """Execute one shell command against the repository."""

    def describe(self) -> str:
        """One line saying what this isolation actually buys."""
