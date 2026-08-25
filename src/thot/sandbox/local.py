"""The host. What Thot has always done, now with a name.

Naming it matters: a user who has not chosen a sandbox should be able to
see that the answer is "none", rather than discovering it when a
repository's test suite writes to their home directory.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from thot.engine.process import GRACE_SECONDS, _LIVE, _LIVE_LOCK, _end_group
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
        # `subprocess.run(timeout=…)` kills the shell it started and nothing
        # under it: a timed-out `pytest` left its server running with ppid=1.
        # Same mechanism as engine/process.py, imported rather than copied —
        # two spellings of a kill is one spelling that drifts.
        process = subprocess.Popen(
            command, shell=True, cwd=str(self.root),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", start_new_session=True,
        )
        with _LIVE_LOCK:
            _LIVE.add(process)
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _end_group(process)
            try:
                process.communicate(timeout=GRACE_SECONDS)  # drain the pipes
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass
            return Result(124, f"Commande interrompue après {timeout} s.",
                          sandbox=self.name, timed_out=True)
        except BaseException:  # Ctrl-C included: nothing outlives its run
            _end_group(process)
            raise
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(process)
        return Result(process.returncode, clip((out or "") + (err or "")),
                      sandbox=self.name)
