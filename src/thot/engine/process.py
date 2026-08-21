"""Run an agent's command line, and leave nothing behind when it hangs.

`subprocess.run(timeout=…)` kills the process it started, and only that one.
Every backend Thot drives spawns children of its own — a node runtime, a
model client, a sandbox — so a timed-out task orphaned all of them. Measured,
not theorised: a `prime-agent` was still running three hours after the audit
that started it had exited, holding its memory and its socket.

So each task gets its own process group, and a timeout kills the group.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass

# How long a group gets to leave politely before it is killed outright.
GRACE_SECONDS = 5


class Timeout(RuntimeError):
    """The task ran past its budget. Its whole process group is gone."""


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


def _end_group(process: subprocess.Popen) -> None:
    """SIGTERM the group, then SIGKILL what is left of it."""
    try:
        group = os.getpgid(process.pid)
    except OSError:  # already gone, or no process groups on this platform
        group = None

    if group is not None:
        try:
            os.killpg(group, signal.SIGTERM)
        except OSError:
            process.terminate()
    else:
        process.terminate()

    try:
        process.wait(timeout=GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass

    if group is not None:
        try:
            os.killpg(group, signal.SIGKILL)
        except OSError:
            process.kill()
    else:
        process.kill()
    try:
        process.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:  # unkillable: reaped by the OS, not us
        pass


def run(
    command: list[str],
    *,
    cwd: str,
    timeout: int,
    stdin_text: str | None = None,
) -> Completed:
    """Run to completion, or raise `Timeout` having killed the whole group.

    `start_new_session` is what makes the group ours to kill. It also detaches
    the child from the terminal, which is correct here and only here: these
    tasks are non-interactive by definition, and the interactive path — where
    the user's Ctrl-C must reach the agent — deliberately does not use this.
    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input=stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        _end_group(process)
        try:
            process.communicate(timeout=GRACE_SECONDS)  # drain the pipes
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        raise Timeout(f"délai dépassé ({timeout}s)") from None
    except BaseException:
        # Ctrl-C, or anything else on the way out: the child must not survive
        # the run that owns it.
        _end_group(process)
        raise

    return Completed(process.returncode, stdout or "", stderr or "")
