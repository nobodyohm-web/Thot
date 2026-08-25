"""Run an agent's command line, and leave nothing behind when it hangs.

`subprocess.run(timeout=…)` kills the process it started, and only that one.
Every backend Thot drives spawns children of its own — a node runtime, a
model client, a sandbox — so a timed-out task orphaned all of them. Measured,
not theorised: a `prime-agent` was still running three hours after the audit
that started it had exited, holding its memory and its socket.

So each task gets its own process group, and a timeout kills the group.

A timeout is not the only way out, though. The panel runs its members in
daemon threads, and a Ctrl-C there kills the interpreter without ever giving
those threads their own cleanup: measured, four detached agents still running
three seconds after python had exited, and still running forty-five seconds
later. atexit handlers do run during finalisation, while daemon threads are
still alive, so the registry below is what closes that path.
"""

from __future__ import annotations

import atexit
import os
import signal
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar

# How long a group gets to leave politely before it is killed outright.
GRACE_SECONDS = 5

# Every group with a `run` still in flight, whoever started it. Module-level
# on purpose: a per-caller registry would miss the worker interrupted between
# the Popen and its own bookkeeping.
_LIVE: set[subprocess.Popen] = set()
_LIVE_LOCK = threading.Lock()

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")


def _end_all() -> None:
    """Kill every group still in flight.

    Idempotent, and safe to call from a thread that owns none of them — which
    is the whole point: on the way out, nobody else is going to.
    """
    while True:
        with _LIVE_LOCK:
            if not _LIVE:
                return
            process = _LIVE.pop()
        _end_group(process)


atexit.register(_end_all)


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
        # Explicit, and lenient: an agent quoting a latin-1 file prints bytes
        # that are not UTF-8, and strict decoding raised UnicodeDecodeError —
        # neither `Timeout` nor `OSError`, so it flew out of `Engine.run` and
        # took the whole deep pass with it, verdicts already produced
        # included. One replacement character costs nothing by comparison.
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    with _LIVE_LOCK:
        _LIVE.add(process)
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
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(process)

    return Completed(process.returncode, stdout or "", stderr or "")


def parallel_map(
    work: Callable[[_Item], _Result],
    items: Iterable[_Item],
    *,
    max_workers: int,
) -> list[_Result]:
    """Run `work` over `items` concurrently, results in the order given.

    `with ThreadPoolExecutor(...)` exits through `shutdown(wait=True)`, so a
    Ctrl-C during a fan_out was only reported once every task in flight had
    finished — up to the 600 s budget of an agent still thinking. Killing the
    live groups is what unblocks the running workers; cancelling the futures
    stops the queue from starting anything new after the interrupt.
    """
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = [pool.submit(work, item) for item in items]
        try:
            return [future.result() for future in futures]
        except BaseException:
            _end_all()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    finally:
        pool.shutdown(wait=False)
