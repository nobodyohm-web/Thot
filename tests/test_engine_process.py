"""Killing a timed-out task means killing what it started.

`subprocess.run(timeout=…)` kills the process it launched and nothing else.
Every agent Thot drives spawns children of its own, so a timed-out task used
to orphan them — a `prime-agent` was found still running three hours after
the audit that started it had exited.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from thot.engine import process


def _python(script: str) -> list[str]:
    return [sys.executable, "-c", script]


def test_a_normal_run_returns_its_output():
    done = process.run(_python("print('bonjour')"), cwd=".", timeout=30)

    assert done.returncode == 0
    assert done.stdout.strip() == "bonjour"


def test_stdin_reaches_the_child_when_it_is_given():
    done = process.run(
        _python("import sys; sys.stdout.write(sys.stdin.read().upper())"),
        cwd=".", timeout=30, stdin_text="salut",
    )
    assert done.stdout == "SALUT"


def test_a_child_that_reaches_for_stdin_is_not_left_waiting():
    """Closed, not inherited: a non-interactive task must fail, not hang."""
    done = process.run(
        _python("import sys; print(len(sys.stdin.read()))"), cwd=".", timeout=30
    )
    assert done.stdout.strip() == "0"


def test_a_timeout_raises_rather_than_returning_a_lie():
    with pytest.raises(process.Timeout):
        process.run(_python("import time; time.sleep(30)"), cwd=".", timeout=1)


def test_a_timeout_takes_the_grandchildren_with_it(tmp_path):
    """The whole point. A killed task must not leave a process running."""
    marker = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time, os\n"
        f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(marker)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(60)\n"
    )

    with pytest.raises(process.Timeout):
        process.run(_python(script), cwd=str(tmp_path), timeout=3)

    assert marker.exists(), "le petit-enfant n'a jamais démarré"
    pid = int(marker.read_text())

    deadline = time.monotonic() + 5
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            alive = False
            break
        time.sleep(0.05)

    if alive:  # do not leak the process into the rest of the suite
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    assert not alive, f"le processus {pid} a survécu au délai dépassé"


# -- what is still in flight -------------------------------------------------
#
# A Ctrl-C during a threaded fan_out never reaches the `except BaseException`
# below: the workers are daemon threads, and the interpreter drops them where
# they stand, inside `communicate()`. Measured before the registry existed:
# four detached agents still running three seconds after the interpreter had
# exited, and still running forty-five seconds later. atexit handlers do run
# at that point, which is what makes the registry the last line of defence.


def test_a_finished_run_is_no_longer_in_flight():
    process.run(_python("print('fini')"), cwd=".", timeout=30)
    assert not process._LIVE


def test_a_timed_out_run_is_no_longer_in_flight():
    with pytest.raises(process.Timeout):
        process.run(_python("import time; time.sleep(30)"), cwd=".", timeout=1)
    assert not process._LIVE


def test_end_all_kills_a_run_nobody_is_going_to_come_back_for(tmp_path):
    """The exact shape of an interrupted fan_out: the thread that owns the
    child is gone, so the kill has to come from outside it."""
    import threading

    marker = tmp_path / "child.pid"
    script = (
        "import os, time\n"
        f"open({str(marker)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    worker = threading.Thread(
        target=lambda: process.run(_python(script), cwd=str(tmp_path), timeout=600),
        daemon=True,
    )
    worker.start()

    deadline = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), "l'enfant n'a jamais démarré"
    pid = int(marker.read_text())

    process._end_all()

    assert not process._LIVE
    assert _dead(pid), f"le processus {pid} a survécu à _end_all()"
    process._end_all()  # idempotent: atexit must not fail on a second pass


def _dead(pid: int, *, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.05)
    try:  # never leak a survivor into the rest of the suite
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return False


# -- decoding ----------------------------------------------------------------


def test_a_non_utf8_byte_does_not_take_the_audit_with_it():
    """`text=True` decodes strict, and UnicodeDecodeError is neither Timeout
    nor OSError: one 0xE9 quoted from a latin-1 file flew out of `Engine.run`
    and killed the whole deep pass, losing the verdicts already produced."""
    done = process.run(
        _python(r"import sys; sys.stdout.buffer.write(b'caf\xe9.py')"),
        cwd=".", timeout=30,
    )
    assert done.stdout == "caf�.py"


def test_undecodable_bytes_on_stderr_are_replaced_too():
    done = process.run(
        _python(r"import sys; sys.stderr.buffer.write(b'\xff'); raise SystemExit(2)"),
        cwd=".", timeout=30,
    )
    assert done.returncode == 2
    assert done.stderr == "�"


def test_non_ascii_still_makes_the_round_trip():
    done = process.run(
        _python("import sys; sys.stdout.write(sys.stdin.read())"),
        cwd=".", timeout=30, stdin_text="héllo ✓\n",
    )
    assert done.stdout == "héllo ✓\n"


# -- interrupting a pool -----------------------------------------------------


def test_an_interrupted_pool_does_not_wait_out_the_tasks_in_flight(tmp_path):
    """`with ThreadPoolExecutor(...)` swallows the interrupt until every task
    in flight has finished — up to the 600 s budget of an agent still
    thinking. Killing the live groups first is what makes it prompt."""
    import threading

    pids = tmp_path / "pids"
    pids.mkdir()
    script = (
        "import os, time\n"
        f"open(os.path.join({str(pids)!r}, str(os.getpid())), 'w').close()\n"
        "time.sleep(60)\n"
    )

    def work(index: int):
        if index == 0:
            while len(list(pids.iterdir())) < 2:
                time.sleep(0.02)
            raise KeyboardInterrupt
        return process.run(_python(script), cwd=str(tmp_path), timeout=600)

    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        process.parallel_map(work, [0, 1, 2], max_workers=3)
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"l'interruption a attendu {elapsed:.0f}s"
    assert all(_dead(int(entry.name)) for entry in pids.iterdir())
    assert threading.active_count() >= 1


def test_parallel_map_keeps_the_order_it_was_given():
    assert process.parallel_map(lambda n: n * n, [1, 2, 3, 4], max_workers=3) == [
        1, 4, 9, 16
    ]
