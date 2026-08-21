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
