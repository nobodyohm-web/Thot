"""A scheduler that lives in the user's own session, because launchd cannot.

macOS refuses `~/Desktop` to a launchd agent. Measured, not assumed: a
minimal agent running `ls ~/thot-tcc-probe` exits 0 while the same agent is
told `Operation not permitted` for `~/Desktop/Thot`. The nightly job never
ran and never could, and no amount of fixing the job would have changed it.

A process started from the user's session keeps that session's access, and
keeps it after being orphaned — a detached probe with `ppid=1` read the tree
in full. So the loop launchd cannot run, this one can, on the same schedule,
with nothing to grant and nothing to move.

The trade is honest and worth saying: this scheduler stops when the machine
does, and has to be started again after a reboot. A LaunchAgent would not —
which is exactly why it is still the right answer for a tree that lives
somewhere macOS does not guard.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from thot.paths import ensure_home, home, log_file
from thot.schedule.install import already_served

TICK_SECONDS = 60
STARTUP_CHECKS = 40
STARTUP_PAUSE = 0.25

# The hour the cron expressions in `jobs.SCHEDULES` name. Kept beside them
# rather than parsed out of them: two readings of one string that must agree
# is a bug waiting for the first person who edits one of them.
RUN_HOUR = 3


def pidfile() -> Path:
    return home() / "scheduler.pid"


def idfile() -> Path:
    """When the OS says the pid in `pidfile()` started.

    A second file rather than a richer `scheduler.pid`: the autostart line
    already written into every user's `.zshrc` reads that one with `cat`,
    and a bare pid is what it expects.
    """
    return home() / "scheduler.id"


def lockfile() -> Path:
    return home() / "scheduler.lock"


def statefile() -> Path:
    return home() / "scheduler.json"


def _started_at(pid: int) -> str:
    """The instant the OS says this pid started, or "" when it says nothing."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)],
                              capture_output=True, text=True)
    except OSError:
        return ""
    return done.stdout.strip()


def _command_of(pid: int) -> str:
    try:
        done = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                              capture_output=True, text=True)
    except OSError:
        return ""
    return done.stdout.strip()


def _recorded_pid() -> int | None:
    """What the pidfile claims, believed or not. Deletes nothing."""
    try:
        return int(pidfile().read_text().strip())
    except (OSError, ValueError):
        return None


def _forget() -> None:
    pidfile().unlink(missing_ok=True)
    idfile().unlink(missing_ok=True)


def previous_occurrence(schedule: str, now: datetime) -> datetime:
    """The most recent instant this schedule named, at or before `now`."""
    anchor = now.replace(minute=0, second=0, microsecond=0)
    if schedule == "hourly":
        return anchor
    if schedule == "daily":
        candidate = anchor.replace(hour=RUN_HOUR)
        return candidate if candidate <= now else candidate - timedelta(days=1)
    if schedule == "weekly":
        candidate = anchor.replace(hour=RUN_HOUR)
        candidate -= timedelta(days=candidate.weekday())  # back to Monday
        return candidate if candidate <= now else candidate - timedelta(days=7)
    raise ValueError(f"fréquence inconnue : {schedule}")


def due(job, now: datetime, last: datetime | None) -> bool:
    """Whether this job has an occurrence it has not run yet.

    A machine that was asleep at three in the morning runs the job once when
    it wakes, not once per hour it slept through: the question is whether
    the *latest* occurrence has been served, never how many were missed.
    """
    return last is None or last < previous_occurrence(job.schedule, now)


def read_state() -> dict[str, datetime]:
    try:
        raw = json.loads(statefile().read_text())
    except (OSError, ValueError):
        return {}
    found: dict[str, datetime] = {}
    for name, stamp in (raw or {}).items():
        try:
            found[name] = datetime.fromisoformat(stamp)
        except (TypeError, ValueError):
            continue
    return found


def write_state(state: dict[str, datetime]) -> None:
    ensure_home()
    statefile().write_text(
        json.dumps({name: when.isoformat() for name, when in state.items()},
                   indent=2)
    )


def seed(state: dict[str, datetime], names, now: datetime) -> dict[str, datetime]:
    """A job the scheduler has never seen waits for its next turn.

    Without this, starting the scheduler at midnight would fire the audit
    that was due at three the previous morning — a surprise, and the kind
    that costs a subscription's worth of tokens before anyone notices.
    """
    fresh = dict(state)
    for name in names:
        fresh.setdefault(name, now)
    return fresh


def _reachable(root: str) -> str:
    """Whether this scheduler can actually read what it is meant to audit."""
    from thot.fusion.locate import repo_root
    from thot.schedule.jobs import FUSION

    target = repo_root() if root == FUSION else Path(root).expanduser()
    try:
        next(Path(target).iterdir(), None)
    except OSError as exc:
        return f"illisible ({exc.strerror})"
    return "lisible"


def serve(*, tick: int = TICK_SECONDS, clock=datetime.now) -> int:
    """Run due jobs for as long as this process lives."""
    from thot.schedule import jobs

    ensure_home()
    # The pidfile is not a lock — writing it was the first thing this did,
    # and the only guard was a check in `start()`, a test-then-act with a
    # ~0.4 s window. The autostart line runs in every new terminal, so two
    # tabs restored at login was enough: measured, pids 63600 and 63601 both
    # alive, the pidfile naming only one, `stop` reaching only that one and
    # `status` answering "arrêté" while the other kept running every job.
    lock = os.open(lockfile(), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock)
        # `_recorded_pid()` and not `running()`: the loser reports, it does
        # not tidy up after the winner it just lost to — which may not even
        # have written its pidfile yet when the race is this tight.
        other = _recorded_pid()
        print("[thot] un planificateur tourne déjà"
              + (f" (pid {other})" if other is not None else "")
              + " — celui-ci s'arrête", flush=True)
        return 1

    try:
        # Identity first: a reader that finds a pidfile must find the file
        # that vouches for it, or it takes the live scheduler for a stale one.
        idfile().write_text(_started_at(os.getpid()))
        pidfile().write_text(str(os.getpid()))
        print(f"[thot] planificateur de session démarré · pid {os.getpid()}",
              flush=True)
        for job in jobs.load():
            owner = " · déjà servi par launchd" if already_served(job) else ""
            print(f"[thot]   {job.name} : {job.schedule}, {job.root} — "
                  f"{_reachable(job.root)}{owner}", flush=True)

        state = seed(read_state(), [j.name for j in jobs.load()], clock())
        write_state(state)

        while True:
            now = clock()
            current = jobs.load()
            # Re-seeded every tick: a job added while this runs is new to the
            # scheduler too, and must wait for its next turn rather than fire
            # the occurrence that passed before it existed.
            state = seed(state, [j.name for j in current], now)
            for job in current:
                if not due(job, now, state.get(job.name)):
                    continue
                if already_served(job):
                    # launchd has this one and has demonstrably run it.
                    # Two schedulers on one job double the work and the
                    # tokens, which is what the first night with both cost.
                    print(f"[thot] {job.name} : servi par launchd, ignoré",
                          flush=True)
                    state[job.name] = now
                    write_state(state)
                    continue
                print(f"[thot] {now:%Y-%m-%d %H:%M} — {job.name}", flush=True)
                try:
                    _run(job.name)
                except Exception as exc:  # a bad job must not end the loop
                    print(f"[thot] {job.name} a échoué : {exc}", flush=True)
                state[job.name] = now
                write_state(state)
            time.sleep(tick)
    except KeyboardInterrupt:
        return 0
    finally:
        if running() == os.getpid():
            _forget()
        # Released explicitly rather than left to the close: the fd stays in
        # this local for the whole loop precisely so nothing else can.
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _run(name: str) -> None:
    from thot.cli import _run_scheduled

    _run_scheduled(name)


def running() -> int | None:
    """The live scheduler's pid, or None. A stale pidfile is cleared."""
    pid = _recorded_pid()
    if pid is None:
        return None
    try:
        os.kill(pid, 0)  # the free filter: an unused pid is answered here
    except OSError:
        _forget()
        return None
    # A pid is not an identity. The file survives a reboot, a `kill -9` and a
    # crash, and pids are reused: with `os.kill(pid, 0)` alone, `stop` sent
    # SIGTERM to an unrelated `/bin/sleep` of the user's — reproduced, the
    # process died. No two processes share a pid *and* a start instant.
    try:
        claimed = idfile().read_text().strip()
    except OSError:
        claimed = ""
    if not claimed or claimed != _started_at(pid):
        _forget()
        return None
    return pid


def start() -> tuple[int, str]:
    """Detach a scheduler from this session and return (pid, log path).

    Detached rather than backgrounded: the terminal that starts it will
    close, and the loop has to outlive it. The access it inherited does not
    depend on the parent staying alive — a probe reparented to init read the
    guarded tree in full.
    """
    live = running()
    if live is not None:
        return live, str(log_file("scheduler"))

    ensure_home()
    destination = log_file("scheduler")
    handle = open(destination, "a", buffering=1)
    # `-c` rather than `-m thot.cli`: the module has no `__main__` block, so
    # `-m` imports it, runs nothing and exits 0 — which is how the first
    # version of this reported a scheduler that had never started.
    process = subprocess.Popen(
        [sys.executable, "-c", "from thot.cli import run; run()",
         "schedule", "daemon"],
        stdout=handle, stderr=handle, stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Wait for the loop to claim the pidfile. Announcing a start that did not
    # happen is worse than failing: the whole point of this scheduler is that
    # the last one failed silently, and its log was the only witness.
    for _ in range(STARTUP_CHECKS):
        live = running()
        if live is not None:
            # The pidfile's pid, not `process.pid`: when the child lost the
            # lock to a scheduler that was already there, the one to name is
            # the one actually running.
            return live, str(destination)
        if process.poll() is not None:
            break
        time.sleep(STARTUP_PAUSE)

    live = running()
    if live is not None:
        return live, str(destination)

    tail = ""
    try:
        tail = "\n".join(destination.read_text().splitlines()[-5:])
    except OSError:
        pass
    raise RuntimeError(
        f"le planificateur s'est arrêté aussitôt (code {process.poll()})"
        + (f"\n{tail}" if tail else "")
    )


def stop() -> bool:
    live = running()
    if live is None:
        return False
    # The one line in this file that kills something, so it asks once more:
    # `running()` compares start instants, this compares what is running.
    if "schedule daemon" not in _command_of(live):
        _forget()
        return False
    os.kill(live, 15)
    _forget()
    return True
