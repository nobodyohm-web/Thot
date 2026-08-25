"""The line that revives the session scheduler after a reboot."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from thot.schedule import autostart


def test_the_block_is_bounded_by_its_markers():
    written = autostart.block()
    assert written.startswith(autostart.OPEN)
    assert written.endswith(autostart.CLOSE)


def test_installing_twice_leaves_one_block():
    once = autostart.install_into("export PATH=/usr/bin\n")
    twice = autostart.install_into(once)
    assert twice.count(autostart.OPEN) == 1
    assert twice.count(autostart.CLOSE) == 1


def test_installing_again_replaces_an_older_line():
    """An older Thot wrote an older body; the fix has to reach it."""
    stale = (f"alias l=ls\n\n{autostart.OPEN}\n"
             "thot schedule start  # une vieille version\n"
             f"{autostart.CLOSE}\n")
    fresh = autostart.install_into(stale)
    assert "une vieille version" not in fresh
    assert autostart.BODY in fresh
    assert "alias l=ls" in fresh


def test_removing_restores_what_was_there():
    original = "export PATH=/usr/bin\nalias l=ls\n"
    assert autostart.remove_from(autostart.install_into(original)) == original


def test_removing_from_a_file_without_the_block_changes_nothing():
    original = "export PATH=/usr/bin\n"
    assert autostart.remove_from(original) == original


def test_a_file_holding_only_the_block_empties_cleanly():
    assert autostart.remove_from(autostart.install_into("")) == ""


def test_the_startup_file_follows_the_shell():
    home = Path("/tmp/nowhere")
    assert autostart.startup_file("/bin/zsh", home) == home / ".zshrc"
    assert autostart.startup_file("/bin/bash", home) == home / ".bashrc"
    assert autostart.startup_file("/usr/local/bin/fish", home) \
        == home / ".config" / "fish" / "config.fish"


def test_bash_prefers_a_profile_that_exists(tmp_path):
    (tmp_path / ".bash_profile").write_text("")
    assert autostart.startup_file("/bin/bash", tmp_path) \
        == tmp_path / ".bash_profile"


def _stage(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A HOME, a `thot` on PATH that only says it was called, and the trace."""
    home = tmp_path / "home"
    (home / ".thot").mkdir(parents=True)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    trace = tmp_path / "appelé"
    stub = binaries / "thot"
    stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> {trace}\n')
    stub.chmod(0o755)
    return home, binaries, trace


def _decide(home: Path, binaries: Path, *, wait: float = 5.0) -> bool:
    """Run the startup block itself and report whether it relaunched."""
    environment = dict(os.environ)
    environment.pop("THOT_NO_AUTOSTART", None)
    environment["HOME"] = str(home)
    environment["PATH"] = f"{binaries}:{environment['PATH']}"
    subprocess.run(["/bin/sh", "-c", autostart.BODY], env=environment,
                   check=True)
    trace = binaries.parent / "appelé"
    deadline = time.monotonic() + wait   # the block starts in the background
    while time.monotonic() < deadline:
        if trace.exists():
            return True
        time.sleep(0.05)
    return False


def test_only_a_real_scheduler_stops_the_line_from_relaunching(tmp_path):
    """`kill -0` on a bare pid answers for whoever holds it today.

    The pidfile outlives a reboot and a `kill -9`, and pids are reused: the
    test said "alive", the block stayed quiet, and the scheduler this line
    exists to revive never came back.
    """
    home, binaries, _ = _stage(tmp_path)
    pidfile = home / ".thot" / "scheduler.pid"

    # A pid of the user's that is emphatically not the scheduler: this one.
    pidfile.write_text(str(os.getpid()))
    assert _decide(home, binaries), \
        "un pid étranger doit faire relancer le planificateur"

    (tmp_path / "appelé").unlink()
    impostor = tmp_path / "faux.sh"
    impostor.write_text("#!/bin/sh\nsleep 30\n")
    scheduler = subprocess.Popen(["/bin/sh", str(impostor),
                                  "schedule", "daemon"])
    try:
        pidfile.write_text(str(scheduler.pid))
        assert not _decide(home, binaries, wait=1.5), \
            "un planificateur vivant ne doit pas en faire démarrer un second"
    finally:
        scheduler.kill()
        scheduler.wait()
