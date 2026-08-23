"""Whether launchd is already running a job, asked of launchd.

A unit was installed here for weeks while nothing ran, so "a unit exists"
never answered it. `launchctl print` reports what actually happened.
"""

from __future__ import annotations

from thot.schedule.install import parse_runs

SAMPLE = """\
com.thot.improve = {
\tactive count = 0
\tpath = /Users/dev/Library/LaunchAgents/com.thot.improve.plist
\tstate = not running
\truns = 1
\tlast exit code = 1
}
"""


def test_the_run_count_is_read():
    assert parse_runs(SAMPLE) == 1


def test_a_unit_that_never_ran_reads_zero():
    assert parse_runs(SAMPLE.replace("runs = 1", "runs = 0")) == 0


def test_an_answer_that_is_not_there_is_not_zero():
    """Not loaded and loaded-but-never-run are different situations."""
    assert parse_runs("com.thot.improve = {\n\tstate = not running\n}\n") is None


def test_an_unreadable_count_is_no_answer():
    assert parse_runs(SAMPLE.replace("runs = 1", "runs = beaucoup")) is None


def test_a_key_that_merely_ends_in_runs_is_not_it():
    assert parse_runs("\tpending runs = 4\n") is None


def test_a_job_launchd_has_run_is_already_served(monkeypatch):
    """Installed is not served: a unit sat here for weeks without running."""
    from thot.schedule import install
    from thot.schedule.jobs import FUSION, Job

    job = Job(name="improve", root=FUSION, deep=True)

    monkeypatch.setattr(install, "launchd_runs", lambda label: 1)
    assert install.already_served(job)

    monkeypatch.setattr(install, "launchd_runs", lambda label: 0)
    assert not install.already_served(job)

    monkeypatch.setattr(install, "launchd_runs", lambda label: None)
    assert not install.already_served(job)
