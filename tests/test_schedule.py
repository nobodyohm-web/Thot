"""Scheduled audits, and the only thing that makes them bearable: silence.

A nightly audit that mails the same 300 findings every night is an unsubscribe
waiting to happen. The job of this module is to run the audit and then say
nothing at all unless something is genuinely new since last time.
"""

from __future__ import annotations

import json

import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.schedule import jobs
from thot.schedule.runner import new_since_last_run


def make_finding(identifier="a", severity=Severity.HIGH):
    location = CodeRef(path=f"{identifier}.py", line=1, symbol="f", ast_hash=identifier)
    return Finding(
        id=Finding.compute_id("sink.os.system", location),
        rule="sink.os.system",
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
    )


# -- job persistence ---------------------------------------------------------


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "schedule.json"
    monkeypatch.setattr(jobs, "REGISTRY_PATH", path)
    return path


def test_a_job_round_trips(registry):
    jobs.add(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    loaded = jobs.load()
    assert len(loaded) == 1
    assert loaded[0].root == "/repo"
    assert loaded[0].schedule == "daily"


def test_adding_the_same_name_replaces_it(registry):
    jobs.add(jobs.Job(name="nuit", root="/a", schedule="daily"))
    jobs.add(jobs.Job(name="nuit", root="/b", schedule="weekly"))
    loaded = jobs.load()
    assert len(loaded) == 1
    assert loaded[0].root == "/b"


def test_removing_a_job(registry):
    jobs.add(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    assert jobs.remove("nuit") is True
    assert jobs.load() == []
    assert jobs.remove("nuit") is False


def test_no_registry_means_no_jobs(registry):
    assert jobs.load() == []


def test_a_corrupt_registry_is_not_fatal(registry):
    registry.write_text("{ pas du json")
    assert jobs.load() == []


def test_an_unknown_schedule_is_refused(registry):
    with pytest.raises(ValueError, match="fréquence"):
        jobs.add(jobs.Job(name="x", root="/r", schedule="parfois"))


def test_schedules_map_to_cron_expressions():
    assert jobs.cron_expression("daily")
    assert jobs.cron_expression("hourly")
    assert jobs.cron_expression("weekly")


# -- the silence rule --------------------------------------------------------


def test_everything_is_new_on_a_first_run():
    current = [make_finding("a"), make_finding("b")]
    assert len(new_since_last_run(current, previous_ids=set())) == 2


def test_nothing_is_new_when_nothing_changed():
    current = [make_finding("a"), make_finding("b")]
    known = {f.id for f in current}
    assert new_since_last_run(current, previous_ids=known) == []


def test_only_the_newcomer_is_reported():
    old = make_finding("a")
    new = make_finding("b")
    fresh = new_since_last_run([old, new], previous_ids={old.id})
    assert [f.location.path for f in fresh] == ["b.py"]


def test_refuted_findings_are_never_news():
    from dataclasses import replace

    refuted = replace(make_finding("a"), confidence=Confidence.REFUTED)
    assert new_since_last_run([refuted], previous_ids=set()) == []


def test_a_threshold_filters_the_noise():
    low = make_finding("a", Severity.LOW)
    high = make_finding("b", Severity.HIGH)
    fresh = new_since_last_run(
        [low, high], previous_ids=set(), threshold=Severity.HIGH
    )
    assert [f.location.path for f in fresh] == ["b.py"]


# -- the diff comes from the store -------------------------------------------


def test_the_store_knows_nothing_before_the_first_run(tmp_path, toy_repo):
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        assert store.previous_finding_ids(str(toy_repo)) == set()
    finally:
        store.close()


def test_the_store_reports_the_last_stored_run(tmp_path, toy_repo):
    """Queried before the next run starts, so the newest row is the baseline."""
    from thot.pipeline import run_audit
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        first = run_audit(toy_repo, store=store, require_authorization=False)
        known = store.previous_finding_ids(str(toy_repo))
        assert known == {f.id for f in first.findings}
    finally:
        store.close()


def test_a_scheduled_run_is_silent_the_second_time(tmp_path, toy_repo):
    from thot.schedule.runner import run_job
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        job = jobs.Job(name="t", root=str(toy_repo), schedule="daily",
                       threshold=Severity.LOW.value)
        first, total = run_job(job, store=store)
        assert first and total
        second, _ = run_job(job, store=store)
        assert second == []
    finally:
        store.close()


# -- handing the job to the system -------------------------------------------


def test_a_launchd_plist_names_the_job_and_the_command():
    from thot.schedule.install import label, launchd_plist

    job = jobs.Job(name="nuit", root="/repo", schedule="daily")
    plist = launchd_plist(job)
    assert label(job) in plist
    assert "<string>schedule</string>" in plist
    assert "<string>nuit</string>" in plist
    assert "<key>Hour</key><integer>3</integer>" in plist


def test_an_hourly_job_has_no_fixed_hour():
    from thot.schedule.install import launchd_plist

    plist = launchd_plist(jobs.Job(name="h", root="/r", schedule="hourly"))
    assert "<key>Hour</key>" not in plist


def test_a_weekly_job_pins_a_weekday():
    from thot.schedule.install import launchd_plist

    plist = launchd_plist(jobs.Job(name="w", root="/r", schedule="weekly"))
    assert "<key>Weekday</key><integer>1</integer>" in plist


def test_the_crontab_line_is_runnable():
    from thot.schedule.install import crontab_line

    line = crontab_line(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    assert line.startswith("0 3 * * *")
    assert "schedule run nuit" in line
