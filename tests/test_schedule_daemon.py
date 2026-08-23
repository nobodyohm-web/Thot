"""The scheduler that runs inside the user's session.

launchd is refused `~/Desktop`, so the nightly job never ran. What decides
when this one runs is pure and lives here; what it then executes is the
same `schedule run` the CLI has always had.
"""

from __future__ import annotations

from datetime import datetime

from thot.schedule.daemon import due, previous_occurrence, seed
from thot.schedule.jobs import Job


def at(text: str) -> datetime:
    return datetime.fromisoformat(text)


def nightly() -> Job:
    return Job(name="nuit", root="fusion", schedule="daily")


def test_daily_falls_at_three_in_the_morning():
    assert previous_occurrence("daily", at("2026-08-23 02:00")) \
        == at("2026-08-22 03:00")
    assert previous_occurrence("daily", at("2026-08-23 03:00")) \
        == at("2026-08-23 03:00")
    assert previous_occurrence("daily", at("2026-08-23 23:59")) \
        == at("2026-08-23 03:00")


def test_hourly_falls_on_the_hour():
    assert previous_occurrence("hourly", at("2026-08-23 10:30")) \
        == at("2026-08-23 10:00")


def test_weekly_falls_back_to_monday():
    """2026-08-23 is a Sunday, so the occurrence is the Monday before it."""
    assert previous_occurrence("weekly", at("2026-08-23 10:00")) \
        == at("2026-08-17 03:00")
    assert previous_occurrence("weekly", at("2026-08-17 02:00")) \
        == at("2026-08-10 03:00")


def test_an_occurrence_is_served_once():
    assert due(nightly(), at("2026-08-23 03:00"), at("2026-08-22 03:05"))
    assert not due(nightly(), at("2026-08-23 04:00"), at("2026-08-23 03:05"))


def test_a_machine_that_slept_runs_once_on_waking():
    """Two days asleep is one run owed, not two."""
    assert due(nightly(), at("2026-08-23 09:00"), at("2026-08-21 03:05"))


def test_a_job_never_seen_waits_for_its_next_turn():
    """Starting at midnight must not fire the audit due at three yesterday."""
    now = at("2026-08-23 00:05")
    state = seed({}, ["nuit"], now)
    assert not due(nightly(), now, state["nuit"])


def test_seeding_never_moves_a_job_that_has_run():
    already = at("2026-08-22 03:05")
    assert seed({"nuit": already}, ["nuit"], at("2026-08-23 00:05")) \
        == {"nuit": already}


def test_an_unknown_frequency_is_refused():
    import pytest

    with pytest.raises(ValueError):
        previous_occurrence("fortnightly", at("2026-08-23 10:00"))


def test_running_exactly_on_the_hour_serves_that_occurrence():
    """`last == the occurrence` is served, not owed — or 03:00 runs twice."""
    assert not due(nightly(), at("2026-08-23 03:00"), at("2026-08-23 03:00"))


def test_a_job_with_no_record_at_all_is_owed_a_run():
    """The library's own answer. `serve` re-seeds so it never asks this."""
    assert due(nightly(), at("2026-08-23 09:00"), None)
