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


def test_the_loop_runs_a_due_job_and_records_it(tmp_path, monkeypatch):
    """The wiring between deciding and doing, on an injected clock.

    `due` is pure and tested above; what this pins is that `serve` asks it,
    acts on the answer, and writes the passage down — so the same occurrence
    is not served twice on the next tick.
    """
    from thot.schedule import daemon

    monkeypatch.setattr(daemon, "home", lambda: tmp_path)
    monkeypatch.setattr(daemon, "ensure_home", lambda: tmp_path)
    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="nuit", root=str(tmp_path), schedule="daily")],
    )

    ran: list[str] = []
    monkeypatch.setattr(daemon, "_run", ran.append)

    ticks = iter([at("2026-08-23 02:00"),   # seeding: nothing is owed yet
                  at("2026-08-23 03:00"),   # the occurrence arrives
                  at("2026-08-23 03:01")])  # and is not owed again

    def clock():
        try:
            return next(ticks)
        except StopIteration:
            raise KeyboardInterrupt

    assert daemon.serve(tick=0, clock=clock) == 0
    assert ran == ["nuit"]
    assert daemon.read_state()["nuit"] == at("2026-08-23 03:00")


def test_a_job_that_raises_does_not_end_the_loop(tmp_path, monkeypatch):
    """One repository in a bad state must not stop the others tonight."""
    from thot.schedule import daemon

    monkeypatch.setattr(daemon, "home", lambda: tmp_path)
    monkeypatch.setattr(daemon, "ensure_home", lambda: tmp_path)
    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="casse", root=str(tmp_path), schedule="daily"),
                 Job(name="sain", root=str(tmp_path), schedule="daily")],
    )

    ran: list[str] = []

    def run(name: str) -> None:
        if name == "casse":
            raise RuntimeError("dépôt introuvable")
        ran.append(name)

    monkeypatch.setattr(daemon, "_run", run)
    ticks = iter([at("2026-08-23 02:00"), at("2026-08-23 03:00")])

    def clock():
        try:
            return next(ticks)
        except StopIteration:
            raise KeyboardInterrupt

    assert daemon.serve(tick=0, clock=clock) == 0
    assert ran == ["sain"]
    assert "casse" in daemon.read_state()


def test_a_job_added_while_running_waits_for_its_next_turn(tmp_path, monkeypatch):
    """Adding a nightly audit at noon must not audit at noon.

    The seeding at startup cannot answer for a job that did not exist then,
    so the loop seeds again on every tick.
    """
    from thot.schedule import daemon

    monkeypatch.setattr(daemon, "home", lambda: tmp_path)
    monkeypatch.setattr(daemon, "ensure_home", lambda: tmp_path)

    old = Job(name="ancien", root=str(tmp_path), schedule="daily")
    new = Job(name="nouveau", root=str(tmp_path), schedule="daily")
    reads = {"n": 0}

    def load():
        reads["n"] += 1
        # Two reads at startup, then one per tick: the newcomer appears on
        # the second tick, hours after the occurrence it must not serve.
        return [old] if reads["n"] <= 3 else [old, new]

    monkeypatch.setattr("thot.schedule.jobs.load", load)
    ran: list[str] = []
    monkeypatch.setattr(daemon, "_run", ran.append)

    ticks = iter([at("2026-08-23 02:00"),
                  at("2026-08-23 04:00"),
                  at("2026-08-23 05:00")])

    def clock():
        try:
            return next(ticks)
        except StopIteration:
            raise KeyboardInterrupt

    assert daemon.serve(tick=0, clock=clock) == 0
    assert ran == ["ancien"]
