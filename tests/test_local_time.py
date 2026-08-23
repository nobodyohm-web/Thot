"""Stored timestamps, shown on the reader's own clock.

The run store writes `datetime('now')`, which is UTC and says nothing about
it. Printed as-is, a job started at 02:36 appeared as 00:36 — noticed by
querying this project's own store for a run that had just happened and
finding nothing there.
"""

from __future__ import annotations

from datetime import timedelta, timezone

from thot.output import local_time

PARIS = timezone(timedelta(hours=2))
KOLKATA = timezone(timedelta(hours=5, minutes=30))


def test_a_bare_stamp_is_read_as_utc():
    assert local_time("2026-08-23 00:36:42", zone=PARIS) == "2026-08-23 02:36"


def test_an_offset_is_honoured_rather_than_assumed():
    assert local_time("2026-08-23T00:36:42+00:00", zone=PARIS) \
        == "2026-08-23 02:36"
    assert local_time("2026-08-23T05:36:42+05:00", zone=PARIS) \
        == "2026-08-23 02:36"


def test_a_trailing_z_is_an_offset_too():
    """Handled by `fromisoformat` itself on every version Thot supports.

    A branch was written for it first, on the belief that 3.11 refused `Z`.
    The mutation survived because 3.11 is exactly where that stopped being
    true. The behaviour is still worth pinning — the floor moves.
    """
    assert local_time("2026-08-23T00:36:42Z", zone=PARIS) == "2026-08-23 02:36"


def test_a_half_hour_zone_is_not_rounded():
    assert local_time("2026-08-23 00:36:42", zone=KOLKATA) \
        == "2026-08-23 06:06"


def test_seconds_are_available_when_asked():
    assert local_time("2026-08-23 00:36:42", zone=PARIS, seconds=True) \
        == "2026-08-23 02:36:42"


def test_nothing_is_nothing():
    assert local_time("") == ""
    assert local_time(None) == ""


def test_an_unreadable_stamp_survives_untouched():
    assert local_time("hier soir", zone=PARIS) == "hier soir"
