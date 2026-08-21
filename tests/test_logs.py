"""Somewhere to look when something went wrong while nobody was watching.

A scheduled audit runs at 03:00; a gateway daemon runs for days. Before
this, "nothing on screen" was the whole diagnostic.
"""

from __future__ import annotations

import logging

from thot import bootstrap, logs


def test_logging_writes_under_the_thot_home(isolated_home):
    target = logs.setup(force=True)

    assert target is not None
    assert target.parent == isolated_home / "logs"

    logs.get("essai").info("un message")
    assert "un message" in target.read_text(encoding="utf-8")


def test_every_logger_hangs_off_one_switch(isolated_home):
    logs.setup(force=True)
    logger = logs.get("gateway")

    assert logger.name == "thot.gateway"
    assert logging.getLogger("thot").level == logging.INFO


def test_a_home_that_cannot_be_written_costs_the_log_not_the_run(monkeypatch):
    """A read-only home is a reason to run without logs, not to refuse."""
    def refuse(*args, **kwargs):
        raise OSError("lecture seule")

    monkeypatch.setattr("pathlib.Path.mkdir", refuse)
    assert logs.setup(force=True) is None
    logs.get("essai").warning("ne doit pas lever")


def test_the_console_stays_quiet_unless_something_is_wrong(isolated_home):
    logs.setup(force=True, console=True)
    handlers = logging.getLogger("thot").handlers
    stream = [h for h in handlers if isinstance(h, logging.StreamHandler)
              and not isinstance(h, logging.FileHandler)]

    assert stream and stream[0].level == logging.WARNING


def test_setup_is_idempotent(isolated_home):
    first = logs.setup(force=True)
    count = len(logging.getLogger("thot").handlers)
    logs.setup()

    assert logs.setup() == first
    assert len(logging.getLogger("thot").handlers) == count


# -- the console Thot has to print into --------------------------------------


def test_the_utf8_bootstrap_does_nothing_on_posix(monkeypatch):
    """Overriding a locale someone set deliberately is the same mistake,
    in the other direction."""
    monkeypatch.setattr(bootstrap, "IS_WINDOWS", False)
    monkeypatch.setattr(bootstrap, "_applied", False)

    assert bootstrap.apply() is False


def test_on_windows_children_inherit_utf8(monkeypatch):
    """`print("réfuté")` on a cp1252 console raises before a single finding."""
    monkeypatch.setattr(bootstrap, "IS_WINDOWS", True)
    monkeypatch.setattr(bootstrap, "_applied", False)
    monkeypatch.delenv("PYTHONUTF8", raising=False)
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)

    import os

    assert bootstrap.apply() is True
    assert os.environ["PYTHONUTF8"] == "1"
    assert os.environ["PYTHONIOENCODING"] == "utf-8"
    assert bootstrap.apply() is False, "idempotent"


def test_the_entry_point_bootstraps_before_anything_prints():
    import inspect

    from thot import cli

    source = inspect.getsource(cli.run)
    assert "bootstrap.apply()" in source
    assert source.index("bootstrap.apply()") < source.index("main()")
