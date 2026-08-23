"""The line that revives the session scheduler after a reboot."""

from __future__ import annotations

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
