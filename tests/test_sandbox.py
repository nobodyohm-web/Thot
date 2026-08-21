"""Running a repository's own code without running it as you.

`pytest` on a repository under audit is that repository's code executing
under your account. These tests are about what the container takes away,
and about the one rule that inverts Thot's usual fail-soft habit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot.sandbox import (
    DockerSandbox,
    LocalSandbox,
    SandboxError,
    build_sandbox,
)


def _line(**kwargs) -> list[str]:
    return DockerSandbox(root=Path("/repo"), **kwargs).command_line("pytest -q")


# -- what the container takes away -------------------------------------------


def test_the_default_container_has_no_network():
    """The single most valuable flag: a hostile test suite cannot phone home."""
    argv = _line()
    assert "--network" in argv
    assert argv[argv.index("--network") + 1] == "none"


def test_the_checkout_is_mounted_read_only_with_a_writable_overlay():
    argv = _line()
    mount = argv[argv.index("-v") + 1]

    assert mount.endswith(":ro")
    assert any("/work:rw" in part for part in argv), (
        "les constructions qui écrivent doivent marcher, sans toucher au dépôt"
    )
    assert "cp -a /repo/. /work/" in argv[-1]


def test_privileges_are_dropped_and_cannot_be_regained():
    argv = _line()
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert any("nosuid" in part for part in argv)


def test_a_fork_bomb_costs_one_container_not_the_machine():
    argv = _line()
    assert "--pids-limit" in argv
    assert "--memory" in argv
    assert "--cpus" in argv
    assert "--rm" in argv, "le conteneur doit disparaître"


def test_opening_the_network_is_possible_and_visible():
    argv = _line(network=True)
    assert "--network" not in argv
    assert "réseau ouvert" in DockerSandbox(root=Path("/r"), network=True).describe()


def test_a_writable_repository_skips_the_copy():
    argv = _line(writable=True)
    mount = argv[argv.index("-v") + 1]

    assert not mount.endswith(":ro")
    assert "cp -a" not in argv[-1]
    assert argv[-1] == "pytest -q"


def test_the_isolation_can_be_read_rather_than_trusted():
    preview = DockerSandbox(root=Path("/repo")).preview("pytest -q")
    assert preview.startswith(("docker", "/")) and "run" in preview
    assert "--network none" in preview


# -- choosing, and refusing ---------------------------------------------------


def test_the_default_is_the_host_and_says_so(tmp_path):
    sandbox = build_sandbox(tmp_path, config={})
    assert sandbox.name == "local"
    assert "aucune isolation" in sandbox.describe()


def test_a_requested_sandbox_that_cannot_be_built_refuses_to_run(tmp_path,
                                                                 monkeypatch):
    """Falling back to the host would turn a safety feature into a lie."""
    monkeypatch.setattr("thot.sandbox.docker._docker", lambda: None)

    with pytest.raises(SandboxError, match="docker"):
        build_sandbox(tmp_path, kind="docker", config={})


def test_an_unknown_sandbox_names_the_known_ones(tmp_path):
    with pytest.raises(SandboxError, match="local, docker"):
        build_sandbox(tmp_path, kind="lune", config={})


def test_the_environment_can_choose_the_sandbox(isolated_home, monkeypatch,
                                                tmp_path):
    from thot.sandbox.factory import load_config

    monkeypatch.setenv("THOT_SANDBOX", "docker")
    monkeypatch.setenv("THOT_SANDBOX_IMAGE", "mon-image:1")

    config = load_config()
    assert config["kind"] == "docker"
    assert config["image"] == "mon-image:1"


# -- the host path still works ------------------------------------------------


def test_a_local_command_runs_and_reports_its_code(tmp_path):
    result = LocalSandbox(root=tmp_path).run("exit 3")
    assert result.exit_code == 3
    assert result.ok is False
    assert result.sandbox == "local"


def test_a_command_that_never_ends_is_cut(tmp_path):
    result = LocalSandbox(root=tmp_path).run("sleep 5", timeout=1)
    assert result.timed_out is True
    assert "interrompue" in result.output


def test_output_is_clipped_rather_than_flooding_the_context(tmp_path):
    from thot.sandbox.local import MAX_OUTPUT_BYTES

    result = LocalSandbox(root=tmp_path).run("head -c 100000 /dev/zero | tr '\\0' 'x'")
    assert len(result.output.encode()) <= MAX_OUTPUT_BYTES + 200
    assert "coupé" in result.output


def test_a_command_keeps_its_end_because_that_is_where_it_failed(tmp_path):
    """Thot used to keep the collection banner and drop the traceback."""
    script = ("for i in $(seq 1 2000); do echo collecte $i; done; "
              "echo 'E   assert 1 == 2'; echo 'FAILED tests/test_x.py'")
    result = LocalSandbox(root=tmp_path).run(script)

    assert "FAILED tests/test_x.py" in result.output
    assert "assert 1 == 2" in result.output
    assert "collecte 1\n" not in result.output
    assert "coupées au début" in result.output


# -- the tool the model actually calls ---------------------------------------


def test_run_command_goes_through_the_sandbox(toy_repo):
    from thot import agent_tools

    class Spy:
        name = "faux"
        seen: list[str] = []

        def describe(self):
            return "bac à sable d'essai"

        def run(self, command, *, timeout=0):
            from thot.sandbox.base import Result

            self.seen.append(command)
            return Result(0, "fait", sandbox=self.name)

    spy = Spy()
    shown = []
    context = agent_tools.ToolContext(
        root=toy_repo, recon=None,
        confirm=lambda action, detail: shown.append(detail) or True,
        refresh=lambda: None, sandbox=spy,
    )
    answer = agent_tools.run_command(context, command="pytest -q")

    assert spy.seen == ["pytest -q"]
    assert "dans faux" in answer
    assert "bac à sable d'essai" in shown[0], (
        "la confirmation doit dire où la commande va tourner"
    )


def test_without_a_sandbox_the_tool_behaves_exactly_as_before(toy_repo):
    from thot import agent_tools

    context = agent_tools.ToolContext(
        root=toy_repo, recon=None, confirm=lambda *a: True, refresh=lambda: None
    )
    answer = agent_tools.run_command(context, command="echo bonjour")

    assert "code de sortie 0" in answer
    assert "bonjour" in answer
    assert "dans " not in answer.splitlines()[0]


def test_a_long_label_does_not_run_into_its_value():
    """`▪ bac à sablelocal` — alignment is worth less than legibility."""
    from thot.ui.theme import field

    rendered = field("bac à sable", "local").plain
    assert "bac à sable  local" in rendered
    assert field("modèle", "opus").plain.count(" ") > 3, "l'alignement tient"
