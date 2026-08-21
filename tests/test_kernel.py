"""A live Python namespace — Prime Agent's thesis, under Thot's constraint.

The constraint is the first test: audited code never runs in Thot's own
process. Everything else here is about what a cell can and cannot make the
host do on its behalf.
"""

from __future__ import annotations

import os

import pytest

from thot.engine import AgentResult, EngineCapabilities
from thot.kernel import Kernel, KernelError


@pytest.fixture
def kernel(tmp_path):
    kernel = Kernel(root=tmp_path).start()
    yield kernel
    kernel.stop()


class StubEngine:
    """An engine that answers without a network, and counts."""

    capabilities = EngineCapabilities(name="stub", max_parallel=1)

    def __init__(self, answer="42"):
        self.answer = answer
        self.seen = []

    def run(self, task):
        self.seen.append(task)
        return AgentResult(task_id=task.id, text=self.answer)

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


# -- the constraint ----------------------------------------------------------


def test_the_namespace_lives_in_another_process(kernel):
    """An exec() inside Thot would hand audited code the credentials."""
    outcome = kernel.execute("import os; os.getpid()")

    assert outcome.ok
    assert int(outcome.value) != os.getpid()


def test_a_cell_cannot_stop_the_kernel(kernel):
    assert "SystemExit" in kernel.execute("raise SystemExit(1)").error
    assert kernel.execute("1 + 1").value == "2", "le noyau doit survivre"


def test_a_cell_that_never_returns_is_cut_and_the_kernel_restarts(tmp_path):
    kernel = Kernel(root=tmp_path).start()
    outcome = kernel.execute("import time; time.sleep(30)", timeout=1)

    assert not outcome.ok
    assert "interrompue" in outcome.error
    assert kernel.execute("1 + 1").value == "2", "un nouveau noyau doit repartir"
    kernel.stop()


# -- what makes it worth having ----------------------------------------------


def test_variables_survive_between_cells(kernel):
    kernel.execute("candidats = [1, 2, 3]")
    kernel.execute("candidats.append(4)")

    assert kernel.execute("sum(candidats)").value == "10"


def test_the_last_expression_is_echoed_like_a_repl(kernel):
    assert kernel.execute("x = 21").value == ""
    assert kernel.execute("x * 2").value == "42"
    assert kernel.execute("print('bonjour')").stdout.strip() == "bonjour"


def test_statements_still_run_when_there_is_no_trailing_expression(kernel):
    """The first version returned early and executed nothing at all."""
    kernel.execute("y = 7\nz = y + 1")
    assert kernel.execute("z").value == "8"


def test_an_error_points_at_the_cell_not_at_the_runner(kernel):
    error = kernel.execute("1/0").error

    assert "ZeroDivisionError" in error
    assert "<cellule>" in error
    assert "worker.py" not in error, "les cadres du lanceur n'aident personne"


def test_a_syntax_error_reads_like_a_repl(kernel):
    error = kernel.execute("x +").error

    assert error.startswith("SyntaxError")
    assert "x +" in error
    assert "ast.py" not in error


def test_the_repository_map_is_available_as_objects(tmp_path):
    """The reason the kernel is worth having: no round trip per question."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def main():\n    pass\n")

    kernel = Kernel(root=tmp_path).start()
    assert kernel.thot_available
    assert "src/app.py" in kernel.execute("files()").value
    assert "main" in kernel.execute("[s.name for s in symbols('main')]").value
    kernel.stop()


def test_reading_outside_the_repository_is_refused(kernel):
    error = kernel.execute("read('../../../etc/passwd')").error
    assert "hors du dépôt" in error


# -- rlm(): the recursive half ------------------------------------------------


def test_a_cell_can_delegate_a_question(tmp_path):
    engine = StubEngine("il valide en amont")
    kernel = Kernel(root=tmp_path, engine=engine).start()

    outcome = kernel.execute("rlm('le parseur valide-t-il ?')")

    assert outcome.value.strip("'\"") == "il valide en amont"
    assert engine.seen[0].instructions == "le parseur valide-t-il ?"
    assert outcome.calls == ("rlm",)
    kernel.stop()


def test_without_an_engine_rlm_says_so_rather_than_failing_obscurely(kernel):
    error = kernel.execute("rlm('une question')").error
    assert "aucun moteur" in error


def test_a_loop_cannot_spend_the_subscription(tmp_path):
    """A cell is not a conversation: a thousand rlm() calls is a runaway."""
    from thot.kernel import MAX_CALLS_PER_CELL

    engine = StubEngine()
    kernel = Kernel(root=tmp_path, engine=engine).start()

    outcome = kernel.execute(
        "faits = []\n"
        "for i in range(50):\n"
        "    faits.append(rlm(f'question {i}'))"
    )

    assert "refusé" in outcome.error
    assert len(engine.seen) == MAX_CALLS_PER_CELL
    kernel.stop()


def test_the_kernel_budget_is_held_by_the_host_not_the_cell(tmp_path):
    """A limit the child could edit is not a limit — and the child is
    running code from the repository under audit."""
    engine = StubEngine()
    kernel = Kernel(root=tmp_path, engine=engine, max_calls=2).start()

    kernel.execute("rlm('une')")
    kernel.execute("rlm('deux')")
    refused = kernel.execute("rlm('trois')")

    assert "budget" in refused.error
    assert len(engine.seen) == 2

    # And a cell rewriting the limit changes nothing.
    kernel.execute("import sys; sys.modules['__main__'].MAX = 999")
    assert "budget" in kernel.execute("rlm('quatre')").error
    assert len(engine.seen) == 2
    kernel.stop()


def test_a_failing_engine_is_reported_to_the_cell(tmp_path):
    class Broken(StubEngine):
        def run(self, task):
            raise RuntimeError("modèle injoignable")

    kernel = Kernel(root=tmp_path, engine=Broken()).start()
    assert "modèle injoignable" in kernel.execute("rlm('x')").error
    kernel.stop()


# -- remember(): what a cell learns -------------------------------------------


def test_a_cell_can_write_down_what_it_learned(tmp_path):
    from thot.harness import Harness

    harness = Harness(tmp_path / "local.json", tmp_path / "global.json")
    kernel = Kernel(root=tmp_path, harness=harness).start()

    kernel.execute("remember('team.shell', 'échappe ses arguments')")

    assert [e.title for e in harness.all()] == ["team.shell"]
    kernel.stop()


def test_an_unknown_host_request_is_refused_by_name(tmp_path):
    kernel = Kernel(root=tmp_path).start()
    error = kernel.execute("host.request('formate_le_disque', {})").error

    assert "demande inconnue" in error
    kernel.stop()


# -- the tool the model calls -------------------------------------------------


def test_the_python_tool_needs_a_kernel(toy_repo):
    from thot import agent_tools

    context = agent_tools.ToolContext(
        root=toy_repo, recon=None, confirm=lambda *a: True, refresh=lambda: None
    )
    assert "Aucun noyau" in agent_tools.dispatch(context, "python", {"code": "1"})


def test_the_python_tool_asks_before_running(toy_repo, tmp_path):
    from thot import agent_tools

    kernel = Kernel(root=tmp_path).start()
    context = agent_tools.ToolContext(
        root=toy_repo, recon=None, confirm=lambda *a: False,
        refresh=lambda: None, kernel=kernel,
    )
    assert "refusé" in agent_tools.dispatch(context, "python", {"code": "1"})
    kernel.stop()


def test_running_python_is_not_a_reading_posture():
    from thot import toolsets

    assert "python" not in toolsets.resolve("lecture")
    assert "python" not in toolsets.resolve("carte")
    assert "python" in toolsets.resolve("complet")


# -- the namespace inside the container ---------------------------------------


def test_the_containerised_kernel_keeps_stdin_open(tmp_path):
    """`docker run` closes stdin otherwise, and the namespace dies at its
    first read."""
    from thot.sandbox import DockerSandbox

    kernel = Kernel(root=tmp_path, sandbox=DockerSandbox(root=tmp_path))
    argv = kernel._command()

    assert "-i" in argv
    assert argv[argv.index("--network") + 1] == "none"


def test_the_container_still_gets_the_copy_prelude(tmp_path):
    """Replacing the whole shell command dropped the read-only overlay copy."""
    from thot.sandbox import DockerSandbox

    kernel = Kernel(root=tmp_path, sandbox=DockerSandbox(root=tmp_path))
    script = kernel._command()[-1]

    assert "cp -a" in script and "cd /work" in script
    assert "def serve(" in script, "le worker doit être inliné"


def test_the_worker_needs_nothing_but_the_standard_library():
    """It is executed inside a container where Thot is not installed."""
    import ast
    from pathlib import Path

    import thot.kernel.worker as worker

    tree = ast.parse(Path(worker.__file__).read_text(encoding="utf-8"))
    top_level = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    modules = set()
    for node in top_level:
        if isinstance(node, ast.Import):
            modules |= {alias.name.split(".")[0] for alias in node.names}
        elif node.module:
            modules.add(node.module.split(".")[0])

    assert "thot" not in modules, "un import de thot au niveau module casserait le conteneur"
    assert modules <= {"__future__", "io", "json", "sys", "traceback",
                       "contextlib"}
