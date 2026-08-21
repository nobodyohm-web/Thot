from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.scope.detect import detect_scope


def build(toy_repo):
    manifest = detect_scope(toy_repo)
    symbols = []
    for relative in manifest.files:
        symbols.extend(PythonIndexer().index_file(toy_repo, relative))
    return CodeGraph.build(symbols, manifest.entrypoints)


def test_local_calls_resolve_to_qualified_names(toy_repo):
    graph = build(toy_repo)
    assert "src.app.run_command" in graph.callees("src.app.main")


def test_callers_is_the_inverse_of_callees(toy_repo):
    graph = build(toy_repo)
    assert "src.app.main" in graph.callers("src.app.run_command")


def test_entrypoint_is_at_distance_zero(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.main") == 0


def test_called_function_is_at_distance_one(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.run_command") == 1


def test_unreachable_symbol_has_no_distance(toy_repo):
    graph = build(toy_repo)
    assert graph.distance_from_entrypoints("src.app.unreachable_helper") is None


# -- routes the graph cannot follow ------------------------------------------
#
# Found by running Thot on itself: the shell sink in LocalSandbox.run sat at
# LOW because nothing "called" it — it is reached through a dispatch table
# and through a variable. Burying a finding for that reason hides the
# ordinary case in every framework there is.


def _index(tmp_path, source: str, name: str = "app.py"):
    from thot.codemap.python_indexer import PythonIndexer

    (tmp_path / name).write_text(source, encoding="utf-8")
    return PythonIndexer().index_file(tmp_path, name)


def test_a_handler_in_a_dispatch_table_is_not_unreachable(tmp_path):
    from thot.codemap.graph import CodeGraph

    symbols = _index(tmp_path, """
import os


def run_command(command):
    os.system(command)


HANDLERS = {"run": run_command}
""")
    graph = CodeGraph.build(symbols)

    assert graph.callers("app.run_command") == set(), "aucun appel réel"
    assert graph.reach_unknown("app.run_command") is True


def test_a_decorated_function_escapes_into_its_decorator(tmp_path):
    from thot.codemap.graph import CodeGraph

    symbols = _index(tmp_path, """
app = object()


@app.route("/ping")
def ping():
    return "pong"
""")
    graph = CodeGraph.build(symbols)

    assert graph.reach_unknown("app.ping") is True


def test_a_call_on_a_variable_of_unknown_type_is_not_proof_of_absence(tmp_path):
    from thot.codemap.graph import CodeGraph

    symbols = _index(tmp_path, """
class Local:
    def run(self, command):
        pass


class Docker:
    def run(self, command):
        pass


def go(sandbox):
    sandbox.run("pytest")
""")
    graph = CodeGraph.build(symbols)

    # Two candidates answer to `run`; recording no edge is right.
    assert graph.callers("app.Local.run") == set()
    # Concluding "unreachable" is not.
    assert graph.reach_unknown("app.Local.run") is True


def test_a_function_nobody_mentions_stays_unreachable(tmp_path):
    """The discount has to keep working, or it stops being a filter."""
    from thot.codemap.graph import CodeGraph

    symbols = _index(tmp_path, """
def entree():
    aide()


def aide():
    pass


def oubliee():
    pass
""")
    graph = CodeGraph.build(symbols, entrypoints=("app.entree",))

    assert graph.reach_unknown("app.oubliee") is False
    assert graph.distance_from_entrypoints("app.oubliee") is None


def test_a_local_variable_is_not_a_function_escaping(tmp_path):
    """`for line in lines` must not mark every `.lines` in the tree as live."""
    from thot.codemap.graph import CodeGraph

    symbols = _index(tmp_path, """
def lines():
    pass


def compte(texte):
    lines = texte.split()
    total = 0
    for item in lines:
        total += 1
    return total
""")
    graph = CodeGraph.build(symbols)

    assert graph.reach_unknown("app.lines") is False


def test_module_level_code_is_indexed_at_all(tmp_path):
    """It was invisible: the table that wires everything together lives there."""
    symbols = _index(tmp_path, """
import os


def helper():
    pass


TABLE = {"h": helper}
os.environ.setdefault("X", "1")
""")
    module = [s for s in symbols if s.kind == "module"]

    assert len(module) == 1
    assert "helper" in module[0].references
    assert any("setdefault" in call for call in module[0].calls)
