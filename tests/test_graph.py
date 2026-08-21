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
