from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.scope.detect import detect_scope
from thot.taint.engine import find_candidates


def analyse(repo):
    manifest = detect_scope(repo)
    symbols = []
    for relative in manifest.files:
        symbols.extend(PythonIndexer().index_file(repo, relative))
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return find_candidates(repo, graph)


def test_argv_to_os_system_is_found(toy_repo):
    candidates = analyse(toy_repo)
    rules = {c.rule for c in candidates}
    assert "sink.os.system" in rules


def test_candidate_carries_the_full_path(toy_repo):
    candidate = next(c for c in analyse(toy_repo) if c.rule == "sink.os.system")
    assert len(candidate.path) >= 2
    assert candidate.sink.path == "src/app.py"


def test_unreachable_helper_is_not_reported(toy_repo):
    """unreachable_helper hits os.system too, but nobody feeds it tainted data."""
    candidates = analyse(toy_repo)
    assert all(
        c.sink.symbol != "src.app.unreachable_helper" for c in candidates
    )


def test_clean_file_produces_nothing(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "clean.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []


def test_constant_argument_is_not_tainted(tmp_path):
    (tmp_path / "const.py").write_text(
        "import os\n\n\ndef main():\n    os.system('ls -la')\n"
    )
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "const.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []


def test_direct_source_to_sink_in_one_body(tmp_path):
    (tmp_path / "direct.py").write_text(
        "import os\nimport sys\n\n\ndef main():\n"
        "    cmd = sys.argv[1]\n    os.system(cmd)\n"
    )
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "direct.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    candidates = find_candidates(tmp_path, graph)
    assert len(candidates) == 1
    assert candidates[0].rule == "sink.os.system"
