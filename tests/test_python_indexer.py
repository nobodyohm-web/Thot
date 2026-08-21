import ast

from thot.codemap.python_indexer import PythonIndexer, normalized_ast_hash


def test_functions_are_indexed_with_qualified_names(toy_repo):
    symbols = PythonIndexer().index_file(toy_repo, "src/app.py")
    names = {s.name for s in symbols}
    assert "src.app.main" in names
    assert "src.app.run_command" in names


def test_calls_are_recorded(toy_repo):
    symbols = {s.name: s for s in PythonIndexer().index_file(toy_repo, "src/app.py")}
    assert "read_user_input" in symbols["src.app.main"].calls
    assert "os.system" in symbols["src.app.run_command"].calls


def test_params_are_recorded(toy_repo):
    symbols = {s.name: s for s in PythonIndexer().index_file(toy_repo, "src/app.py")}
    assert symbols["src.app.run_command"].params == ("cmd",)


def test_ast_hash_ignores_formatting_and_comments():
    a = ast.parse("def f(x):\n    return x + 1\n")
    b = ast.parse("def f(x):\n    # a comment\n    return  x  +  1\n")
    assert normalized_ast_hash(a) == normalized_ast_hash(b)


def test_ast_hash_changes_when_logic_changes():
    a = ast.parse("def f(x):\n    return x + 1\n")
    b = ast.parse("def f(x):\n    return x + 2\n")
    assert normalized_ast_hash(a) != normalized_ast_hash(b)


def test_methods_are_indexed_with_class_in_the_name(tmp_path):
    (tmp_path / "m.py").write_text("class A:\n    def go(self):\n        pass\n")
    symbols = {s.name for s in PythonIndexer().index_file(tmp_path, "m.py")}
    assert "m.A.go" in symbols


def test_syntax_error_yields_no_symbols_without_raising(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    assert PythonIndexer().index_file(tmp_path, "broken.py") == []
