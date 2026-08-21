from thot.contracts import CodeRef, Confidence, Finding, Severity


def test_coderef_renders_as_path_colon_line():
    ref = CodeRef(path="src/app.py", line=42)
    assert str(ref) == "src/app.py:42"


def test_coderef_is_hashable_and_frozen():
    ref = CodeRef(path="src/app.py", line=42)
    assert {ref: 1}[ref] == 1


def test_finding_id_is_stable_across_line_moves():
    a = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="abc")
    b = CodeRef(path="src/app.py", line=99, symbol="app.handler", ast_hash="abc")
    assert Finding.compute_id("taint.os.system", a) == Finding.compute_id(
        "taint.os.system", b
    )


def test_finding_id_changes_when_symbol_body_changes():
    a = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="abc")
    b = CodeRef(path="src/app.py", line=10, symbol="app.handler", ast_hash="def")
    assert Finding.compute_id("taint.os.system", a) != Finding.compute_id(
        "taint.os.system", b
    )


def test_severity_and_confidence_serialise_as_strings():
    assert Severity.HIGH.value == "high"
    assert Confidence.PLAUSIBLE.value == "plausible"
