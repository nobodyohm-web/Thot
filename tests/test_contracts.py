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


# --- nommer lequel des deux appels ----------------------------------------
#
# `str(CodeRef)` rend `path:line`, ce qui suffit partout sauf là où deux
# findings partagent une ligne. `site` existe pour les distinguer — il entre
# dans `compute_id` — mais aucun rendu ne le montrait : ni les trois rapports,
# ni le contexte remis à l'agent qui juge. Celui-ci recevait donc deux tâches
# au libellé identique pour deux appels différents, et un verdict rendu sur
# l'un pouvait raisonnablement parler pour l'autre.


def test_a_location_without_a_site_reads_as_before():
    from thot.contracts import CodeRef

    reference = CodeRef(path="a.ts", line=219, symbol="load", ast_hash="h")

    assert reference.pinpoint() == "a.ts:219"
    assert str(reference) == "a.ts:219"


def test_a_location_with_a_site_names_which_call():
    from thot.contracts import CodeRef

    reference = CodeRef(path="a.ts", line=219, symbol="load", ast_hash="h",
                        site="join#1")

    assert reference.pinpoint() == "a.ts:219 (join#1)"
    assert str(reference) == "a.ts:219", "`str` ne change pas : il sert de clé ailleurs"
