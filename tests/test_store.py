from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.store.db import Store


def make_finding(rule="sink.os.system"):
    ref = CodeRef(path="src/app.py", line=10, symbol="src.app.run", ast_hash="abc")
    return Finding(
        id=Finding.compute_id(rule, ref),
        rule=rule,
        severity=Severity.CRITICAL,
        confidence=Confidence.PLAUSIBLE,
        location=ref,
        taint_path=(ref,),
        failure_scenario="argv reaches os.system",
    )


def test_schema_is_created_on_open(tmp_path):
    store = Store.open(tmp_path / "s.db")
    assert store.findings_for_run(1) == []
    store.close()


def test_findings_round_trip(tmp_path):
    store = Store.open(tmp_path / "s.db")
    run_id = store.start_run(root="/repo", commit="deadbeef")
    store.save_findings(run_id, [make_finding()])
    loaded = store.findings_for_run(run_id)
    assert len(loaded) == 1
    assert loaded[0].rule == "sink.os.system"
    assert loaded[0].severity == Severity.CRITICAL
    assert loaded[0].location.line == 10
    assert loaded[0].taint_path[0].path == "src/app.py"
    store.close()


def test_symbol_cache_round_trips(tmp_path):
    store = Store.open(tmp_path / "s.db")
    store.remember_symbols({"src.app.main": "hash1"})
    assert store.cached_symbol_hashes()["src.app.main"] == "hash1"
    store.close()


def test_saving_the_same_finding_twice_keeps_one_row(tmp_path):
    store = Store.open(tmp_path / "s.db")
    run_id = store.start_run(root="/repo", commit=None)
    store.save_findings(run_id, [make_finding(), make_finding()])
    assert len(store.findings_for_run(run_id)) == 1
    store.close()


def test_the_scheduler_can_write_while_a_session_reads(tmp_path):
    """The daemon audits on its own clock; a reader must not lock it out.

    Outside WAL a single open read transaction makes every write wait for
    the busy timeout and then fail — five seconds lost, then a traceback.
    """
    import sqlite3

    path = tmp_path / "s.db"
    store = Store.open(path)
    reader = sqlite3.connect(path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM runs").fetchall()
    try:
        run_id = store.start_run(root="/repo", commit=None)
        store.save_findings(run_id, [make_finding()])
    finally:
        reader.close()
        store.close()
