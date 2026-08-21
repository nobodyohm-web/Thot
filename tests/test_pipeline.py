import pytest

from thot.contracts import Severity
from thot.errors import AuthorizationError
from thot.pipeline import run_audit
from thot.scope.authorization import write_authorization


def test_end_to_end_finds_the_command_injection(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    rules = {f.rule for f in result.findings}
    assert "sink.os.system" in rules


def test_unauthorized_repo_raises(toy_repo):
    with pytest.raises(AuthorizationError):
        run_audit(toy_repo)


def test_findings_carry_computed_severity_and_a_scenario(toy_repo):
    write_authorization(toy_repo, owner="tester")
    result = run_audit(toy_repo)
    finding = next(f for f in result.findings if f.rule == "sink.os.system")
    assert finding.severity in set(Severity)
    assert finding.failure_scenario


def test_clean_repo_produces_no_findings(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    write_authorization(tmp_path, owner="tester")
    assert run_audit(tmp_path).findings == []


def test_store_persists_the_run(toy_repo, tmp_path):
    from thot.store.db import Store

    write_authorization(toy_repo, owner="tester")
    store = Store.open(tmp_path / "s.db")
    result = run_audit(toy_repo, store=store)
    assert result.run_id is not None
    assert len(store.findings_for_run(result.run_id)) == len(result.findings)
    assert store.cached_symbol_hashes()
    store.close()
