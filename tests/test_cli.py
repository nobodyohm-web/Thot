import json

from thot import cli
from thot.scope.authorization import write_authorization


def test_version_flag_prints_version_and_exits_zero(capsys):
    code = cli.main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert "thot" in captured.out.lower()


def test_no_command_opens_the_session(monkeypatch):
    """`thot` alone is the product: it connects if needed, then opens a session."""
    calls = {}
    monkeypatch.setattr(
        "thot.onboarding.ensure_configured", lambda: "fake-config"
    )
    def fake_start(root, config):
        calls["started"] = (root, config)
        return 0

    monkeypatch.setattr("thot.session.start", fake_start)
    assert cli.main([]) == 0
    assert calls["started"][1] == "fake-config"


def test_help_lists_the_commands(capsys):
    code = cli.main(["--help"])
    captured = capsys.readouterr()
    assert code == 0
    assert "audit" in captured.out
    assert "login" in captured.out


def test_init_creates_the_authorization_file(tmp_path):
    code = cli.main(["init", str(tmp_path), "--owner", "Dev"])
    assert code == 0
    assert (tmp_path / ".thot" / "authorization.yaml").exists()


def test_audit_without_authorization_exits_three(toy_repo, capsys):
    code = cli.main(["audit", str(toy_repo), "--no-store"])
    captured = capsys.readouterr()
    assert code == 3
    assert "autorisation" in (captured.out + captured.err).lower()


def test_audit_json_output_is_valid(toy_repo, capsys):
    write_authorization(toy_repo, owner="tester")
    code = cli.main(["audit", str(toy_repo), "--json", "--no-store"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["summary"]["total"] >= 1
    assert code in (0, 1)


def test_fail_on_low_exits_one(toy_repo):
    write_authorization(toy_repo, owner="tester")
    code = cli.main(
        ["audit", str(toy_repo), "--json", "--no-store", "--fail-on", "low"]
    )
    assert code == 1


def test_out_file_is_written(toy_repo, tmp_path):
    write_authorization(toy_repo, owner="tester")
    target = tmp_path / "report.md"
    cli.main(
        ["audit", str(toy_repo), "--markdown", "--no-store", "--out", str(target)]
    )
    assert "Rapport d'audit Thot" in target.read_text()


def test_low_findings_are_hidden_by_default(toy_repo, capsys):
    """A report that shows everything shows nothing. Default floor is medium."""
    write_authorization(toy_repo, owner="tester")
    cli.main(["audit", str(toy_repo), "--json", "--no-store"])
    default_payload = json.loads(capsys.readouterr().out)

    cli.main(["audit", str(toy_repo), "--json", "--no-store", "--all"])
    all_payload = json.loads(capsys.readouterr().out)

    assert all_payload["summary"]["total"] >= default_payload["summary"]["total"]
    assert "hidden_below_threshold" in default_payload["summary"]


def test_min_severity_low_shows_more_than_high(toy_repo, capsys):
    write_authorization(toy_repo, owner="tester")
    cli.main(["audit", str(toy_repo), "--json", "--no-store", "--min-severity", "low"])
    low = json.loads(capsys.readouterr().out)["summary"]["total"]
    cli.main(["audit", str(toy_repo), "--json", "--no-store", "--min-severity", "critical"])
    critical = json.loads(capsys.readouterr().out)["summary"]["total"]
    assert low >= critical
