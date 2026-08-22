import json

import pytest

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
    def fake_start(root, config, **kwargs):
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


# -- every subcommand must actually reach its handler ------------------------


def test_no_subcommand_argument_shadows_the_dispatch_key():
    """`thot sandbox show` silently printed the help for a while.

    Its positional was named `command`, which is the top-level subparser's
    own dest: parsing overwrote `args.command` with the shell command, the
    dispatch matched nothing, and argparse printed the usage as if the user
    had typed nonsense. Any future collision fails here instead.
    """
    from thot.cli import build_parser

    parser = build_parser()
    subparsers = [action for action in parser._actions
                  if hasattr(action, "choices") and action.choices
                  and action.dest == "command"]
    assert subparsers, "le parseur doit avoir des sous-commandes"

    offenders = []
    for name, sub in subparsers[0].choices.items():
        for argument in sub._actions:
            if argument.dest == "command":
                offenders.append(f"{name}.{argument.dest}")
            # A nested subparser's dest must not collide either.
            if getattr(argument, "choices", None) and argument.dest == "command":
                offenders.append(f"{name} (sous-commandes)")
    assert offenders == [], f"dest en collision avec la dispatch : {offenders}"


@pytest.mark.parametrize(
    "argv",
    [
        ["skills", "list"],
        ["mcp", "list"],
        ["sandbox", "status"],
        ["sandbox", "show", "pytest", "-q"],
        ["gateway", "list"],
        ["deps", ".", "--list"],
        ["sessions", "--all"],
        ["verdicts", "--where"],
    ],
)
def test_each_subcommand_reaches_a_handler(argv, isolated_home, monkeypatch,
                                           capsys, tmp_path):
    """Not about the output — about the dispatch not falling through to help."""
    from thot.cli import main

    monkeypatch.chdir(tmp_path)
    code = main(argv)
    printed = capsys.readouterr().out

    assert code in (0, 2), f"{argv} a rendu {code}"
    assert "positional arguments:" not in printed, (
        f"{argv} est retombé sur l'aide au lieu d'un gestionnaire"
    )


def test_a_verdict_pointing_at_nothing_is_listed_as_such(
    isolated_home, monkeypatch, capsys, toy_repo
):
    """A decision outlives the finding that produced it.

    Six decisions of which three are dead should not read as six live ones —
    that is how a memory quietly stops meaning anything.
    """
    from thot.cli import main
    from thot.memory import Decision, Verdict, build_memory
    from thot.paths import run_store
    from thot.pipeline import run_audit
    from thot.store.db import Store

    store = Store.open(run_store())
    try:
        result = run_audit(toy_repo, store, require_authorization=False)
    finally:
        store.close()

    live = result.findings[0]
    ghost = Verdict(
        finding_id="0" * 16, decision=Decision.REFUTED, reason="code disparu",
        author="dev", rule="sink.os.system", path="src/parti.py",
        symbol="src.parti.run", ast_hash="vieux", decided_at="",
    )
    memory = build_memory(toy_repo)
    try:
        memory.remember(Verdict.of(live, Decision.REFUTED, "littéral", "dev"))
        memory.remember(ghost)
    finally:
        memory.close()

    monkeypatch.chdir(toy_repo)
    assert main(["verdicts"]) == 0
    printed = capsys.readouterr().out

    assert "1 sans finding correspondant" in printed
    ghost_line = next(l for l in printed.splitlines() if l.startswith("0" * 16))
    live_line = next(l for l in printed.splitlines() if l.startswith(live.id))
    assert "absent du dernier audit" in ghost_line
    assert "absent du dernier audit" not in live_line


def test_nothing_is_called_stale_before_the_first_audit(
    isolated_home, monkeypatch, capsys, toy_repo
):
    """Never having audited here is not evidence that a decision is dead."""
    from thot.cli import main
    from thot.memory import Decision, Verdict, build_memory

    memory = build_memory(toy_repo)
    try:
        memory.remember(Verdict(
            finding_id="a" * 16, decision=Decision.REFUTED, reason="r",
            author="dev", rule="sink.eval", path="src/app.py",
            symbol="src.app.run", ast_hash="h", decided_at="",
        ))
    finally:
        memory.close()

    monkeypatch.chdir(toy_repo)
    assert main(["verdicts"]) == 0
    assert "absent du dernier audit" not in capsys.readouterr().out


def test_a_path_that_is_not_a_directory_is_refused_not_created(
    isolated_home, tmp_path, capsys
):
    """Authorising a directory into existence is how a typo becomes a
    mandate — and the audit would then report it as clean."""
    from thot.cli import main

    missing = tmp_path / "faute-de-frappe"
    assert main(["init", str(missing)]) != 0
    assert not missing.exists()
    assert "pas un dossier" in capsys.readouterr().err


def test_auditing_a_missing_path_says_so_rather_than_reporting_nothing(
    isolated_home, tmp_path
):
    from thot.errors import ScopeError
    from thot.pipeline import run_audit

    import pytest as _pytest

    with _pytest.raises(ScopeError):
        run_audit(tmp_path / "absent", require_authorization=False)


def test_the_progress_line_tells_the_three_kinds_of_undecided_apart(capsys):
    """An agent that failed, a model that hesitated, and a refutation a second
    agent refused to stand behind all leave the finding `plausible`.

    The last is a result, not an absence: it is the program catching itself
    about to bury a defect.
    """
    from dataclasses import replace

    from thot.cli import _deep_progress
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    base = Finding(
        id="1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="a.py", line=1, symbol="f", ast_hash="h"),
    )
    show = _deep_progress()
    show(replace(base, provenance={"moteur": "hermes"}))
    show(replace(base, provenance={"moteur": "hermes",
                                   "erreur": "délai dépassé (600s)"}))
    show(replace(base, provenance={"moteur": "hermes", "relecture": "prime",
                                   "réfutation contestée": "la ligne est bien là"}))

    lines = capsys.readouterr().err.splitlines()
    assert "sans verdict" in lines[0]
    assert "échec : délai dépassé (600s)" in lines[1]
    assert "réfutation contestée" in lines[2] and "prime" in lines[2]


def test_the_report_is_handed_the_whole_pass_not_only_what_is_shown(
    toy_repo, capsys, monkeypatch
):
    """A refutation lands on INFO, so it always falls below the display floor.

    `_confidence_note` counts refutations, but the CLI handed it only the
    findings the threshold kept — so a `--deep` pass that argued two findings
    away closed on "Chaque finding est PLAUSIBLE". The wiring is what makes
    the note able to see them, and nothing exercised it.
    """
    from thot import console

    seen = {}
    real = console.print_report

    def spy(result, hidden=0, judged=None):
        seen["judged"] = judged
        return real(result, hidden=hidden, judged=judged)

    monkeypatch.setattr(console, "print_report", spy)
    write_authorization(toy_repo, owner="tester")
    cli.main(["audit", str(toy_repo), "--no-store"])
    capsys.readouterr()

    assert seen.get("judged") is not None, "le CLI n'a pas transmis la passe entière"


def test_the_json_summary_counts_findings_the_threshold_hid(toy_repo, capsys):
    """`total` follows the display floor; `by_confidence` must not.

    With everything hidden, a consumer still has to be able to see that the
    run found — and judged — something. Passing only the kept findings made
    the two agree by accident on any run where nothing was filtered, which is
    why this test raises the floor.
    """
    write_authorization(toy_repo, owner="tester")
    cli.main(["audit", str(toy_repo), "--json", "--no-store",
              "--min-severity", "critical"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["summary"]["total"] == 0
    assert payload["summary"]["hidden_below_threshold"] >= 1
    assert sum(payload["summary"]["by_confidence"].values()) >= 1, payload["summary"]
    assert "engine" in payload["summary"]
