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

    assert "1 hors du dernier audit de ce dépôt" in printed
    ghost_line = next(l for l in printed.splitlines() if l.startswith("0" * 16))
    live_line = next(l for l in printed.splitlines() if l.startswith(live.id))
    assert "hors du dernier audit" in ghost_line
    assert "hors du dernier audit" not in live_line


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


def test_the_markdown_report_is_handed_the_pass_and_the_engine(
    toy_repo, capsys, monkeypatch
):
    """Only a `--deep` run has an engine, so the wiring cannot be seen from
    the rendered text on a deterministic audit. It is checked at the call."""
    from thot.report import markdown_report

    seen = {}
    real = markdown_report.render_markdown

    def spy(findings, manifest, elapsed, hidden=0, judged=None, engine=None):
        seen["judged"], seen["engine"] = judged, engine
        return real(findings, manifest, elapsed, hidden=hidden,
                    judged=judged, engine=engine)

    monkeypatch.setattr(markdown_report, "render_markdown", spy)
    monkeypatch.setattr("thot.cli.render_markdown", spy, raising=False)
    write_authorization(toy_repo, owner="tester")
    cli.main(["audit", str(toy_repo), "--markdown", "--no-store"])
    capsys.readouterr()

    assert "judged" in seen, "le CLI n'a pas transmis la passe au rapport markdown"
    assert seen["judged"] is not None


def test_verdicts_from_another_tree_are_not_called_orphans(
    toy_repo, capsys, monkeypatch, isolated_home
):
    """The memory is shared across trees; the audit is per repository.

    A verdict recorded against a finding in `hermes/` has no counterpart in
    Thot's own last audit, and the listing called that "sans finding
    correspondant" with "[absent du dernier audit]" on every line. Measured on
    this machine: 446 of 450 decisions, 99%, every one of them valid and
    scoped to another tree. A reader who trusts that wording forgets them.
    """
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.memory import build_memory
    from thot.memory.base import record_verdicts

    elsewhere = CodeRef(path="hermes/utils.py", line=3, symbol="fetch",
                        ast_hash="z")
    finding = Finding(
        id=Finding.compute_id("sink.network", elsewhere), rule="sink.network",
        severity=Severity.INFO, confidence=Confidence.REFUTED,
        location=elsewhere,
        failure_scenario="x\n\nRéfuté : garde en amont",
    )
    # Un audit stocké, sinon rien n'est dit « hors du dernier audit » — le
    # compteur se tait tant qu'aucune passe n'a été enregistrée, et un autre
    # test épingle ce silence.
    from thot.paths import run_store
    from thot.pipeline import run_audit
    from thot.store.db import Store

    store = Store.open(run_store())
    try:
        run_audit(toy_repo, store, require_authorization=False)
    finally:
        store.close()

    memory = build_memory(toy_repo)
    try:
        record_verdicts([finding], memory, author="hermes")
    finally:
        memory.close()

    monkeypatch.chdir(toy_repo)
    assert cli.main(["verdicts"]) == 0
    out = capsys.readouterr().out

    assert "sans finding correspondant" not in out, out
    assert "hors du dernier audit de ce dépôt" in out, out
    # Et la raison : sans elle, « hors du dernier audit » invite encore à
    # supprimer une décision parfaitement valide.
    assert "commune aux dépôts" in out, out


def test_verdicts_can_be_asked_about_another_tree(toy_repo, tmp_path, capsys,
                                                  monkeypatch, isolated_home):
    """The listing advertises `thot verdicts <chemin>`; it has to exist.

    The command read `Path.cwd()` and took no positional argument, so the
    advice added one commit earlier pointed at a usage error. Nothing caught
    it because every test chdirs first and calls `verdicts` bare — the same
    shortcut that let the advice be written without being run.

    The assertion has to be the out-of-scope count, not the presence of the
    verdict: the memory is global, so the decision is listed from any root and
    a first version of this test passed with the argument ignored.
    """
    from thot.memory import build_memory
    from thot.memory.base import Decision, Verdict
    from thot.paths import run_store
    from thot.pipeline import run_audit
    from thot.store.db import Store

    other = tmp_path / "ailleurs"
    (other / "src").mkdir(parents=True)
    (other / "src" / "app.py").write_text(
        "import os, sys\n\n\ndef run():\n    os.system(sys.argv[1])\n",
        encoding="utf-8",
    )

    store = Store.open(run_store())
    try:
        here = run_audit(toy_repo, store, require_authorization=False)
        there = run_audit(other, store, require_authorization=False)
    finally:
        store.close()

    assert there.findings, "le dépôt témoin n'a produit aucun finding"
    memory = build_memory(other)
    try:
        memory.remember(
            Verdict.of(there.findings[0], Decision.REFUTED, "littéral", "prime")
        )
    finally:
        memory.close()

    monkeypatch.chdir(toy_repo)

    assert cli.main(["verdicts", str(other)]) == 0
    asked_there = capsys.readouterr().out
    assert cli.main(["verdicts"]) == 0
    asked_here = capsys.readouterr().out

    assert "hors du dernier audit" not in asked_there, asked_there
    assert "hors du dernier audit" in asked_here, asked_here
    assert here.findings is not None


def test_verdicts_without_an_argument_still_means_here(toy_repo, capsys,
                                                       monkeypatch):
    monkeypatch.chdir(toy_repo)

    assert cli.main(["verdicts"]) == 0


# --- une phrase d'aide est une affirmation sur le programme ----------------
#
# `thot verdicts <chemin>` a été conseillé dans une sortie alors que la
# commande ne prenait pas d'argument : le conseil pointait sur une erreur
# d'usage. Écrire une phrase d'aide, c'est affirmer quelque chose du
# programme, et cela mérite la même vérification qu'une ligne de code.


def _advertised_commands() -> set[tuple[str, ...]]:
    """Every `thot …` command quoted in the source, as token tuples."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    quoted = re.compile(r"`thot ((?:[a-z][a-z-]*)(?: [a-z][a-z-]*)*)")
    found: set[tuple[str, ...]] = set()
    sources = [
        path
        for folder in ("src/thot", "plugins")
        for path in (root / folder).rglob("*.py")
        if "__pycache__" not in path.parts
    ]
    # The README too: it is the first thing anyone reads, and a command that
    # does not exist wastes their first minute. How many there are is not
    # written here — the count drifted the moment five commands were added,
    # and `test_the_sweep_actually_finds_commands` already holds the floor
    # that matters, which is that this sweep finds anything at all.
    sources.append(root / "README.md")
    for path in sources:
        for match in quoted.findall(path.read_text(encoding="utf-8")):
            found.add(tuple(match.split()))
    return found


def test_every_command_the_program_suggests_exists():
    import argparse

    from thot import cli

    parser = cli.build_parser()
    top = parser._subparsers._group_actions[0].choices
    inner = {}
    for name, sub in top.items():
        for action in sub._actions:
            if isinstance(action, argparse._SubParsersAction):
                inner[name] = set(action.choices)

    unknown = []
    for tokens in sorted(_advertised_commands()):
        if tokens[0] not in top:
            unknown.append(" ".join(tokens))
            continue
        if len(tokens) > 1 and tokens[0] in inner and tokens[1] not in inner[tokens[0]]:
            unknown.append(" ".join(tokens))

    assert unknown == [], unknown


def test_the_sweep_actually_finds_commands():
    """Guard the guard: an empty sweep would pass the test above silently."""
    assert len(_advertised_commands()) >= 25


def test_every_slash_command_the_readme_documents_exists():
    """Same claim, other interface: `/x` in the README must resolve.

    Three of them — /triage, /harden, /regress — are not built-ins but shipped
    custom commands, which the README states outright ("Trois sont livrées").
    Checked rather than trusted: all three load.
    """
    import re
    from pathlib import Path

    from thot.commands import discover

    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "thot" / "session.py").read_text(encoding="utf-8")

    builtin = set(re.findall(r'command == "([a-z-]+)"', source))
    for group in re.findall(r"command in \{([^}]*)\}", source):
        builtin |= {
            word.strip().strip("\"'") for word in group.split(",") if word.strip()
        }
    shipped = {getattr(item, "name", "") for item in discover(root)}

    documented = {
        name.strip("`/")
        for name in re.findall(r"`(/[a-z-]+)`",
                               (root / "README.md").read_text(encoding="utf-8"))
    }

    assert documented, "aucune commande de session citée dans le README"
    assert documented - builtin - shipped == set(), documented - builtin - shipped


# --- le code de sortie est le contrat avec une chaîne d'intégration --------
#
# Un seul test le couvrait : `--fail-on low` sort en 1. Les deux propriétés
# qui décident d'un pipeline ne l'étaient pas — ne pas échouer à tort, et ne
# pas laisser le seuil d'affichage masquer un échec. La seconde porte un
# commentaire explicite dans `cli.py` (« the floor never hides a CI
# failure ») et rien ne la tenait.


def _severities(toy_repo) -> set[str]:
    import json as _json

    from thot.paths import run_store
    from thot.pipeline import run_audit
    from thot.store.db import Store

    store = Store.open(run_store())
    try:
        result = run_audit(toy_repo, store, require_authorization=False)
    finally:
        store.close()
    del _json
    return {f.severity.value for f in result.findings}


def test_a_threshold_above_everything_found_does_not_fail(toy_repo, capsys):
    write_authorization(toy_repo, owner="tester")
    found = _severities(toy_repo)
    capsys.readouterr()
    assert "critical" not in found, "le dépôt témoin a changé : plus de repère"

    code = cli.main(
        ["audit", str(toy_repo), "--json", "--no-store", "--fail-on", "critical"]
    )
    capsys.readouterr()

    assert code == 0


def test_the_display_floor_never_hides_a_failure(toy_repo, capsys):
    """`--min-severity` is a reading convenience, not a way to pass CI."""
    write_authorization(toy_repo, owner="tester")
    found = _severities(toy_repo)
    capsys.readouterr()
    assert "high" in found, "le dépôt témoin a changé : plus de repère"

    code = cli.main([
        "audit", str(toy_repo), "--json", "--no-store",
        "--fail-on", "high", "--min-severity", "critical",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert payload["summary"]["total"] == 0, "tout devait être masqué"
    assert code == 1, "le seuil d'affichage a caché un échec"


# --- le même contrat, pour l'audit de dépendances --------------------------
#
# `thot deps --fail-on` calcule `max(...)` sur les findings : une liste vide
# lèverait `ValueError`. Un retour anticipé protège l'appel — vérifié sur un
# arbre sain, code 0 sans plantage — et rien ne le tenait. Les trois cas qui
# décident d'un pipeline non plus.


def _deps_result(findings, checked=True):
    from thot.supply.audit import SupplyResult

    return SupplyResult(findings, components=3, checked=checked)


def _vulnerable(severity):
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    return Finding(
        id="v1", rule="supply.vulnerable", severity=Severity(severity),
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="requirements.txt", line=1, symbol="requests",
                         ast_hash="h"),
        failure_scenario="GHSA-xxxx — requests@2.19.1 est couvert",
        provenance={"paquet": "requests@2.19.1", "avis": "GHSA-xxxx"},
    )


def test_deps_without_a_vulnerability_never_fails(toy_repo, capsys, monkeypatch):
    from thot import supply

    monkeypatch.setattr(supply, "audit_dependencies",
                        lambda root, **kw: _deps_result([]))

    code = cli.main(["deps", str(toy_repo), "--fail-on", "low"])
    capsys.readouterr()

    assert code == 0


def test_deps_fails_when_something_reaches_the_threshold(toy_repo, capsys,
                                                         monkeypatch):
    from thot import supply

    monkeypatch.setattr(supply, "audit_dependencies",
                        lambda root, **kw: _deps_result([_vulnerable("high")]))

    code = cli.main(["deps", str(toy_repo), "--fail-on", "high"])
    capsys.readouterr()

    assert code == 1


def test_deps_does_not_fail_below_the_threshold(toy_repo, capsys, monkeypatch):
    from thot import supply

    monkeypatch.setattr(supply, "audit_dependencies",
                        lambda root, **kw: _deps_result([_vulnerable("high")]))

    code = cli.main(["deps", str(toy_repo), "--fail-on", "critical"])
    capsys.readouterr()

    assert code == 0


# --- le docteur est fait pour tenir dans une chaîne ------------------------
#
# Sa docstring énonce le contrat : « non nul en cas d'échec, pour qu'il puisse
# tenir dans un job d'intégration ou une chaîne `&&` — un diagnostic sur
# lequel personne ne peut agir automatiquement est un diagnostic qu'on cesse
# de lancer ». Rien ne le tenait. Sur cette machine il rend bien 4 avec un
# contrôle en échec, mais personne ne l'avait vérifié dans l'autre sens.


def _check(name, ok):
    from thot.doctor import Check

    return Check(name, ok, "peu importe")


def test_the_doctor_fails_the_shell_when_a_check_fails(capsys, monkeypatch):
    from thot import doctor

    monkeypatch.setattr(doctor, "run",
                        lambda root: [_check("a", True), _check("b", False)])

    code = cli.main(["doctor"])
    capsys.readouterr()

    assert code != 0


def test_the_doctor_says_nothing_is_wrong_by_exiting_zero(capsys, monkeypatch):
    from thot import doctor

    monkeypatch.setattr(doctor, "run",
                        lambda root: [_check("a", True), _check("b", True)])

    code = cli.main(["doctor"])
    capsys.readouterr()

    assert code == 0


# --- nommer une condition sans donner de moyen d'agir ----------------------
#
# `thot sessions` annonce « N session(s) vide(s) non listée(s) — un processus
# tué ne peut pas se ranger », et rien ne permettait de les retirer : leurs
# identifiants sont précisément ce que la liste masque, et `--forget` en
# demande un. Le remède est ajouté d'abord, cité ensuite.


def _empty_session(root):
    from thot.state.store import SessionStore

    store = SessionStore.open()
    try:
        return store.start(str(root), title="tuée en route")
    finally:
        store.close()


def test_empty_sessions_can_be_forgotten(toy_repo, capsys, monkeypatch):
    from thot.state.store import SessionStore

    _empty_session(toy_repo)
    monkeypatch.chdir(toy_repo)

    assert cli.main(["sessions", "--forget-empty"]) == 0
    out = capsys.readouterr().out

    assert "1" in out
    store = SessionStore.open()
    try:
        assert [i for i in store.sessions(str(toy_repo), limit=50)
                if not i.message_count] == []
    finally:
        store.close()


def test_the_notice_points_at_the_remedy(toy_repo, capsys, monkeypatch):
    _empty_session(toy_repo)
    _empty_session(toy_repo)
    monkeypatch.chdir(toy_repo)

    cli.main(["sessions"])
    out = capsys.readouterr().out

    assert "vide" in out
    assert "--forget-empty" in out, out


def test_the_notice_below_a_real_listing_points_at_the_remedy(
    toy_repo, capsys, monkeypatch
):
    """Two notices say this; the earlier test only reached one of them.

    With every session empty the listing stops before the table and prints the
    short form. The long one, below a real listing, is the case a user
    actually meets — and the mutation showed it was uncovered.
    """
    from thot.state.store import SessionStore

    store = SessionStore.open()
    try:
        real = store.start(str(toy_repo), title="vraie")
        store.append(real, "user", "bonjour")
    finally:
        store.close()
    _empty_session(toy_repo)
    monkeypatch.chdir(toy_repo)

    cli.main(["sessions"])
    out = capsys.readouterr().out

    assert "vraie" in out, out
    assert "--forget-empty" in out, out


# --- un chemin absent n'est pas un dépôt sans problème ---------------------
#
# `audit` (pipeline.py) et `init` refusent tous deux un chemin qui n'est pas
# là ; `deps` était le seul point d'entrée à l'oublier, et il répondait
# « 0 dépendance(s), aucune vulnérabilité connue. » avec le code 0 — un feu
# vert de CI sur une faute de frappe.


def test_deps_refuses_a_path_that_is_not_there(tmp_path, capsys):
    code = cli.main(["deps", str(tmp_path / "absent"), "--fail-on", "critical"])
    err = capsys.readouterr().err

    assert code == cli.EXIT_USAGE
    assert "absent" in err


def test_deps_listing_refuses_a_path_that_is_not_there(tmp_path, capsys):
    code = cli.main(["deps", str(tmp_path / "absent"), "--list"])
    out, err = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "dépendance" not in out


def test_deps_refuses_a_file(tmp_path, capsys):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.1\n")

    code = cli.main(["deps", str(manifest)])
    capsys.readouterr()

    assert code == cli.EXIT_USAGE


# --- un chemin de sortie ne jette jamais l'audit ---------------------------
#
# `--out` écrivait sans garde et sans créer le parent : en CI, `--out
# reports/x.json` sortait une pile pathlib APRÈS l'audit complet, le rapport
# calculé n'allait nulle part, et le code 1 se lisait comme EXIT_FINDINGS.


def test_out_creates_the_missing_parent(toy_repo, tmp_path):
    write_authorization(toy_repo, owner="tester")
    target = tmp_path / "reports" / "nested" / "report.md"

    code = cli.main(
        ["audit", str(toy_repo), "--markdown", "--no-store", "--out", str(target)]
    )

    assert code == 0
    assert "Rapport d'audit Thot" in target.read_text()


def test_an_unwritable_out_keeps_the_report_on_stdout(toy_repo, tmp_path, capsys):
    write_authorization(toy_repo, owner="tester")
    blocker = tmp_path / "blocker"
    blocker.write_text("pas un dossier")

    code = cli.main(
        ["audit", str(toy_repo), "--json", "--no-store", "--out",
         str(blocker / "report.json")]
    )
    out, err = capsys.readouterr()

    assert code == cli.EXIT_ERROR
    json.loads(out)
    assert "Rapport non écrit" in err


# --- l'identifiant imprimé est l'identifiant accepté -----------------------
#
# `skills list` et `skills search` impriment `catégorie/nom` ; `show` et
# `install` ne comparaient que `nom`. Copier l'identifiant que le programme
# venait d'afficher, juste sous l'instruction qui dit de le faire, échouait
# en code 2. C'est l'invariant qui est testé, pas la forme du nom.


def _printed_identifier(text: str, *, after: str = "") -> str:
    lines = text.splitlines()
    if after:
        start = next(i for i, line in enumerate(lines) if after in line) + 1
        lines = lines[start:]
    for line in lines:
        columns = line.split()
        if columns and "/" in columns[0]:
            return columns[0]
    raise AssertionError(f"aucun identifiant qualifié dans :\n{text}")


def test_skills_show_accepts_what_skills_list_printed(toy_repo, capsys, monkeypatch):
    monkeypatch.chdir(toy_repo)
    assert cli.main(["skills", "list"]) == 0
    identifier = _printed_identifier(capsys.readouterr().out)

    code = cli.main(["skills", "show", identifier])
    out = capsys.readouterr().out

    assert code == 0
    assert identifier.split("/")[-1] in out


def test_skills_install_accepts_what_skills_search_printed(toy_repo, capsys,
                                                           monkeypatch):
    from thot.skills.loader import discover, optional

    monkeypatch.chdir(toy_repo)
    candidate = optional()[0]
    assert cli.main(["skills", "search", candidate.name]) == 0
    identifier = _printed_identifier(capsys.readouterr().out,
                                     after="Bibliothèque optionnelle")

    code = cli.main(["skills", "install", identifier])
    capsys.readouterr()

    assert code == 0
    assert candidate.name in {s.name for s in discover(toy_repo)}


# --- une pipe fermée n'est pas un verdict d'audit --------------------------
#
# `Console.on_broken_pipe` de rich fait `raise SystemExit(1)` ; 1 est
# EXIT_FINDINGS. `thot audit . | head -1` sortait donc en 1 sur un dépôt sans
# rien à signaler, stderr vide, sans aucun moyen de distinguer les deux.


def _audit_into(consumer: list[str], *arguments: str) -> tuple[int, str]:
    """Run a real `thot audit` whose stdout is a program that closes early."""
    import os
    import subprocess
    import sys

    reader = subprocess.Popen(consumer, stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL)
    audit = subprocess.Popen(
        [sys.executable, "-c", "from thot.cli import run; run()", *arguments],
        stdout=reader.stdin, stderr=subprocess.PIPE, env=dict(os.environ),
    )
    assert reader.stdin is not None
    reader.stdin.close()
    error = audit.communicate()[1].decode()
    reader.wait()
    return audit.returncode, error


def test_a_pipe_closed_early_does_not_report_findings(toy_repo):
    write_authorization(toy_repo, owner="tester")

    code, error = _audit_into(["true"], "audit", str(toy_repo), "--no-store")

    assert code == cli.EXIT_OK, f"code={code} stderr={error}"


def test_a_pipe_closed_early_still_lets_fail_on_speak(toy_repo):
    """The other half: going quiet must not swallow a real CI failure.

    Answering EXIT_OK on a broken pipe would be the easy fix and the wrong
    one — `--fail-on` is computed after the printing, and its verdict is the
    reason the command was run.
    """
    write_authorization(toy_repo, owner="tester")

    code, error = _audit_into(["true"], "audit", str(toy_repo),
                              "--no-store", "--fail-on", "low")

    assert code == cli.EXIT_FINDINGS, f"code={code} stderr={error}"


def test_a_reader_that_never_reads_leaves_no_exception_behind(toy_repo):
    """`--json` goes through print(), not rich: a second, separate path.

    A consumer already gone when the report is written made the interpreter
    fail its final flush — « Exception ignored … BrokenPipeError », code 120.
    """
    write_authorization(toy_repo, owner="tester")

    code, error = _audit_into(["true"], "audit", str(toy_repo),
                              "--json", "--no-store")

    assert code == cli.EXIT_OK, f"code={code} stderr={error}"
    assert "BrokenPipeError" not in error


# --- Ctrl-C n'est pas un incident du programme ----------------------------
#
# `main()` n'attrape que AuthorizationError/ThotError : un Ctrl-C pendant un
# audit déversait une pile de vingt lignes jusque dans `ast.parse`. Le code
# de sortie, lui, était déjà bon — CPython réarme SIGINT et se re-tue — et le
# correctif le préserve : mourir du signal, pas d'un exit(130), est ce que
# make et les boucles shell inspectent.


def _run_interrupted() -> tuple[int, str]:
    """Drive `cli.run()` in a child whose `main()` receives a real SIGINT."""
    import os
    import subprocess
    import sys

    body = (
        "import os, signal\n"
        "from thot import cli\n"
        "def interrupted(argv=None):\n"
        "    os.kill(os.getpid(), signal.SIGINT)\n"
        "    return 0\n"
        "cli.main = interrupted\n"
        "cli.run()\n"
    )
    done = subprocess.run([sys.executable, "-c", body], capture_output=True,
                          text=True, env=dict(os.environ))
    return done.returncode, done.stderr


def test_an_interrupted_command_says_so_instead_of_unwinding():
    code, error = _run_interrupted()

    assert "Interrompu." in error, error
    assert "Traceback" not in error, error


def test_an_interrupted_command_still_dies_of_the_signal():
    import signal

    code, _ = _run_interrupted()

    assert code == -signal.SIGINT


# --- une base de ~/.thot illisible n'est pas une pile Python ---------------
#
# `Session._open_state` applique déjà la règle — « A store that will not open
# costs history, not the session » ; le CLI, lui, sortait une traceback
# sqlite3 sur presque toutes les commandes, en code 1, c'est-à-dire
# EXIT_FINDINGS, sans nommer ni le fichier ni le geste qui répare.


def _corrupt(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"ceci n'est pas une base sqlite\n" * 8)


def test_an_unreadable_run_store_costs_history_not_the_audit(toy_repo, capsys):
    from thot.paths import run_store

    write_authorization(toy_repo, owner="tester")
    _corrupt(run_store())

    code = cli.main(["audit", str(toy_repo), "--json"])
    out, err = capsys.readouterr()

    assert code == 0
    json.loads(out), "le rapport doit rester un rapport"
    assert str(run_store()) in err


def test_an_unreadable_memory_costs_verdicts_not_the_audit(toy_repo, capsys):
    from thot.paths import memory_db

    write_authorization(toy_repo, owner="tester")
    _corrupt(memory_db())

    code = cli.main(["audit", str(toy_repo), "--json", "--no-store"])
    out, err = capsys.readouterr()

    assert code == 0
    json.loads(out)
    assert str(memory_db()) in err


def test_an_unreadable_session_store_names_the_file_and_the_remedy(capsys):
    from thot.paths import sessions_db

    _corrupt(sessions_db())

    code = cli.main(["sessions"])
    err = capsys.readouterr().err

    assert code == cli.EXIT_ERROR, "1 se lirait comme EXIT_FINDINGS"
    assert str(sessions_db()) in err
    assert "supprimer" in err


def test_an_unreadable_session_store_stops_a_search_the_same_way(capsys):
    from thot.paths import sessions_db

    _corrupt(sessions_db())

    code = cli.main(["search", "parseur"])
    err = capsys.readouterr().err

    assert code == cli.EXIT_ERROR
    assert str(sessions_db()) in err


def test_an_unreadable_verdict_store_names_the_file_and_the_remedy(tmp_path,
                                                                   capsys):
    from thot.paths import memory_db

    _corrupt(memory_db())

    code = cli.main(["verdicts", str(tmp_path)])
    err = capsys.readouterr().err

    assert code == cli.EXIT_ERROR
    assert str(memory_db()) in err
    assert "supprimer" in err


# -- `--out` sans format écrivait dans le vide ------------------------------
#
# Le rendu n'existe que si `--json`, `--markdown` ou `--html` est demandé ;
# sinon `rendered is None` et la branche qui écrit le fichier n'est jamais
# atteinte. `thot audit . --out rapport.json` imprimait donc le rapport au
# terminal, ne créait aucun fichier, et sortait 0. Demander un fichier et
# repartir avec un succès sans fichier est la pire des trois issues — pire
# que la traceback d'origine, qui au moins se voyait.
#
# Le format se déduit du nom : c'est ce que l'utilisateur a déjà écrit.


def _petit_depot(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    write_authorization(tmp_path, owner="tester")
    return tmp_path


@pytest.mark.parametrize("nom, marqueur", [
    ("rapport.json", '"findings"'),
    ("rapport.md", "#"),
    ("rapport.html", "<html"),
])
def test_the_format_follows_the_name_that_was_asked_for(tmp_path, monkeypatch,
                                                        nom, marqueur):
    from thot import cli

    repo = _petit_depot(tmp_path / "repo")
    cible = tmp_path / "sortie" / nom

    code = cli.main(["audit", str(repo), "--out", str(cible)])

    assert code == 0, code
    assert cible.is_file(), "aucun fichier écrit"
    assert marqueur in cible.read_text(encoding="utf-8").lower()


def test_a_name_thot_cannot_render_is_refused_not_ignored(tmp_path):
    from thot import cli

    repo = _petit_depot(tmp_path / "repo")

    code = cli.main(["audit", str(repo), "--out", str(tmp_path / "rapport.xyz")])

    assert code != 0
    assert not (tmp_path / "rapport.xyz").exists()


def test_an_explicit_format_still_wins_over_the_name(tmp_path):
    from thot import cli

    repo = _petit_depot(tmp_path / "repo")
    cible = tmp_path / "rapport.txt"

    code = cli.main(["audit", str(repo), "--json", "--out", str(cible)])

    assert code == 0
    assert '"findings"' in cible.read_text(encoding="utf-8")


# -- evolve: which judge the command hands the loop ---------------------------


class _WritesNothing:
    """An agent that is installed and is never called.

    `_cmd_evolve` refuses before it picks a gate when no agent is available,
    so the tests below need one to exist; none of them lets it write.
    """

    def __init__(self, root, max_parallel=1):
        self.root = root

    @classmethod
    def available(cls):
        return True


@pytest.fixture
def evolve_judge(monkeypatch, tmp_path):
    """An evolve run with both expensive halves removed — no agent writes and
    no gate runs — so that what the command *chose* stays visible."""
    import thot.engine.factory as factory

    monkeypatch.setattr(factory, "AGENT_ENGINES", {"hermes": _WritesNothing})
    monkeypatch.setattr(factory, "available_engines", lambda: ["hermes"])

    seen = {}

    def fake_evolve(root, *, goals, gate, **kwargs):
        seen["gate"] = gate
        seen["goals"] = list(goals)
        return []

    monkeypatch.setattr("thot.evolve.evolve", fake_evolve)
    (tmp_path / "repo" / "src").mkdir(parents=True)
    seen["repo"] = tmp_path / "repo"
    return seen


def test_evolve_with_neither_a_goal_nor_a_measurement_to_take_one_from_is_refused(
    evolve_judge, capsys,
):
    """`goal` became optional so `--from-bench` could supply it. Optional and
    absent is a loop with nothing to do, and argparse cannot say that.

    The fixture is here for the failure case rather than the passing one:
    `--path` defaults to the working directory, so a regression that let this
    through would otherwise turn an agent loose on the repository under test.
    """
    code = cli.main(["evolve"])

    assert code == 2
    assert "--from-bench" in capsys.readouterr().err


def test_without_a_corpus_the_judge_stays_thots_opinion_of_itself(evolve_judge):
    """The behaviour that was there before the corpus existed, unchanged."""
    from thot.evolve import DEFAULT_GUARDS, thot_metrics

    code = cli.main(["evolve", "corriger", "xss", "--path", str(evolve_judge["repo"])])

    assert code == 0
    assert evolve_judge["gate"].guards == DEFAULT_GUARDS
    assert evolve_judge["gate"].metrics is thot_metrics
    assert evolve_judge["goals"] == ["corriger xss"]


def test_naming_a_corpus_moves_the_judge_onto_numbers_thot_did_not_compute(
    evolve_judge, capsys, tmp_path
):
    """No test in this repository asserts a detection rate, so a rule that
    stops firing passes green. That is what the corpus is for, and the line
    printed before the run has to name the guards actually in force."""
    from thot.evolve import BENCH_GUARDS

    code = cli.main(["evolve", "corriger xss", "--corpus", str(tmp_path / "bp"),
                     "--hold-out", "django", "--path", str(evolve_judge["repo"])])

    assert code == 0
    assert evolve_judge["gate"].guards == BENCH_GUARDS
    printed = " ".join(capsys.readouterr().out.split())
    assert "youden_holdout" in printed
    assert "django tenue à l'écart" in printed


def test_sans_mesure_wins_over_a_named_corpus_and_says_what_that_costs(
    evolve_judge, capsys, tmp_path
):
    """The escape hatch has to stay an escape hatch: asked for both, the
    command judges on the tests alone rather than quietly keeping the
    expensive guard the flag exists to drop."""
    code = cli.main(["evolve", "corriger xss", "--corpus", str(tmp_path / "bp"),
                     "--sans-mesure", "--path", str(evolve_judge["repo"])])

    assert code == 0
    assert evolve_judge["gate"].metrics is None
    assert evolve_judge["gate"].guards == {}
    assert "régression silencieuse" in capsys.readouterr().out


def test_from_bench_takes_the_goals_from_the_measurement(
    evolve_judge, monkeypatch, tmp_path, capsys
):
    """The loop could only ever chase what a human already suspected. A goal
    built from the score is the program saying where it is weakest in numbers
    it did not choose."""
    from thot.bench.score import Score, Tally

    measured = Score(suite="total",
                     by_category={"xxe": Tally(tp=0, fp=50, fn=50, tn=0),
                                  "sqli": Tally(tp=40, fp=2, fn=10, tn=48)},
                     cwe={"xxe": 611, "sqli": 89})
    monkeypatch.setattr("thot.bench.run.measure_all",
                        lambda path, **kwargs: ([measured], measured))

    code = cli.main(["evolve", "--from-bench", "--corpus", str(tmp_path / "bp"),
                     "--path", str(evolve_judge["repo"])])

    assert code == 0
    assert "xxe" in evolve_judge["goals"][0]
    assert "inversée" in evolve_judge["goals"][0]
    # Named with `goal_key`, which is what the ledger files them under: the
    # names on the screen and the names `recall` matches on are one list.
    assert "les pires d'abord : xxe, sqli" in " ".join(capsys.readouterr().out.split())


def test_a_measurement_that_names_nothing_stops_the_loop_instead_of_starting_it(
    evolve_judge, monkeypatch, tmp_path, capsys
):
    """`--from-bench` with no target is not an empty run to be reported at the
    end; it is a run that must not let an agent near the source."""
    from thot.bench.score import Score

    monkeypatch.setattr("thot.bench.run.measure_all",
                        lambda path, **kwargs: ([], Score(suite="total")))

    code = cli.main(["evolve", "--from-bench", "--corpus", str(tmp_path / "bp"),
                     "--path", str(evolve_judge["repo"])])

    assert code == 2
    assert "gate" not in evolve_judge
    assert "aucune catégorie" in capsys.readouterr().err.lower()


def test_a_corpus_that_cannot_be_read_stops_from_bench_rather_than_starting_blind(
    evolve_judge, tmp_path, capsys
):
    code = cli.main(["evolve", "--from-bench", "--corpus",
                     str(tmp_path / "nowhere"),
                     "--path", str(evolve_judge["repo"])])

    assert code == 2
    assert "gate" not in evolve_judge
    assert "corpus" in capsys.readouterr().err.lower()


def test_the_fused_loop_refuses_with_a_way_out_when_an_agent_is_missing(
    evolve_judge, monkeypatch, capsys
):
    """Two agents doing different work, or neither: a fused run that quietly
    fell back to one agent would attribute its own history to the wrong one."""
    import thot.engine.factory as factory
    from thot.engine.cascade import NoAgents

    def refuse(root, **kwargs):
        raise NoAgents("aucun des deux n'est joignable")

    monkeypatch.setattr(factory, "build_cascade", refuse)

    code = cli.main(["evolve", "corriger xss", "--fused",
                     "--path", str(evolve_judge["repo"])])

    assert code == 2
    assert "fusion status" in capsys.readouterr().err
    assert "gate" not in evolve_judge
