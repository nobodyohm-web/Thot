"""Verdict memory: decide once, never re-litigate.

The expensive part of an audit is not finding candidates, it is deciding what
they mean. Losing those decisions between runs is what makes security tooling
unbearable — the same forty false positives, every week, forever.

The pivot is that a verdict is keyed on Finding.compute_id, which hashes the
normalised AST of the symbol. Reformat the file and the verdict holds. Change
what the code does and the verdict expires by construction, so a dismissal can
never hide a regression.
"""

from __future__ import annotations

import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.memory import Decision, Verdict, apply_memory
from thot.memory.sqlite import SqliteMemory


@pytest.fixture
def memory(tmp_path):
    store = SqliteMemory.open(tmp_path / "memory.db")
    yield store
    store.close()


def make_finding(ast_hash="h1", rule="sink.os.system", severity=Severity.HIGH):
    location = CodeRef(path="app.py", line=9, symbol="run", ast_hash=ast_hash)
    return Finding(
        id=Finding.compute_id(rule, location),
        rule=rule,
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
        failure_scenario="candidat",
    )


# -- storage -----------------------------------------------------------------


def test_a_verdict_survives_a_reopen(tmp_path):
    path = tmp_path / "m.db"
    finding = make_finding()
    first = SqliteMemory.open(path)
    first.remember(Verdict.of(finding, Decision.REFUTED, "entrée constante", "dev"))
    first.close()

    second = SqliteMemory.open(path)
    try:
        assert second.recall(finding.id).reason == "entrée constante"
    finally:
        second.close()


def test_recalling_an_unknown_finding_gives_nothing(memory):
    assert memory.recall("jamais-vu") is None


def test_remembering_twice_updates_rather_than_duplicates(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "première raison"))
    memory.remember(Verdict.of(finding, Decision.ACCEPTED, "deuxième raison"))
    assert len(memory.all_verdicts()) == 1
    assert memory.recall(finding.id).decision is Decision.ACCEPTED


def test_forgetting_removes_the_verdict(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "x"))
    assert memory.forget(finding.id) is True
    assert memory.recall(finding.id) is None
    assert memory.forget(finding.id) is False


# -- application -------------------------------------------------------------


def test_a_refuted_finding_is_downgraded_not_deleted(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "entrée constante"))
    out = apply_memory([finding], memory)
    assert len(out) == 1
    assert out[0].confidence is Confidence.REFUTED
    assert "entrée constante" in out[0].failure_scenario


def test_an_accepted_risk_drops_to_info(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.ACCEPTED, "risque assumé"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.INFO
    assert "risque assumé" in out[0].failure_scenario


def test_an_untouched_finding_passes_through(memory):
    finding = make_finding()
    assert apply_memory([finding], memory)[0] == finding


def test_changing_the_code_expires_the_verdict(memory):
    """The whole safety property, in one test."""
    original = make_finding(ast_hash="before")
    memory.remember(Verdict.of(original, Decision.REFUTED, "sûr à l'époque"))

    edited = make_finding(ast_hash="after")
    out = apply_memory([edited], memory)
    assert out[0].confidence is Confidence.PLAUSIBLE
    assert "sûr à l'époque" not in out[0].failure_scenario


def test_a_fixed_finding_coming_back_is_a_regression(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.FIXED, "corrigé en mars"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.HIGH
    assert "régression" in out[0].failure_scenario.lower()
    assert out[0].provenance.get("régression") is True


def test_provenance_records_where_the_decision_came_from(memory):
    finding = make_finding()
    memory.remember(Verdict.of(finding, Decision.REFUTED, "x", "dev"))
    out = apply_memory([finding], memory)
    assert out[0].provenance["mémoire"] == "refuted"
    assert out[0].provenance["décidé par"] == "dev"


# -- the expensive pass is paid once ----------------------------------------


def test_adversarial_refutations_are_recorded(memory):
    """A refutation costs two model calls. It should cost them once."""
    from thot.memory import record_verdicts

    refuted = make_finding()
    refuted = refuted.__class__(**{**refuted.__dict__,
                                   "confidence": Confidence.REFUTED,
                                   "failure_scenario": "Réfuté : constante"})
    record_verdicts([refuted], memory, author="thot")
    assert memory.recall(refuted.id).decision is Decision.REFUTED


def test_only_refutations_are_recorded_automatically(memory):
    from thot.memory import record_verdicts

    confirmed = make_finding()
    record_verdicts([confirmed], memory, author="thot")
    assert memory.all_verdicts() == []


# -- what people actually type -----------------------------------------------


@pytest.mark.parametrize("word,expected", [
    ("refute", Decision.REFUTED), ("refuted", Decision.REFUTED),
    ("réfuté", Decision.REFUTED), ("écarter", Decision.REFUTED),
    ("accept", Decision.ACCEPTED), ("accepté", Decision.ACCEPTED),
    ("fix", Decision.FIXED), ("corrigé", Decision.FIXED),
    ("REFUTE", Decision.REFUTED), (" fixed ", Decision.FIXED),
])
def test_decisions_accept_what_people_type(word, expected):
    assert Decision.parse(word) is expected


def test_an_unknown_word_is_rejected_not_guessed():
    assert Decision.parse("peut-être") is None


def test_a_dismissed_finding_leaves_the_top_of_the_report(memory):
    """Dismissing must change the ranking, not just an invisible field."""
    finding = make_finding(severity=Severity.HIGH)
    memory.remember(Verdict.of(finding, Decision.REFUTED, "faux positif"))
    out = apply_memory([finding], memory)
    assert out[0].severity is Severity.INFO
    assert out[0].confidence is Confidence.REFUTED


# -- expiry, proved through the real pipeline --------------------------------
#
# The unit test above builds a Finding by hand and gives it an ast_hash, so it
# passed for months while the pipeline attached none to taint findings — every
# refutation of a taint finding was immortal. These go through run_audit.


def _vulnerable_repo(root, extra: str = ""):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "handlers.py").write_text(
        "import os\n"
        "import sys\n"
        "\n"
        "\n"
        "def handle():\n"
        f"{extra}"
        "    target = sys.argv[1]\n"
        "    os.system('ping -c1 ' + target)\n",
        encoding="utf-8",
    )
    return root


def _taint_findings(root):
    from thot.pipeline import run_audit

    result = run_audit(root, None, require_authorization=False)
    return [f for f in result.findings if f.rule.startswith("sink.")]


def test_a_taint_finding_carries_the_hash_of_the_code_it_accuses(tmp_path):
    """Without it, `compute_id` hashes an empty string and never changes."""
    findings = _taint_findings(_vulnerable_repo(tmp_path))

    assert findings, "le dépôt d'essai doit produire un chemin de teinte"
    assert findings[0].location.ast_hash, (
        "un finding de teinte sans empreinte AST porte un verdict immortel"
    )


def test_changing_the_accused_function_expires_its_verdict_end_to_end(tmp_path):
    from thot.contracts import Severity
    from thot.memory.base import apply_memory
    from thot.memory.jsonfile import JsonMemory

    before = _taint_findings(_vulnerable_repo(tmp_path))[0]
    memory = JsonMemory.open(tmp_path / "v.json")
    memory.remember(Verdict.of(before, Decision.REFUTED, "argv est de confiance"))

    dismissed = apply_memory([before], memory)[0]
    assert dismissed.severity is Severity.INFO

    # Change what the function does, without touching the dangerous line.
    after = _taint_findings(_vulnerable_repo(tmp_path, extra="    _ = 1\n"))[0]

    assert after.id != before.id, "l'identité doit suivre le corps de la fonction"
    assert apply_memory([after], memory)[0].severity is not Severity.INFO


def test_moving_the_function_down_the_file_keeps_the_verdict(tmp_path):
    """Identity is the body, not the line: reformatting must not resurrect."""
    from thot.contracts import Severity
    from thot.memory.base import apply_memory
    from thot.memory.jsonfile import JsonMemory

    before = _taint_findings(_vulnerable_repo(tmp_path))[0]
    memory = JsonMemory.open(tmp_path / "v.json")
    memory.remember(Verdict.of(before, Decision.REFUTED, "argv est de confiance"))

    path = tmp_path / "app" / "handlers.py"
    path.write_text("# une ligne de commentaire ajoutée en tête\n"
                    + path.read_text(encoding="utf-8"), encoding="utf-8")
    after = _taint_findings(tmp_path)[0]

    assert after.location.line != before.location.line
    assert after.id == before.id
    assert apply_memory([after], memory)[0].severity is Severity.INFO


# -- the reason is the value ------------------------------------------------


def test_a_long_refutation_is_kept_whole():
    """27 of 28 machine refutations were stored cut at 300 characters, one
    of them ending on "Mais la s". A verdict nobody can read back is not a
    verdict."""
    from dataclasses import replace

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.memory.base import _reason_from

    argument = (
        "La branche shell=True est bien atteignable — avec EDITOR=\"gedit; id\", "
        "shlex.split donne argv[0]=\"gedit;\" qui n'existe pas, subprocess.call "
        "lève FileNotFoundError, et le repli exécute la chaîne via le shell. "
        "Mais la seule source de EDITOR est l'environnement de l'utilisateur, "
        "qui possède déjà un shell : aucune frontière n'est franchie."
    )
    location = CodeRef(path="a.py", line=1, symbol="s", ast_hash="h")
    finding = Finding(
        id=Finding.compute_id("r", location), rule="r", severity=Severity.HIGH,
        confidence=Confidence.REFUTED, location=location,
        failure_scenario=argument,
    )
    assert _reason_from(finding) == argument
    assert "aucune frontière" in _reason_from(finding)


def test_an_enormous_reason_is_cut_on_a_sentence_not_a_word():
    from thot.memory.base import MAX_REASON, _trim

    text = ("Une phrase complète. " * 400)
    cut = _trim(text)
    assert len(cut) <= MAX_REASON + 8
    assert cut.endswith(". […]")
    assert not cut.rstrip(" […]").endswith("phras")


def test_a_whole_agent_s_judgements_can_be_forgotten_at_once(tmp_path):
    """Sometimes an agent turns out to have been unable to see what it judged.

    Hermes rendered sixty-five refutations while it could not open a file by
    relative path — so it could never check a claim that rested on a second
    file. A verdict silences its finding for good, which makes one that may
    be unsound worse than none at all.
    """
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.memory import build_memory
    from thot.memory.base import Decision, Verdict

    memory = build_memory(tmp_path)
    try:
        for index, author in enumerate(("hermes", "hermes", "prime")):
            location = CodeRef(path=f"a{index}.py", line=1, symbol="f",
                               ast_hash="h")
            finding = Finding(
                id=Finding.compute_id("r", location), rule="r",
                severity=Severity.HIGH, confidence=Confidence.REFUTED,
                location=location,
            )
            memory.remember(
                Verdict.of(finding, Decision.REFUTED, "raison", author)
            )

        doomed = [v for v in memory.all_verdicts() if v.author == "hermes"]
        assert len(doomed) == 2
        for verdict in doomed:
            assert memory.forget(verdict.finding_id) is True

        left = memory.all_verdicts()
        assert [v.author for v in left] == ["prime"]
    finally:
        memory.close()


def test_a_shared_verdict_travels_to_a_colleague_who_has_no_history(tmp_path,
                                                                    monkeypatch):
    """The whole point of committing `.thot/verdicts.json`.

    Verified by hand first, on a scratch machine with an empty THOT_HOME: the
    decision *and its reason* cross, attributed to whoever took it, and the
    finding drops from HIGH to INFO. A colleague must not inherit a silently
    downgraded finding — they must see who decided and why.
    """
    from thot.cli import _share_verdict
    from thot.contracts import Confidence
    from thot.memory import build_memory
    from thot.memory.base import Decision, Verdict
    from thot.pipeline import run_audit
    from thot.scope.authorization import write_authorization

    (tmp_path / "app.py").write_text(
        "import os\nimport sys\n\n\ndef run():\n    os.system('ls ' + sys.argv[1])\n"
    )
    write_authorization(tmp_path, owner="tester")

    finding = run_audit(tmp_path).findings[0]
    assert finding.severity.value == "high"

    # Alex decides, on their machine.
    author = build_memory(tmp_path)
    try:
        author.remember(
            Verdict.of(finding, Decision.ACCEPTED, "entrée locale seulement",
                       "dev")
        )
        _share_verdict(author, finding.id, tmp_path)
    finally:
        author.close()

    assert (tmp_path / ".thot" / "verdicts.json").is_file()

    # The colleague: same repository, no history of their own. The memory is
    # built the way the CLI builds it — `run_audit` reads no verdicts unless
    # it is handed a store, which is what makes this a round trip and not a
    # test of `apply_memory` in isolation.
    monkeypatch.setenv("THOT_HOME", str(tmp_path / "vierge"))
    colleague = build_memory(tmp_path)
    try:
        inherited = run_audit(tmp_path, memory=colleague)
        seen = colleague.recall(finding.id)
    finally:
        colleague.close()
    same = next(f for f in inherited.findings if f.id == finding.id)

    assert inherited.remembered == 1
    assert same.confidence is not Confidence.CONFIRMED
    assert same.severity.value == "info", "la décision doit dégrader le finding"

    assert seen is not None, "le collègue doit voir la décision, pas seulement la subir"
    assert seen.author == "dev"
    assert "entrée locale" in seen.reason


# --- une réfutation dont la relecture a échoué n'est pas acquise -----------
#
# La relecture n'est déclenchée que pour les findings qui comptent (MEDIUM et
# au-dessus) : elle existe pour rattraper une réfutation fautive avant qu'elle
# ne fasse taire un défaut vivant. Quand elle échouait — quota, délai, agent
# absent — `_apply_review` conservait la réfutation en notant « relecture
# impossible », et `record_verdicts` l'écrivait quand même en mémoire
# permanente. L'étage de contrôle devenait facultatif sans que rien ne le
# dise, et la réfutation non vérifiée obtenait la même permanence qu'une
# réfutation vérifiée.


def _refuted(identifier="f1", provenance=None):
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    return Finding(
        id=identifier, rule="sink.os.system", severity=Severity.INFO,
        confidence=Confidence.REFUTED,
        location=CodeRef(path="a.py", line=2, symbol="m", ast_hash="h"),
        failure_scenario="argv atteint os.system\n\nRéfuté : entrée constante",
        provenance=provenance,
    )


def test_a_refutation_whose_review_failed_is_not_remembered(tmp_path):
    from thot.memory.base import record_verdicts
    from thot.memory.jsonfile import JsonMemory

    memory = JsonMemory.open(tmp_path / "v.json")
    kept = record_verdicts(
        [_refuted(provenance={"relecture": "prime",
                              "relecture impossible": "délai dépassé"})],
        memory, author="hermes",
    )

    assert kept == 0
    assert memory.recall("f1") is None


def test_a_reviewed_refutation_is_remembered(tmp_path):
    from thot.memory.base import record_verdicts
    from thot.memory.jsonfile import JsonMemory

    memory = JsonMemory.open(tmp_path / "v.json")
    kept = record_verdicts(
        [_refuted(provenance={"relecture": "prime", "réfutation vérifiée": "oui"})],
        memory, author="hermes",
    )

    assert kept == 1
    assert memory.recall("f1") is not None


def test_a_refutation_that_needed_no_review_is_still_remembered(tmp_path):
    """Low-severity findings never reach the review stage; nothing changes."""
    from thot.memory.base import record_verdicts
    from thot.memory.jsonfile import JsonMemory

    memory = JsonMemory.open(tmp_path / "v.json")
    kept = record_verdicts(
        [_refuted(provenance={"contradicteur": "hermes"})], memory, author="hermes"
    )

    assert kept == 1


# --- lire l'équipe, écrire chez soi ----------------------------------------
#
# Observé en montant un dépôt avec un `.thot/verdicts.json` : la chaîne
# devient « json → sqlite (écriture : sqlite) ». C'est la bonne conception —
# on lit les décisions de l'équipe et on écrit les siennes dans son magasin
# privé. Si elle s'inversait, chaque réfutation locale atterrirait dans le
# fichier versionné et serait committée par accident, sans que personne ne
# l'ait décidé pour l'équipe.


def test_a_local_verdict_never_lands_in_the_committed_file(tmp_path):
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.memory import build_memory
    from thot.memory.base import Decision, Verdict
    from thot.memory.jsonfile import JsonMemory

    shared = tmp_path / ".thot" / "verdicts.json"
    shared.parent.mkdir(parents=True)

    def finding(identifier, line):
        location = CodeRef(path="app.py", line=line, symbol="run", ast_hash="h")
        return Finding(
            id=identifier, rule="sink.os.system", severity=Severity.HIGH,
            confidence=Confidence.PLAUSIBLE, location=location,
            failure_scenario="argv atteint os.system",
        )

    team = JsonMemory.open(shared)
    team.remember(Verdict.of(finding("equipe", 2), Decision.REFUTED,
                             "décidé ensemble", "équipe"))
    team.close()
    before = shared.read_text(encoding="utf-8")

    memory = build_memory(tmp_path)
    try:
        assert "json" in memory.describe(), memory.describe()
        assert memory.recall("equipe") is not None, "la décision d'équipe est lue"
        memory.remember(Verdict.of(finding("perso", 9), Decision.REFUTED,
                                   "mon avis à moi", "dev"))
    finally:
        getattr(memory, "close", lambda: None)()

    assert shared.read_text(encoding="utf-8") == before, (
        "un verdict local a été écrit dans le fichier de l'équipe"
    )

    reread = build_memory(tmp_path)
    try:
        assert reread.recall("perso") is not None, "le verdict local est perdu"
    finally:
        getattr(reread, "close", lambda: None)()


# -- a decision belongs to the code it is about ---------------------------
#
# The memory is shared across trees while `.thot/verdicts.json` is committed
# with one repository. Publishing without asking which is which put a
# decision about Hermes into Prime's file, and nothing said so.


def test_a_decision_belongs_to_a_repository_that_holds_its_file(tmp_path):
    from thot.memory.base import Decision, Verdict, concerns

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    mine = Verdict("a", Decision.REFUTED, path="src/app.py")
    theirs = Verdict("b", Decision.REFUTED, path="autre/projet.py")

    assert concerns(mine, tmp_path)
    assert not concerns(theirs, tmp_path)


def test_a_decision_without_a_path_belongs_nowhere(tmp_path):
    from thot.memory.base import Decision, Verdict, concerns

    assert not concerns(Verdict("a", Decision.REFUTED), tmp_path)


def test_a_path_climbing_out_of_the_tree_does_not_belong(tmp_path):
    """`../voisin/app.py` may well exist, and is not this repository's."""
    from thot.memory.base import Decision, Verdict, concerns

    neighbour = tmp_path.parent / "voisin"
    neighbour.mkdir(exist_ok=True)
    (neighbour / "app.py").write_text("x = 1\n")
    escaped = Verdict("a", Decision.REFUTED, path="../voisin/app.py")

    assert not concerns(escaped, tmp_path)


def test_publishing_refuses_a_decision_about_another_tree(tmp_path, capsys):
    from thot.cli import EXIT_USAGE, _share_verdict
    from thot.memory.base import Decision, Verdict

    class OneVerdict:
        def recall(self, finding_id):
            return Verdict("a", Decision.REFUTED, path="ailleurs/app.py",
                           rule="sink.exec")

    assert _share_verdict(OneVerdict(), "a", tmp_path) == EXIT_USAGE
    assert "ailleurs/app.py" in capsys.readouterr().err
    assert not (tmp_path / ".thot" / "verdicts.json").exists()


def test_publishing_everything_takes_only_this_tree_s_decisions(tmp_path):
    import json

    from thot.cli import EXIT_OK, _share_all_verdicts
    from thot.memory.base import Decision, Verdict

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")

    class Everything:
        def all_verdicts(self):
            return [
                Verdict("ici", Decision.REFUTED, path="src/app.py", rule="r1"),
                Verdict("ailleurs", Decision.REFUTED, path="autre/x.py",
                        rule="r2"),
            ]

    assert _share_all_verdicts(Everything(), tmp_path) == EXIT_OK
    published = json.loads((tmp_path / ".thot" / "verdicts.json").read_text())
    assert [v["finding_id"] for v in published["verdicts"]] == ["ici"]
