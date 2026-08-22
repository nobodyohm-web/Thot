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
