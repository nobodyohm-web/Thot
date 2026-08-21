import json

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.report.json_report import render_json
from thot.report.markdown_report import render_markdown
from thot.scope.manifest import ScopeManifest


def sample():
    ref = CodeRef(path="src/app.py", line=10, symbol="src.app.run", ast_hash="abc")
    finding = Finding(
        id="deadbeef",
        rule="sink.os.system",
        severity=Severity.CRITICAL,
        confidence=Confidence.PLAUSIBLE,
        location=ref,
        taint_path=(ref,),
        failure_scenario="sys.argv[1] reaches os.system unfiltered",
    )
    manifest = ScopeManifest(
        root="/repo", files=("src/app.py",), languages={"python": 1},
        entrypoints=("src.app.main",), test_command="pytest",
    )
    return [finding], manifest


def test_json_is_parseable_and_carries_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule"] == "sink.os.system"
    assert payload["summary"]["by_severity"]["critical"] == 1


def test_json_never_contains_absolute_paths_in_findings():
    findings, manifest = sample()
    payload = json.loads(render_json(findings, manifest, elapsed=1.5))
    assert not payload["findings"][0]["location"]["path"].startswith("/")


def test_markdown_has_a_heading_and_the_finding():
    findings, manifest = sample()
    text = render_markdown(findings, manifest, elapsed=1.5)
    assert text.startswith("# ")
    assert "src/app.py:10" in text
    assert "sink.os.system" in text


def test_empty_report_says_so_explicitly():
    _, manifest = sample()
    text = render_markdown([], manifest, elapsed=0.2)
    assert "Aucun" in text
