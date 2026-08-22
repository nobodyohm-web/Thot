"""The ported security patterns, applied as an audit sweep.

Taint analysis proves a path and covers Python only. These 25 patterns prove
nothing but recognise shapes that are dangerous wherever they appear, in
JavaScript and YAML too. The two are complementary, and neither replaces the
other — what matters here is that the sweep stays precise enough to be worth
reading.
"""

from __future__ import annotations

import pytest

from thot.contracts import Confidence, Severity
from thot.guard.scanner import scan_text, sweep_patterns


def test_pickle_load_is_flagged():
    findings = scan_text("app.py", "import pickle\ndata = pickle.loads(blob)\n")
    assert [f.rule for f in findings] == ["pattern.pickle_deserialization"]
    assert findings[0].location.line == 2


def test_the_reminder_becomes_the_scenario():
    findings = scan_text("app.py", "import yaml\ncfg = yaml.load(raw)\n")
    assert findings
    assert "yaml.safe_load" in findings[0].failure_scenario


def test_a_javascript_pattern_is_caught():
    findings = scan_text("ui.jsx", "el.innerHTML = userInput;\n")
    assert findings
    assert findings[0].rule == "pattern.innerHTML_xss"


def test_path_filters_are_respected():
    """A Python pattern must not fire inside a JavaScript file."""
    assert scan_text("ui.js", "pickle.loads(x)\n") == []


def test_tls_verification_disabled_is_caught():
    findings = scan_text("client.py", "requests.get(url, verify=False)\n")
    assert findings
    assert findings[0].rule == "pattern.tls_verification_disabled"


def test_clean_code_produces_nothing():
    assert scan_text("app.py", "import json\ndata = json.loads(blob)\n") == []


def test_findings_are_plausible_never_confirmed():
    findings = scan_text("app.py", "eval(user_input)\n")
    assert findings
    assert all(f.confidence is Confidence.PLAUSIBLE for f in findings)


def test_severity_is_assigned_per_rule():
    critical = scan_text("app.py", "import pickle\npickle.loads(b)\n")
    assert critical[0].severity in {Severity.CRITICAL, Severity.HIGH}


def test_identity_is_stable_across_line_moves():
    first = scan_text("app.py", "import pickle\npickle.loads(b)\n")
    second = scan_text("app.py", "\n\n\nimport pickle\npickle.loads(b)\n")
    assert first[0].id == second[0].id


def test_the_same_rule_twice_in_a_file_is_reported_once():
    findings = scan_text("app.py", "pickle.loads(a)\npickle.loads(b)\n")
    assert len(findings) == 1


def test_sweep_reads_the_repository(tmp_path):
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(x)\n")
    (tmp_path / "b.py").write_text("import json\njson.loads(x)\n")
    findings = sweep_patterns(tmp_path, ["a.py", "b.py"])
    assert len(findings) == 1
    assert findings[0].location.path == "a.py"


def test_an_unreadable_file_is_skipped_not_fatal(tmp_path):
    assert sweep_patterns(tmp_path, ["absent.py"]) == []


# -- literals and comments are not code --------------------------------------
# A pattern scanner that reads string literals flags every rule catalog, every
# test fixture and every piece of documentation that mentions a dangerous call.
# On Thot's own source that was 25 findings, all of them false.


def test_a_pattern_inside_a_string_literal_is_not_a_finding():
    assert scan_text("catalog.py", 'PATTERNS = ["pickle.loads", "os.system"]\n') == []


def test_a_pattern_inside_a_comment_is_not_a_finding():
    assert scan_text("a.py", "# never call pickle.loads on user data\n") == []


def test_a_pattern_inside_a_docstring_is_not_a_finding():
    assert scan_text("a.py", '"""Avoid pickle.loads here."""\n') == []


def test_real_code_is_still_caught_next_to_a_mention():
    text = 'DOC = "pickle.loads"\nimport pickle\npickle.loads(x)\n'
    findings = scan_text("a.py", text)
    assert len(findings) == 1
    assert findings[0].location.line == 3


def test_unparseable_python_still_gets_scanned():
    """A syntax error must not silently disable the sweep for that file."""
    assert scan_text("a.py", "def broken(:\npickle.loads(x)\n")


def test_non_python_files_are_unaffected():
    assert scan_text("ui.jsx", "el.innerHTML = x;\n")


# -- identity must expire when the dangerous line changes --------------------
# A pattern finding's id keys its stored verdict. Keying on the rule name alone
# made that verdict immortal: dismiss one os.system in a file and any future
# os.system in that same file inherits the dismissal.


def test_identity_changes_when_the_matching_line_changes():
    safe = scan_text("a.py", "import os\nos.system(FIXED_COMMAND)\n")
    risky = scan_text("a.py", "import os\nos.system(user_input)\n")
    assert safe and risky
    assert safe[0].id != risky[0].id


def test_identity_survives_edits_elsewhere_in_the_file():
    before = scan_text("a.py", "import os\nos.system(cmd)\n")
    after = scan_text("a.py", "import os\n\ndef helper():\n    pass\n\nos.system(cmd)\n")
    assert before[0].id == after[0].id


def test_identity_survives_reindentation():
    flat = scan_text("a.py", "import os\nos.system(cmd)\n")
    nested = scan_text("a.py", "import os\nif x:\n        os.system(cmd)\n")
    assert flat[0].id == nested[0].id


# -- the vendored Hermes cron monitor ----------------------------------------


def _monitor():
    """Hermes's cron monitor, imported from the tree this program ships."""
    import importlib.util
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    path = root / "cron" / "monitor.py"
    if not path.is_file():
        pytest.skip("cette version de Hermes n'a pas ce module")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location("hermes_cron_monitor", path)
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the module holds dataclasses, and
    # `@dataclass` resolves annotations through `sys.modules[__name__]`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_cron_monitor_refuses_an_address_only_this_host_can_reach():
    """Confirmed by the panel: SSRF with the response handed back.

    `monitor_url` is settable through an agent tool, so a prompt-injected
    model can point the fetch at the cloud metadata service — and the body
    comes back into its own prompt. The scheme check stopped `file://` and
    nothing else.
    """
    monitor = _monitor()
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "http://localhost/admin",
        "http://10.0.0.5/",
    ):
        assert monitor._refuse_internal_target(url), url


def test_the_cron_monitor_still_allows_a_public_address():
    monitor = _monitor()
    assert monitor._refuse_internal_target("https://example.com/status") is None


def test_a_redirect_is_checked_as_well_as_the_first_hop():
    """A host an attacker owns answers publicly, then redirects to loopback."""
    monitor = _monitor()
    opener = monitor._guarded_opener()
    handler = next(
        h for h in opener.handlers
        if type(h).__name__ == "_NoInternalRedirects"
    )
    with pytest.raises(OSError):
        handler.redirect_request(
            None, None, 302, "Found", {}, "http://127.0.0.1/secret"
        )
