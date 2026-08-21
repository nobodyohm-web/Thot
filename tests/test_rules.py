"""Custom audit rules loaded from disk.

The built-in catalog knows the Python standard library. It cannot know the
wrapper your team wrote around `subprocess`, the queue your service reads
from, or the validator that makes a value safe here. Without a way to say so,
every audit of a real codebase starts by being wrong in the same three places.
"""

from __future__ import annotations

import pytest

from thot.codemap import rules
from thot.codemap.catalog import DEFAULT_CATALOG
from thot.contracts import Severity


def write_rules(root, text, name="team.yaml"):
    directory = root / ".thot" / "rules"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text, encoding="utf-8")


def test_no_rules_directory_yields_the_builtin_catalog(tmp_path):
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    assert catalog.sinks == DEFAULT_CATALOG.sinks
    assert catalog.sources == DEFAULT_CATALOG.sources


def test_a_custom_sink_is_detected(tmp_path):
    write_rules(tmp_path, """
sinks:
  - id: sink.team.shell
    patterns: [utils.run_shell]
    impact: critical
    description: Wrapper shell maison
""")
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    rule = catalog.match_sink("utils.run_shell")
    assert rule is not None
    assert rule.impact is Severity.CRITICAL
    assert rule.id == "sink.team.shell"


def test_builtin_sinks_survive_a_custom_file(tmp_path):
    write_rules(tmp_path, "sinks:\n  - id: sink.x\n    patterns: [zzz]\n    impact: low\n    description: x\n")
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    assert catalog.match_sink("os.system") is not None


def test_a_custom_source_is_detected(tmp_path):
    write_rules(tmp_path, """
sources:
  - id: source.queue
    patterns: [msg.payload]
    description: File de messages
    match_mode: prefix
""")
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    assert catalog.match_source("msg.payload.decode") is not None


def test_a_custom_sanitizer_breaks_the_chain(tmp_path):
    write_rules(tmp_path, "sanitizers: [validate_host, team.escape]\n")
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    assert catalog.is_sanitizer("validate_host")
    assert catalog.is_sanitizer("team.escape")
    assert catalog.is_sanitizer("int")  # builtins still there


def test_a_custom_rule_can_override_a_builtin_by_id(tmp_path):
    write_rules(tmp_path, """
sinks:
  - id: sink.os.system
    patterns: [os.system]
    impact: low
    description: Toléré chez nous
""")
    catalog = rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")
    rule = catalog.match_sink("os.system")
    assert rule.impact is Severity.LOW
    assert len([r for r in catalog.sinks if r.id == "sink.os.system"]) == 1


def test_user_wide_rules_apply_to_every_repo(tmp_path):
    user = tmp_path / "home" / "rules"
    user.mkdir(parents=True)
    (user / "mine.yaml").write_text("sinks:\n  - id: sink.mine\n    patterns: [danger]\n    impact: high\n    description: d\n")
    catalog = rules.load_catalog(tmp_path / "repo", user_dir=user)
    assert catalog.match_sink("danger") is not None


def test_repo_rules_win_over_user_rules(tmp_path):
    user = tmp_path / "home" / "rules"
    user.mkdir(parents=True)
    (user / "mine.yaml").write_text("sinks:\n  - id: sink.dup\n    patterns: [d]\n    impact: low\n    description: user\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    write_rules(repo, "sinks:\n  - id: sink.dup\n    patterns: [d]\n    impact: critical\n    description: repo\n")
    catalog = rules.load_catalog(repo, user_dir=user)
    assert catalog.match_sink("d").impact is Severity.CRITICAL


def test_a_malformed_file_is_reported_not_swallowed(tmp_path):
    write_rules(tmp_path, "sinks:\n  - id: sans_patterns\n    impact: high\n")
    with pytest.raises(rules.RuleError, match="patterns"):
        rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")


def test_an_unknown_severity_names_the_file(tmp_path):
    write_rules(tmp_path, "sinks:\n  - id: s\n    patterns: [x]\n    impact: enorme\n    description: d\n")
    with pytest.raises(rules.RuleError, match="team.yaml"):
        rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")


def test_broken_yaml_names_the_file(tmp_path):
    write_rules(tmp_path, "sinks: [\n  unclosed", name="cassé.yaml")
    with pytest.raises(rules.RuleError, match="cassé.yaml"):
        rules.load_catalog(tmp_path, user_dir=tmp_path / "absent")


def test_a_dangerous_pattern_in_a_test_file_says_it_is_a_test(tmp_path):
    """Half of Hermes's and Prime's HIGH findings were test code scored as
    production. The demotion has to be legible, not just arithmetic."""
    from thot.guard.scanner import scan_text

    payload = 'const { exec } = require("child_process"); exec(cmd);\n'

    production = scan_text("src/core/clipboard.ts", payload)
    in_test = scan_text("packages/ai/test/stream.test.ts", payload)
    assert production and in_test, "la règle doit se déclencher dans les deux"

    assert production[0].severity is not in_test[0].severity
    assert (production[0].provenance or {}).get("rôle") is None
    assert (in_test[0].provenance or {}).get("rôle") == "test"


def test_a_test_finding_is_still_reported(tmp_path):
    from thot.contracts import Severity
    from thot.guard.scanner import scan_text

    found = scan_text("tests/conftest.py", "import os\nos.system(cmd)\n")
    assert found
    assert found[0].severity is not Severity.INFO
