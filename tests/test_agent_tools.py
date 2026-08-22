"""Tools: the guard rails matter more than the happy path."""

from __future__ import annotations

import pytest

from thot import agent_tools
from thot.agent_tools import ToolContext, ToolError
from thot.recon import sweep


@pytest.fixture
def context(toy_repo):
    answers = {"confirm": True}
    ctx = ToolContext(
        root=toy_repo.resolve(),
        recon=sweep(toy_repo),
        confirm=lambda action, detail: answers["confirm"],
        refresh=lambda: None,
    )
    ctx.answers = answers  # test handle
    return ctx


def test_read_file_returns_numbered_lines(context):
    out = agent_tools.read_file(context, path="src/app.py", start=1, end=2)
    assert out.splitlines()[0].strip().startswith("1")


def test_path_outside_the_project_is_refused(context):
    with pytest.raises(ToolError, match="hors du répertoire"):
        agent_tools.read_file(context, path="../../../etc/passwd")


def test_write_requires_confirmation(context):
    context.answers["confirm"] = False
    with pytest.raises(ToolError, match="refusé"):
        agent_tools.write_file(context, path="new.py", content="x = 1\n")
    assert not (context.root / "new.py").exists()


def test_confirmed_write_lands_on_disk(context):
    agent_tools.write_file(context, path="new.py", content="x = 1\n")
    assert (context.root / "new.py").read_text() == "x = 1\n"


def test_ambiguous_edit_is_refused_rather_than_guessed(context):
    (context.root / "dup.py").write_text("a = 1\na = 1\n")
    context.recon = sweep(context.root)
    with pytest.raises(ToolError, match="2 fois"):
        agent_tools.edit_file(context, path="dup.py", old="a = 1", new="a = 2")


def test_run_command_requires_confirmation(context):
    context.answers["confirm"] = False
    with pytest.raises(ToolError, match="refusé"):
        agent_tools.run_command(context, command="echo nope")


def test_dispatch_turns_errors_into_messages_for_the_model(context):
    out = agent_tools.dispatch(context, "read_file", {"path": "missing.py"})
    assert out.startswith("Erreur")


def test_audit_tool_reports_the_taint_path(context):
    out = agent_tools.dispatch(context, "audit", {})
    assert "sink.os.system" in out
    assert "→" in out


def test_every_spec_has_a_handler():
    assert {spec.name for spec in agent_tools.SPECS} == set(agent_tools.HANDLERS)


# -- code_map filtering ------------------------------------------------------
# A model's first instinct is a glob, not a substring. Both must work, because
# a silent "0 fichiers" reads as "empty project" and sends it off grepping.


def test_code_map_lists_everything_without_a_pattern(context):
    out = agent_tools.code_map(context)
    assert "src/app.py" in out


def test_code_map_accepts_a_bare_star(context):
    out = agent_tools.code_map(context, pattern="*")
    assert "src/app.py" in out


def test_code_map_accepts_a_glob(context):
    out = agent_tools.code_map(context, pattern="src/*.py")
    assert "src/app.py" in out


def test_code_map_matches_a_glob_on_the_basename(context):
    out = agent_tools.code_map(context, pattern="*.py")
    assert "src/app.py" in out


def test_code_map_still_accepts_a_plain_substring(context):
    out = agent_tools.code_map(context, pattern="app")
    assert "src/app.py" in out


def test_code_map_reports_an_empty_match_explicitly(context):
    out = agent_tools.code_map(context, pattern="*.rs")
    assert "Aucun fichier" in out


# -- plugin warnings ride back on the write ----------------------------------


def test_a_dangerous_write_carries_a_warning_back(context):
    out = agent_tools.write_file(
        context, path="risky.py", content="import pickle\npickle.loads(blob)\n"
    )
    assert "risky.py" in out
    assert "pickle" in out.lower()
    assert (context.root / "risky.py").exists()  # advisory, never blocking


def test_a_safe_write_says_nothing_extra(context):
    out = agent_tools.write_file(
        context, path="safe.py", content="import json\njson.loads(blob)\n"
    )
    assert "⚠" not in out


# -- one tool call must not cost half a context window -----------------------


def _many_findings(count: int):
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    severities = [Severity.INFO] * count
    severities[0] = Severity.CRITICAL
    severities[1] = Severity.HIGH
    out = []
    for index, severity in enumerate(severities):
        location = CodeRef(path=f"f{index}.py", line=1, symbol="s",
                           ast_hash=f"h{index}")
        out.append(
            Finding(
                id=Finding.compute_id("r", location), rule="sink.os.system",
                severity=severity, confidence=Confidence.PLAUSIBLE,
                location=location,
                failure_scenario="détail " * 200,
            )
        )
    return out


def _context_with(findings, tmp_path):
    from thot.agent_tools import ToolContext

    class _Recon:
        pass

    recon = _Recon()
    recon.findings = findings
    return ToolContext(root=tmp_path, recon=recon,
                       confirm=lambda a, d: False, refresh=lambda: None)


def test_the_audit_tool_bounds_what_it_hands_back(tmp_path):
    """Measured on Hermes before this: 372 findings, some 94 000 tokens in a
    single answer — and this tool is exposed over MCP to the user's own
    sessions, where a smaller window would simply fail."""
    from thot.agent_tools import MAX_LISTED, audit

    answer = audit(_context_with(_many_findings(300), tmp_path))

    assert answer.count("sink.os.system") <= MAX_LISTED + 1
    assert len(answer) < 40_000


def test_what_is_not_listed_is_counted_not_dropped(tmp_path):
    """"40 findings" where there are 300 is a lie a reader cannot detect."""
    from thot.agent_tools import MAX_LISTED, audit

    answer = audit(_context_with(_many_findings(300), tmp_path))

    assert f"{300 - MAX_LISTED} autre(s) finding(s)" in answer
    assert "info" in answer


def test_the_worst_come_first(tmp_path):
    from thot.agent_tools import audit

    answer = audit(_context_with(_many_findings(300), tmp_path))
    head = answer.splitlines()[0]

    assert "CRITICAL" in head


def test_a_short_report_is_left_whole(tmp_path):
    from thot.agent_tools import audit

    answer = audit(_context_with(_many_findings(3), tmp_path))

    assert "autre(s) finding(s)" not in answer
