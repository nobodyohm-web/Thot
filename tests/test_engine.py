"""One contract suite, run against every engine.

An engine that passes this is interchangeable by construction — that is the
whole point of the port. The Claude CLI engine is exercised against a fake
`claude` binary that speaks real stream-json, so the parsing is under test too,
not stubbed away.
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from thot.engine import AgentTask
from thot.engine.claude_cli_engine import ClaudeCliEngine
from thot.engine.direct import DirectEngine
from thot.engine.hermes_engine import HermesEngine
from thot.engine.prime_engine import PrimeEngine
from thot.llm.base import Message, Reply, Usage


class EchoProvider:
    """Answers with the prompt reversed, so results are distinguishable."""

    name = "echo"
    model = "echo-1"

    def complete(self, *, system, messages, tools, on_text=None):
        text = messages[-1].content
        if "BOOM" in text:
            raise RuntimeError("le fournisseur a explosé")
        return Reply(message=Message(role="assistant", content=text[::-1]),
                     usage=Usage(input_tokens=3, output_tokens=4))


FAKE_CLAUDE = '''#!{python}
import json, sys
prompt = sys.stdin.read()
if "BOOM" in prompt:
    sys.stderr.write("fake failure\\n")
    raise SystemExit(2)
out = prompt[::-1]
print(json.dumps({{"type": "system", "subtype": "init", "model": "fake-model"}}))
print(json.dumps({{"type": "assistant", "message": {{"content": [{{"type": "text", "text": out}}]}}}}))
print(json.dumps({{"type": "result", "is_error": False, "result": out,
                  "usage": {{"input_tokens": 3, "output_tokens": 4}}}}))
'''


# Hermes one-shot: the prompt arrives in argv after `-z`, and only the final
# answer goes to stdout — no banner, no tool previews, no token counts.
FAKE_HERMES = '#!{python}\nimport sys\nargv = sys.argv[1:]\nprompt = argv[argv.index("-z") + 1]\n# The system instruction rides at the head of the prompt; the real agent\n# consumes it the same way.\nprompt = prompt.split("\\n\\n", 1)[-1]\nif "BOOM" in prompt:\n    sys.stderr.write("fake hermes failure\\n")\n    raise SystemExit(2)\nprint(prompt[::-1])\n'

# Prime one-shot: a JSON event stream, carrying real token counts.
FAKE_PRIME = '#!{python}\nimport json, sys\nargv = sys.argv[1:]\nprompt = argv[argv.index("--") + 1]\nif "BOOM" in prompt:\n    sys.stderr.write("fake prime failure\\n")\n    raise SystemExit(2)\nout = prompt[::-1]\nmessage = {{"role": "assistant",\n           "content": [{{"type": "text", "text": out}}],\n           "usage": {{"input": 1, "output": 4, "cacheRead": 2, "cacheWrite": 0}}}}\nprint(json.dumps({{"type": "agent_start"}}))\nprint(json.dumps({{"type": "turn_end", "message": message}}))\nprint(json.dumps({{"type": "agent_end", "messages": [message]}}))\n'


def _install(tmp_path, monkeypatch, name, source):
    binary = tmp_path / name
    binary.write_text(source.format(python=sys.executable))
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return binary


@pytest.fixture
def fake_hermes(tmp_path, monkeypatch):
    binary = _install(tmp_path, monkeypatch, "hermes", FAKE_HERMES)
    monkeypatch.setattr("thot.fusion.locate.hermes_command", lambda: [str(binary)])
    return binary


@pytest.fixture
def fake_prime(tmp_path, monkeypatch):
    binary = _install(tmp_path, monkeypatch, "prime-fake", FAKE_PRIME)
    monkeypatch.setattr("thot.fusion.locate.prime_command", lambda: [str(binary)])
    return binary


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    binary = tmp_path / "claude"
    binary.write_text(FAKE_CLAUDE.format(python=sys.executable))
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return binary


@pytest.fixture(params=["direct", "claude-cli", "hermes", "prime"])
def engine(request, tmp_path, fake_claude, fake_hermes, fake_prime):
    if request.param == "direct":
        return DirectEngine(provider=EchoProvider())
    if request.param == "claude-cli":
        return ClaudeCliEngine(root=tmp_path)
    if request.param == "hermes":
        return HermesEngine(root=tmp_path)
    return PrimeEngine(root=tmp_path)


# -- the contract ------------------------------------------------------------


def test_run_returns_a_result_for_the_task(engine):
    result = engine.run(AgentTask(id="t1", instructions="abc"))
    assert result.task_id == "t1"
    assert result.ok
    assert result.text == "cba"


def test_context_is_part_of_the_prompt(engine):
    result = engine.run(AgentTask(id="t1", instructions="Q", context="CTX"))
    assert "CTX"[::-1] in result.text


def test_fan_out_preserves_order(engine):
    tasks = [AgentTask(id=f"t{i}", instructions=str(i) * 3) for i in range(6)]
    results = engine.fan_out(tasks)
    assert [r.task_id for r in results] == [t.id for t in tasks]
    assert all(r.ok for r in results)


def test_a_failing_task_does_not_sink_the_others(engine):
    tasks = [
        AgentTask(id="ok1", instructions="aaa"),
        AgentTask(id="bad", instructions="BOOM"),
        AgentTask(id="ok2", instructions="bbb"),
    ]
    results = {r.task_id: r for r in engine.fan_out(tasks)}
    assert results["ok1"].ok and results["ok2"].ok
    assert not results["bad"].ok
    assert results["bad"].error


def test_capabilities_are_declared(engine):
    caps = engine.capabilities
    assert caps.name
    assert caps.max_parallel >= 1


def test_empty_fan_out_is_not_an_error(engine):
    assert engine.fan_out([]) == []


def test_usage_is_reported_or_declared_absent(engine):
    """An engine that cannot count must not produce a number anyway.

    Hermes's one-shot mode prints the answer and nothing else. Reporting a
    confident 0 would put an invented figure in `/cost`; declaring the
    absence lets the caller say "non mesuré".
    """
    result = engine.run(AgentTask(id="t1", instructions="abc"))
    if engine.capabilities.reports_usage:
        assert result.usage.output_tokens > 0
    else:
        assert result.usage.output_tokens == 0
        assert result.usage.input_tokens == 0


# -- schema-constrained answers ---------------------------------------------


def test_json_answer_is_parsed_when_a_schema_is_given(tmp_path):
    class JsonProvider(EchoProvider):
        def complete(self, *, system, messages, tools, on_text=None):
            payload = json.dumps({"verdict": "real", "why": "parce que"})
            return Reply(message=Message(role="assistant",
                                         content=f"Voici:\n```json\n{payload}\n```"),
                         usage=Usage(1, 1))

    engine = DirectEngine(provider=JsonProvider())
    result = engine.run(AgentTask(id="t1", instructions="x", schema={"type": "object"}))
    assert result.data == {"verdict": "real", "why": "parce que"}


def test_unparseable_json_is_reported_not_raised(tmp_path):
    class BadJson(EchoProvider):
        def complete(self, *, system, messages, tools, on_text=None):
            return Reply(message=Message(role="assistant", content="pas du json"),
                         usage=Usage(1, 1))

    engine = DirectEngine(provider=BadJson())
    result = engine.run(AgentTask(id="t1", instructions="x", schema={"type": "object"}))
    assert result.data is None
    assert not result.ok


# -- the two agent engines, specifically -------------------------------------

ARGV_DUMP = '#!{python}\nimport json, os, sys\nhere = os.path.dirname(os.path.abspath(__file__))\nwith open(os.path.join(here, "argv.json"), "w") as handle:\n    json.dump(sys.argv[1:], handle)\ndata = sys.stdin.read()\nprint(json.dumps({{"type": "turn_end", "message": {{"role": "assistant",\n      "content": [{{"type": "text", "text": "stdin=" + repr(data)}}],\n      "usage": {{"input": 1, "output": 1}}}}}}))\n'


@pytest.fixture
def dumping(tmp_path, monkeypatch):
    """A fake that reports its argv on stderr and what stdin gave it."""
    binary = _install(tmp_path, monkeypatch, "dump", ARGV_DUMP)
    monkeypatch.setattr("thot.fusion.locate.hermes_command", lambda: [str(binary)])
    monkeypatch.setattr("thot.fusion.locate.prime_command", lambda: [str(binary)])
    return binary


def test_the_child_never_inherits_our_standard_input(dumping, tmp_path):
    """A task is non-interactive: a child reaching for stdin must see EOF.

    Inherited stdin is how the first real run hung for ten minutes with
    nothing on screen.
    """
    engine = PrimeEngine(root=tmp_path)
    result = engine.run(AgentTask(id="t1", instructions="salut"))
    assert "stdin=''" in result.text


def test_prime_stops_flag_parsing_before_the_prompt(dumping, tmp_path):
    """An audit scenario can start with a dash. Without `--`, Prime would
    read the beginning of the question as an option."""
    engine = PrimeEngine(root=tmp_path)
    engine.run(AgentTask(id="t1", instructions="--verbose n'est pas un drapeau"))

    argv = json.loads((tmp_path / "argv.json").read_text())
    assert argv[argv.index("--") + 1] == "--verbose n'est pas un drapeau"


def test_the_tier_chooses_effort_not_a_model(dumping, tmp_path):
    """Naming a model would override what the user configured in their own
    agent; effort is the part that belongs to the task."""
    HermesEngine(root=tmp_path).run(
        AgentTask(id="t1", instructions="x", tier="deep")
    )
    argv = json.loads((tmp_path / "argv.json").read_text())
    assert argv[argv.index("--reasoning") + 1] == "high"
    assert "-m" not in argv and "--model" not in argv


@pytest.mark.parametrize("engine_class", [HermesEngine, PrimeEngine])
def test_a_prompt_too_long_for_argv_is_refused_not_truncated(
    engine_class, dumping, tmp_path
):
    """execve fails with E2BIG long before this, and a truncated audit prompt
    would produce a confident answer about the wrong code."""
    engine = engine_class(root=tmp_path)
    result = engine.run(AgentTask(id="t1", instructions="x" * 200_000))
    assert not result.ok
    assert "trop long" in result.error


def test_hermes_reports_a_missing_install_instead_of_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr("thot.fusion.locate.hermes_command", lambda: None)
    result = HermesEngine(root=tmp_path).run(AgentTask(id="t1", instructions="x"))
    assert not result.ok
    assert "uv sync" in result.error


def test_prime_reports_an_uncompiled_tree_instead_of_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr("thot.fusion.locate.prime_command", lambda: None)
    result = PrimeEngine(root=tmp_path).run(AgentTask(id="t1", instructions="x"))
    assert not result.ok
    assert "npm run build" in result.error


# -- choosing one ------------------------------------------------------------


def test_naming_an_unknown_engine_says_which_exist(tmp_path):
    from thot.engine.factory import NoEngine, build_engine

    with pytest.raises(NoEngine) as raised:
        build_engine(tmp_path, prefer="gemini")
    assert "hermes" in str(raised.value) and "prime" in str(raised.value)


def test_an_engine_asked_for_but_absent_raises_rather_than_substituting(
    tmp_path, monkeypatch
):
    """A run that silently used a different agent would make its verdicts
    unattributable — they are stored under the name of whoever decided."""
    from thot.engine.factory import NoEngine, build_engine

    monkeypatch.setattr("thot.fusion.locate.prime_command", lambda: None)
    with pytest.raises(NoEngine) as raised:
        build_engine(tmp_path, prefer="prime")
    assert "npm run build" in str(raised.value)


def test_the_engine_can_be_named_by_environment(dumping, tmp_path, monkeypatch):
    from thot.engine.factory import ENGINE_ENV, build_engine

    monkeypatch.setenv(ENGINE_ENV, "hermes")
    assert build_engine(tmp_path).capabilities.name == "hermes"


# -- the panel: the three agents on one run -----------------------------------


class _Fake:
    """An engine that records what it was asked, and can be told to fail."""

    def __init__(self, name, *, fails=False):
        self._name = name
        self.fails = fails
        self.seen = []

    @property
    def capabilities(self):
        from thot.engine.base import EngineCapabilities

        return EngineCapabilities(name=self._name, max_parallel=1)

    def run(self, task):
        from thot.engine.base import AgentResult

        self.seen.append(task.id)
        if self.fails:
            return AgentResult(task_id=task.id, error="indisponible")
        return AgentResult(task_id=task.id, text=self._name)

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


def _task(task_id):
    from thot.engine.base import AgentTask

    return AgentTask(id=task_id, instructions="x")


def test_the_refutation_goes_to_a_different_agent_than_the_argument():
    """A model attacking the scenario it just committed to marks its own work."""
    from thot.engine.panel import PanelEngine

    a, b = _Fake("hermes"), _Fake("prime")
    panel = PanelEngine(members=[a, b])

    panel.fan_out([_task("probe:f1")])
    arguer = panel.who("probe:f1")

    panel.fan_out([_task("refute:f1")])
    assert panel.who("refute:f1") != arguer


def test_a_failing_member_does_not_cost_the_task():
    from thot.engine.panel import PanelEngine

    broken, working = _Fake("hermes", fails=True), _Fake("prime")
    panel = PanelEngine(members=[broken, working])

    result = panel.run(_task("probe:f1"))

    assert result.ok
    assert panel.who("probe:f1") == "prime"
    assert broken.seen == ["probe:f1"], "l'échec a bien été tenté d'abord"


def test_a_panel_of_one_still_attacks_its_own_argument():
    """Better a self-refutation than a finding nobody ever attacked."""
    from thot.engine.panel import PanelEngine

    panel = PanelEngine(members=[_Fake("claude")])

    panel.fan_out([_task("probe:f1"), _task("refute:f1")])
    assert panel.who("refute:f1") == "claude"


def test_the_panel_reports_no_usage_when_one_member_cannot_count():
    from thot.engine.base import EngineCapabilities
    from thot.engine.panel import PanelEngine

    class _Silent(_Fake):
        @property
        def capabilities(self):
            return EngineCapabilities(
                name="hermes", max_parallel=1, reports_usage=False
            )

    panel = PanelEngine(members=[_Silent("hermes"), _Fake("prime")])
    assert panel.capabilities.reports_usage is False


def test_provenance_names_the_arguer_and_the_attacker(tmp_path):
    """What the panel is for, seen from the report."""
    from thot.analysis.probe import _apply_probe, _apply_refutation
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.engine.base import AgentResult
    from thot.engine.panel import PanelEngine

    panel = PanelEngine(members=[_Fake("hermes"), _Fake("prime")])
    panel.fan_out([_task("probe:f1")])
    panel.fan_out([_task("refute:f1")])

    finding = Finding(
        id="f1",
        rule="sink.os.system",
        location=CodeRef(path="a.py", line=1),
        severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        failure_scenario="scénario",
    )
    probed = _apply_probe(
        finding,
        AgentResult(task_id="probe:f1", data={"verdict": "confirmed"}),
        panel,
    )
    refuted = _apply_refutation(
        probed,
        AgentResult(task_id="refute:f1", data={"refuted": True, "raison": "non"}),
        panel,
    )

    assert refuted.provenance["moteur"] != refuted.provenance["contradicteur"]


def test_a_slow_member_does_not_hold_the_batch_open():
    """The fast agents must absorb the work a straggler cannot take.

    A fixed share of the batch looked fair and was not: agents differ by a
    factor of four in speed, so a static split left everyone waiting on one.
    """
    import threading
    import time

    from thot.engine.base import AgentResult, AgentTask, EngineCapabilities
    from thot.engine.panel import PanelEngine

    class _Slow:
        def __init__(self, name, delay):
            self._name, self.delay = name, delay
            self.seen = []

        @property
        def capabilities(self):
            return EngineCapabilities(name=self._name, max_parallel=1)

        def run(self, task):
            self.seen.append(task.id)
            time.sleep(self.delay)
            return AgentResult(task_id=task.id, text=self._name)

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    slow, fast = _Slow("hermes", 0.20), _Slow("claude", 0.001)
    panel = PanelEngine(members=[slow, fast])
    tasks = [AgentTask(id=f"probe:f{i}", instructions="x") for i in range(8)]

    results = panel.fan_out(tasks)

    assert all(r.ok for r in results)
    assert [r.task_id for r in results] == [t.id for t in tasks], "ordre préservé"
    assert len(fast.seen) > len(slow.seen), "le rapide doit avoir absorbé le gros"


def test_a_stand_in_is_never_someone_who_already_spoke():
    """Seen in a real run: both attackers of one finding were the same agent.

    The first attacker failed the second-attack task, and the stand-in was
    picked as "the next member in the list" — which was the first attacker
    itself. The escalation then bought nothing at all.
    """
    from thot.engine.panel import PanelEngine

    arguer, attacker, third = _Fake("hermes"), _Fake("claude"), _Fake("prime")
    panel = PanelEngine(members=[arguer, attacker, third])

    panel.fan_out([_task("probe:f1")])
    panel.fan_out([_task("refute:f1")])

    spoken = {panel.who("probe:f1"), panel.who("refute:f1")}
    assert len(spoken) == 2
    third.fails = True  # the only member eligible for the second attack fails

    result = panel.fan_out([_task("refute2:f1")])[0]

    assert panel.who("refute2:f1") not in spoken
    assert not result.ok, "un échec vaut mieux qu'un second avis qui n'en est pas un"


def test_the_audit_engines_cannot_write_where_they_read():
    """An audit has no business holding a terminal in the user's repository.

    Reading stays — a refutation almost always rests on code outside the
    excerpt and checking it is the entire job. Prime is the stated exception:
    its only built-in tool is an IPython kernel, so a probe on Prime has
    Prime's reach, and pretending otherwise would be worse than saying it.
    """
    from pathlib import Path

    from thot.engine.claude_cli_engine import ClaudeCliEngine
    from thot.engine.hermes_engine import HermesEngine
    from thot.llm.claude_cli import WRITING_TOOLS

    if ClaudeCliEngine.available():
        command = ClaudeCliEngine(root=Path("."))._command(
            __import__("thot.engine.base", fromlist=["AgentTask"]).AgentTask(
                id="probe:x", instructions="x"
            )
        )
        assert "--disallowed-tools" in command
        for tool in WRITING_TOOLS:
            assert tool in command

    if HermesEngine.available():
        from thot.engine.base import AgentTask
        from thot.engine.hermes_engine import TOOLSETS

        command = HermesEngine(root=Path("."))._command(
            AgentTask(id="probe:x", instructions="x"), "prompt"
        )
        assert "-t" in command and TOOLSETS in command
        assert "terminal" not in TOOLSETS and "code_execution" not in TOOLSETS
