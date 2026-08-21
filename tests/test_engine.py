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


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    binary = tmp_path / "claude"
    binary.write_text(FAKE_CLAUDE.format(python=sys.executable))
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return binary


@pytest.fixture(params=["direct", "claude-cli"])
def engine(request, tmp_path, fake_claude):
    if request.param == "direct":
        return DirectEngine(provider=EchoProvider())
    return ClaudeCliEngine(root=tmp_path)


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


def test_usage_is_reported(engine):
    result = engine.run(AgentTask(id="t1", instructions="abc"))
    assert result.usage.output_tokens > 0


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
