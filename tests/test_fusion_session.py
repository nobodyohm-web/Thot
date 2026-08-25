"""The session running on Hermes and Prime — Thot being what it says it is.

`Config.provider` accepted `claude-cli`, `claude`, `openai`, `local`,
`custom`. Neither agent. So the program whose premise is that it is the
fusion of the two ran on neither, and every check that ever passed was about
the audit engine rather than about the thing the user launches.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot.engine.base import AgentResult, AgentTask, EngineCapabilities
from thot.llm.base import Usage
from thot.llm.credentials import Config


class Fake:
    def __init__(self, name: str) -> None:
        self.name = name
        self.seen: list[AgentTask] = []

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(name=self.name)

    def run(self, task: AgentTask) -> AgentResult:
        self.seen.append(task)
        return AgentResult(task_id=task.id, text=f"[{self.name}] répond",
                           usage=Usage(input_tokens=7, output_tokens=3))

    def fan_out(self, tasks):
        return [self.run(task) for task in tasks]


@pytest.fixture
def fused(tmp_path, monkeypatch):
    """A session on a cascade of two fake agents, with no model anywhere."""
    from thot.engine.cascade import Cascade
    from thot.session import Session

    hermes, prime = Fake("hermes"), Fake("prime")
    monkeypatch.setattr(
        "thot.engine.factory.build_cascade",
        lambda root, **kwargs: Cascade(root=Path(root),
                                       members={"hermes": hermes, "prime": prime}),
    )
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    session = Session(root=tmp_path, config=Config(provider="fusion", model=""))
    return session, hermes, prime


def test_the_fusion_provider_builds_no_model_client(fused):
    """No Claude CLI, no API provider. The two agents are the backend."""
    session, _, _ = fused
    assert session.claude is None
    assert session.provider is None
    assert session.agent is not None


def test_a_turn_that_asks_to_act_goes_to_prime(fused):
    from thot.llm.base import Message

    session, hermes, prime = fused
    session.messages.append(Message(role="user", content="lance les tests"))
    session._turn()

    assert len(prime.seen) == 1
    assert not hermes.seen
    assert session.messages[-1].role == "assistant"
    assert session.messages[-1].content == "[prime] répond"


def test_a_turn_that_asks_to_think_goes_to_hermes(fused):
    from thot.llm.base import Message

    session, hermes, prime = fused
    session.messages.append(Message(role="user", content="explique le cache"))
    session._turn()

    assert len(hermes.seen) == 1
    assert not prime.seen


def test_the_thread_survives_the_change_of_agent(fused):
    """The point of the whole thing. Both agents are one-shot, so Prime must
    see what Hermes answered — otherwise the fusion is two strangers."""
    from thot.llm.base import Message

    session, hermes, prime = fused
    session.messages.append(Message(role="user", content="explique le cache"))
    session._turn()
    session.messages.append(Message(role="user", content="corrige-le"))
    session._turn()

    handed = prime.seen[-1].prompt()
    assert "explique le cache" in handed
    assert "[hermes] répond" in handed


def test_the_repository_map_travels_with_every_turn(fused):
    from thot.llm.base import Message

    session, hermes, _ = fused
    session.messages.append(Message(role="user", content="explique"))
    session._turn()

    assert "fichier" in hermes.seen[-1].prompt().lower()


def test_the_turn_is_charged_to_the_session(fused):
    from thot.llm.base import Message

    session, _, _ = fused
    before = session.spent_input + session.spent_output
    session.messages.append(Message(role="user", content="lance les tests"))
    session._turn()

    assert session.spent_input + session.spent_output > before


def test_forcing_one_agent_holds_across_turns(fused):
    from thot.llm.base import Message

    session, hermes, prime = fused
    session._command("/hermes")
    session.messages.append(Message(role="user", content="lance les tests"))
    session._turn()

    assert len(hermes.seen) == 1 and not prime.seen

    session._command("/auto")
    session.messages.append(Message(role="user", content="lance les tests"))
    session._turn()

    assert len(prime.seen) == 1


def test_the_label_says_which_two_agents_are_behind_it():
    assert "hermes" in Config(provider="fusion", model="").label().lower()


def test_the_stable_half_of_the_prompt_comes_first(fused):
    """A compaction summary changes every time it is written; the repository
    map does not. Putting the volatile half in front means no reusable
    prefix exists even in principle — there is nothing a cache could hold."""
    from thot.llm.base import Message

    session, hermes, _ = fused
    session.carry = "RESUME-VOLATIL"
    session.messages.append(Message(role="user", content="explique"))
    session._turn()

    sent = hermes.seen[-1].prompt().lower()
    assert "fichier" in sent
    assert sent.index("fichier") < sent.index("resume-volatil"), (
        "la carte du dépôt doit précéder le résumé volatil"
    )


# -- reaching for the agents from a session that started elsewhere ------------
#
# From a real run: a Claude session hit its account limit ("resets 1am"), and
# `/hermes` did nothing because these commands were gated on a cascade built
# at startup. Two agents were installed and idle while the work stopped for
# hours.


@pytest.fixture
def on_claude(tmp_path, monkeypatch):
    """A session on the Claude CLI, with both agents installed but unused."""
    from thot.engine.cascade import Cascade
    from thot.session import Session

    hermes, prime = Fake("hermes"), Fake("prime")
    monkeypatch.setattr(
        "thot.engine.factory.build_cascade",
        lambda root, **kwargs: Cascade(root=Path(root),
                                       members={"hermes": hermes, "prime": prime}),
    )
    monkeypatch.setattr("thot.llm.claude_cli.ClaudeCli.available", lambda: True)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    session = Session(root=tmp_path, config=Config(provider="claude-cli", model=""))
    return session, hermes, prime


def test_a_claude_session_starts_with_no_cascade(on_claude):
    """The premise of the fix: it is not fused, and that is correct."""
    session, _, _ = on_claude
    assert session.agent is None
    assert session.claude is not None


def test_the_agents_can_be_reached_after_the_model_stops_answering(on_claude):
    """`/auto` opens the cascade instead of being ignored.

    The session started on Claude; Claude ran out. Refusing to use two
    installed agents because of how the session started is refusing for no
    reason.
    """
    session, _, _ = on_claude
    session._command("/auto")
    assert session.agent is not None
    assert session.agent.forced == ""


def test_one_agent_can_be_named_from_a_claude_session(on_claude):
    """`/hermes` both opens the cascade and pins the turns to Hermes."""
    session, _, _ = on_claude
    session._command("/hermes")
    assert session.agent is not None
    assert session.agent.forced == "hermes"


def test_the_next_turn_then_goes_to_the_agents(on_claude):
    """Opening the cascade is what redirects the turn — `_turn` checks it first."""
    from thot.llm.base import Message

    session, hermes, _ = on_claude
    session._command("/hermes")
    session.messages.append(Message(role="user", content="explique ce fichier"))
    session._turn()
    assert len(hermes.seen) == 1


def test_a_machine_with_neither_agent_says_so_instead_of_pretending(
    tmp_path, monkeypatch
):
    """No cascade, no silent no-op: the user is told why nothing happened."""
    from thot.session import Session

    def refuse(root, **kwargs):
        raise FileNotFoundError("aucun agent")

    monkeypatch.setattr("thot.engine.factory.build_cascade", refuse)
    monkeypatch.setattr("thot.llm.claude_cli.ClaudeCli.available", lambda: True)
    (tmp_path / "a.py").write_text("x = 1\n")
    session = Session(root=tmp_path, config=Config(provider="claude-cli", model=""))
    session._command("/auto")
    assert session.agent is None


def test_switching_and_continuing_are_one_gesture(on_claude):
    """`/auto continue` must do both.

    Typed exactly that way in a stuck session. Switching the backend and
    dropping the instruction reads as the command having done nothing.
    """
    session, _, _ = on_claude
    assert session._command("/auto continue") == "continue"
    assert session.agent is not None


def test_a_bare_switch_asks_nothing(on_claude):
    """`/auto` alone changes the backend and waits."""
    session, _, _ = on_claude
    assert session._command("/auto") is None


def test_naming_an_agent_carries_the_instruction_too(on_claude):
    """`/hermes explique ce fichier` pins Hermes and asks the question."""
    session, _, _ = on_claude
    assert session._command("/hermes explique ce fichier") == "explique ce fichier"
    assert session.agent.forced == "hermes"
