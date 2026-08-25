"""Thot running *on* Hermes and Prime, which is what Thot is.

The session used to be a single-model loop: `Config.provider` accepted
`claude-cli`, `claude`, `openai`, `local`, `custom` — and neither agent. The
two were reachable only as audit contradictors and as MCP clients consuming
Thot's map. The half where Thot *runs on them* did not exist.

Both are one-shot and stateless — `hermes -z` and `prime -p` answer once and
forget. So the thread has to be held by somebody, and that somebody is Thot.
That is not a workaround: it is the persistent memory and the long context
the program claims, doing the one job only it can do.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from thot.engine.base import AgentResult, AgentTask, EngineCapabilities
from thot.engine.cascade import Cascade, NoAgents
from thot.llm.base import Message, Usage


class Fake:
    """An engine that records what it was asked, and answers."""

    def __init__(self, name: str, *, fails: str = "") -> None:
        self.name = name
        self.seen: list[AgentTask] = []
        self.fails = fails

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(name=self.name)

    def run(self, task: AgentTask) -> AgentResult:
        self.seen.append(task)
        if self.fails:
            return AgentResult(task_id=task.id, error=self.fails)
        return AgentResult(task_id=task.id, text=f"[{self.name}] fait",
                           usage=Usage(input_tokens=10, output_tokens=5))

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        return [self.run(task) for task in tasks]


def _cascade(**members) -> Cascade:
    return Cascade(root=Path("."), members={k: v for k, v in members.items() if v})


def _both() -> tuple[Cascade, Fake, Fake]:
    hermes, prime = Fake("hermes"), Fake("prime")
    return _cascade(hermes=hermes, prime=prime), hermes, prime


# --- who takes the turn ---------------------------------------------------


def test_an_instruction_to_act_goes_to_prime():
    cascade, _, _ = _both()
    assert cascade.route("lance les tests")[0] == "prime"
    assert cascade.route("corrige le cache MCP")[0] == "prime"


def test_an_instruction_to_think_goes_to_hermes():
    cascade, _, _ = _both()
    assert cascade.route("explique pourquoi le cache est périmé")[0] == "hermes"
    assert cascade.route("compare les deux approches")[0] == "hermes"


def test_the_first_verb_wins():
    """`explique comment lancer les tests` asks for an explanation. A rule
    that scanned for any action word anywhere would send it to Prime, which
    would run the tests nobody asked to run."""
    cascade, _, _ = _both()
    assert cascade.route("explique comment lancer les tests")[0] == "hermes"
    assert cascade.route("lance les tests et explique les échecs")[0] == "prime"


def test_a_turn_nobody_claims_goes_to_the_one_that_holds_the_thread():
    """Hermes by default, because the default is continuity: the turn that
    names no verb is usually the user carrying on a conversation."""
    cascade, _, _ = _both()
    who, why = cascade.route("et pour les gros fichiers ?")
    assert who == "hermes"
    assert why


def test_the_only_agent_installed_takes_everything():
    only_prime = _cascade(prime=Fake("prime"))
    assert only_prime.route("explique le cache")[0] == "prime"

    only_hermes = _cascade(hermes=Fake("hermes"))
    assert only_hermes.route("lance les tests")[0] == "hermes"


def test_no_agent_at_all_says_what_to_install():
    with pytest.raises(NoAgents) as raised:
        _cascade().route("peu importe")
    assert "hermes" in str(raised.value).lower()
    assert "prime" in str(raised.value).lower()


def test_a_forced_agent_wins_over_the_rule():
    """The rule is a heuristic and says so. `/prime` and `/hermes` are how a
    user overrides it without arguing with a keyword list."""
    cascade, _, prime = _both()
    cascade.forced = "prime"
    who, why = cascade.route("explique pourquoi le cache est périmé")
    assert who == "prime"
    assert "forcé" in why.lower()


# --- what actually travels ------------------------------------------------


def test_the_thread_travels_with_the_instruction():
    """The whole point. Both agents forget between calls, so a question that
    depends on three turns of context has to carry them — otherwise the
    second question in any conversation is answered blind."""
    cascade, hermes, _ = _both()
    history = [
        Message(role="user", content="quelle est la racine du dépôt ?"),
        Message(role="assistant", content="/Users/dev/Desktop/Thot"),
    ]

    cascade.turn("et sa taille ?", history=history, brief="")

    sent = hermes.seen[-1].prompt()
    assert "quelle est la racine" in sent
    assert "/Users/dev/Desktop/Thot" in sent
    assert "et sa taille ?" in sent


def test_the_map_travels_too():
    cascade, hermes, _ = _both()
    cascade.turn("explique", history=[], brief="203 fichiers · 3356 symboles")
    assert "3356 symboles" in hermes.seen[-1].prompt()


def test_the_turn_says_who_took_it_and_why():
    cascade, _, _ = _both()
    turn = cascade.turn("lance les tests", history=[], brief="")
    assert turn.agent == "prime"
    assert turn.why
    assert turn.text == "[prime] fait"


# --- one agent down, the other one available ------------------------------
#
# Measured on 2026-08-24: Anthropic answered `overloaded_error` and Prime
# failed twice in a row, 19 s each, while Hermes answered the same question
# correctly. Every `ACTS` verb died and every `THINKS` verb worked, so the
# fusion read as one broken half — with a working agent sitting idle.


def test_a_failed_agent_hands_the_turn_to_the_other_one():
    cascade = _cascade(hermes=Fake("hermes", fails="Provider overloaded"),
                       prime=Fake("prime"))
    turn = cascade.turn("explique le cache", history=[], brief="")

    assert turn.ok, turn.error
    assert turn.agent == "prime"
    assert turn.text == "[prime] fait"


def test_the_relay_says_it_happened_and_why():
    """A turn answered by somebody else must not look like a normal route."""
    cascade = _cascade(
        hermes=Fake("hermes"),
        prime=Fake("prime", fails="Provider overloaded (overloaded_error): "
                                  "Overloaded [request_id: req_011Ce]"),
    )
    turn = cascade.turn("lance les tests", history=[], brief="")

    assert turn.agent == "hermes"
    assert "prime" in turn.why and "hermes" in turn.why
    assert "Provider overloaded" in turn.why
    assert "request_id" not in turn.why, "l'id de requête ne dit rien au lecteur"


def test_the_relay_is_handed_the_same_prompt():
    """Including the transcript. A stand-in given less than the first agent
    answers a different question and nobody can see that it did."""
    hermes = Fake("hermes")
    cascade = _cascade(hermes=hermes, prime=Fake("prime", fails="down"))
    cascade.turn("lance les tests", history=[
        Message(role="user", content="on parlait du cache"),
    ], brief="CARTE")

    handed = hermes.seen[-1].prompt()
    assert "on parlait du cache" in handed
    assert "CARTE" in handed


def test_both_attempts_are_billed():
    """A call that failed is still a call. Charging one hides the cost of
    the very mechanism that saved the turn."""
    cascade = _cascade(hermes=Fake("hermes"), prime=Fake("prime", fails="down"))
    turn = cascade.turn("lance les tests", history=[], brief="")

    assert turn.usage.input_tokens == 10  # the failing fake spends nothing
    assert turn.usage.output_tokens == 5


def test_a_named_agent_is_not_quietly_replaced():
    """`/prime` is a promise about whose voice this is. `build_cascade` states
    the rule: a session that silently ran on another agent attributes its own
    history to the wrong one."""
    cascade = _cascade(hermes=Fake("hermes"),
                       prime=Fake("prime", fails="prime: exit 1"))
    cascade.forced = "prime"
    turn = cascade.turn("explique le cache", history=[], brief="")

    assert turn.agent == "prime"
    assert turn.error and "exit 1" in turn.error


def test_an_agent_that_fails_alone_does_not_end_the_session():
    """A backend that is down costs the turn, never the conversation — the
    thread is Thot's and outlives whoever was asked to think about it."""
    cascade = _cascade(hermes=Fake("hermes", fails="hermes: exit 1"))
    turn = cascade.turn("explique le cache", history=[], brief="")

    assert turn.error and "exit 1" in turn.error
    assert turn.agent == "hermes"


def test_both_agents_down_names_both():
    """Reporting one of the two sends the user looking at the wrong agent
    for a failure that is upstream of both."""
    cascade = _cascade(hermes=Fake("hermes", fails="hermes: exit 1"),
                       prime=Fake("prime", fails="prime: overloaded"))
    turn = cascade.turn("lance les tests", history=[], brief="")

    assert turn.error
    assert "hermes: exit 1" in turn.error
    assert "prime: overloaded" in turn.error


def test_the_cost_of_the_turn_comes_back():
    cascade, _, _ = _both()
    turn = cascade.turn("lance les tests", history=[], brief="")
    assert turn.usage.input_tokens == 10
    assert turn.usage.output_tokens == 5


def test_a_long_thread_is_carried_from_the_end():
    """A one-shot agent takes a prompt on its command line, and an unbounded
    transcript stops being sendable. What is dropped is the oldest, and the
    prompt says so rather than pretending it is whole."""
    history = [
        Message(role="user" if i % 2 == 0 else "assistant", content=f"tour {i} " + "x" * 400)
        for i in range(200)
    ]
    cascade, hermes, _ = _both()

    cascade.turn("et maintenant ?", history=history, brief="")
    sent = hermes.seen[-1].prompt()

    assert len(sent) < 80_000
    assert "tour 199" in sent
    assert "tour 0" not in sent
    assert "tronqué" in sent.lower() or "antérieur" in sent.lower()


def test_a_hyphenated_imperative_still_routes():
    """`corrige-le` is the ordinary way to ask, and the tokeniser glued it
    into one unknown word — so the follow-up to every explanation went back
    to Hermes instead of to Prime."""
    cascade, _, _ = _both()
    assert cascade.route("corrige-le")[0] == "prime"
    assert cascade.route("peux-tu lancer les tests ?")[0] == "prime"
    assert cascade.route("peux-tu expliquer ce cache ?")[0] == "hermes"
