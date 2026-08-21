"""The agentic loop, exercised end to end against a scripted provider.

No network: the fake provider replays a fixed sequence of replies, which is
enough to prove the loop runs tools, feeds results back, and stops.
"""

from __future__ import annotations

import pytest

from thot.llm.base import Message, Reply, ToolCall, Usage
from thot.llm.credentials import Config
from thot.session import Session


class ScriptedProvider:
    """Returns a prepared reply per call and records what it was asked."""

    name = "fake"
    model = "fake-1"

    def __init__(self, replies: list[Message]) -> None:
        self._replies = list(replies)
        self.calls: list[dict] = []

    def complete(self, *, system, messages, tools, on_text=None):
        self.calls.append(
            {"system": system, "messages": list(messages), "tools": list(tools)}
        )
        message = self._replies.pop(0)
        if on_text and message.content:
            on_text(message.content)
        return Reply(message=message, usage=Usage(10, 5))


@pytest.fixture
def session(toy_repo, monkeypatch):
    monkeypatch.setattr(
        "thot.session.PromptSession", lambda **kwargs: None
    )
    return Session(root=toy_repo, config=Config(provider="fake", model="fake-1"))


def test_recon_runs_at_startup(session):
    assert session.recon.file_count == 2
    assert session.recon.symbols
    assert any(f.rule == "sink.os.system" for f in session.recon.findings)


def test_briefing_reaches_the_system_prompt(session):
    system = session._system()
    assert "src/app.py" in system or "src.app.main" in system
    assert "sink.os.system" in system


def test_plain_answer_ends_the_turn(session):
    session.provider = ScriptedProvider([Message(role="assistant", content="Bonjour.")])
    session.messages.append(Message(role="user", content="salut"))
    session._turn()
    assert session.messages[-1].content == "Bonjour."


def test_tool_call_is_executed_and_fed_back(session):
    provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="t1", name="find_symbol", arguments={"name": "main"}),
                ),
            ),
            Message(role="assistant", content="Trouvé."),
        ]
    )
    session.provider = provider
    session.messages.append(Message(role="user", content="où est main ?"))
    session._turn()

    tool_messages = [m for m in session.messages if m.role == "tool"]
    assert len(tool_messages) == 1
    assert "src.app.main" in tool_messages[0].content
    assert tool_messages[0].tool_call_id == "t1"
    # The tool result went back to the model on the second call.
    assert len(provider.calls) == 2
    assert session.messages[-1].content == "Trouvé."


def test_graph_tools_answer_without_reading_files(session):
    provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="t1", name="callers", arguments={"symbol": "run_command"}),
                ),
            ),
            Message(role="assistant", content="ok"),
        ]
    )
    session.provider = provider
    session.messages.append(Message(role="user", content="qui appelle run_command ?"))
    session._turn()

    answer = [m for m in session.messages if m.role == "tool"][0].content
    assert "src.app.main" in answer
    assert "saut" in answer


def test_runaway_tool_loop_is_capped(session, monkeypatch):
    monkeypatch.setattr("thot.session.MAX_TOOL_ROUNDS", 3)
    looping = [
        Message(
            role="assistant",
            tool_calls=(ToolCall(id=f"t{i}", name="code_map", arguments={}),),
        )
        for i in range(10)
    ]
    session.provider = ScriptedProvider(looping)
    session.messages.append(Message(role="user", content="boucle"))
    session._turn()
    assert len([m for m in session.messages if m.role == "tool"]) == 3


def test_unknown_tool_does_not_crash_the_session(session):
    session.provider = ScriptedProvider(
        [
            Message(
                role="assistant",
                tool_calls=(ToolCall(id="t1", name="nope", arguments={}),),
            ),
            Message(role="assistant", content="fini"),
        ]
    )
    session.messages.append(Message(role="user", content="?"))
    session._turn()
    assert "inconnu" in [m for m in session.messages if m.role == "tool"][0].content


# -- /audit deep -------------------------------------------------------------


def test_deep_analysis_degrades_gracefully_without_an_engine(session, monkeypatch):
    """A missing CLI must cost the verdicts, never the audit."""
    from thot.engine.factory import NoEngine

    def refuse(*args, **kwargs):
        raise NoEngine("pas de moteur")

    monkeypatch.setattr("thot.engine.factory.build_engine", refuse)
    findings = session.recon.findings
    assert session._deep_analyse(findings) == findings


def test_deep_analysis_replaces_findings_with_verdicts(session, monkeypatch):
    from thot.contracts import Confidence
    from thot.engine import AgentResult, EngineCapabilities

    class Confirming:
        capabilities = EngineCapabilities(name="stub", max_parallel=1)

        def run(self, task):
            if task.id.startswith("probe:"):
                return AgentResult(task_id=task.id, data={
                    "verdict": "confirmed", "scenario": "entrée non validée",
                    "severity": "critical"})
            return AgentResult(task_id=task.id, data={"refuted": False, "raison": "-"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    monkeypatch.setattr(
        "thot.engine.factory.build_engine", lambda *a, **k: Confirming()
    )
    out = session._deep_analyse(session.recon.findings)
    assert any(f.confidence is Confidence.CONFIRMED for f in out)


# -- the session log ---------------------------------------------------------


def test_the_conversation_is_written_down_as_it_happens(session):
    session.provider = ScriptedProvider([Message(role="assistant", content="Voilà.")])
    session.messages.append(Message(role="user", content="salut"))
    session._record("user", "salut")
    session._turn()

    turns = session.store.turns(session.session_id)
    assert [(t.role, t.content) for t in turns] == [
        ("user", "salut"),
        ("assistant", "Voilà."),
    ]


def test_findings_are_searchable_long_after_the_audit(session):
    session._record_audit(session.recon.findings)

    hits = session.store.find("sink.os.system")
    assert hits, "un finding doit rester retrouvable par /search"
    assert "app.py" in hits[0].plain() or "src" in hits[0].plain()


def test_resume_restores_the_transcript(session):
    previous = session.store.start(session.root)
    session.store.append(previous, "user", "question d'hier")
    session.store.append(previous, "assistant", "réponse d'hier")

    session._resume(previous[:8])

    assert session.session_id == previous
    assert [m.content for m in session.messages] == [
        "question d'hier",
        "réponse d'hier",
    ]


def test_resume_hands_the_thread_back_to_the_official_cli(session):
    """Restoring a transcript is not restoring context; the CLI owns that."""
    from thot.llm.claude_cli import ClaudeCli

    session.claude = ClaudeCli(root=session.root)
    previous = session.store.start(session.root)
    session.store.append(previous, "user", "hier")
    session.store.link_cli(previous, "cli-thread-42")

    session._resume(previous)

    assert session.claude.session_id == "cli-thread-42"
    assert session.claude._started is True  # so the next call passes --resume


def test_compacting_starts_a_new_thread_and_keeps_the_old_one(session):
    session._record("user", "beaucoup de travail")
    old = session.session_id

    session._compact("résumé fourni à la main")

    assert session.session_id != old
    assert session.store.info(old).ended_at, "l'ancienne session doit être close"
    assert session.store.info(session.session_id).parent_id == old
    assert "résumé fourni" in session.messages[0].content


def test_an_empty_startup_session_is_not_left_behind_by_resume(session):
    previous = session.store.start(session.root)
    session.store.append(previous, "user", "hier")
    empty = session.session_id

    session._resume(previous)

    assert session.store.info(empty) is None


# -- goals and custom commands ----------------------------------------------


def test_the_goal_rides_in_every_briefing(session):
    session.store.set_goal(session.root, "zéro HIGH dans le parseur",
                           token_budget=5000)

    system = session._system()
    assert "zéro HIGH dans le parseur" in system
    assert "5000" in system
    # And it is still there after the conversation is thrown away.
    session._compact("résumé")
    assert "zéro HIGH dans le parseur" in session._system()


def test_a_turn_is_billed_to_the_goal(session):
    goal = session.store.set_goal(session.root, "auditer", token_budget=1000)
    session.provider = ScriptedProvider([Message(role="assistant", content="ok")])
    session.messages.append(Message(role="user", content="vas-y"))
    session._turn()

    charged = session.store.goal(session.root)
    assert charged.tokens_used == 15  # the scripted provider reports 10 + 5
    assert charged.calls_used == 1
    assert charged.id == goal.id


def test_a_custom_command_expands_into_a_prompt(session, tmp_path):
    folder = session.root / ".thot" / "commands"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "revue.md").write_text("Relis $1 sans rien changer.", encoding="utf-8")

    assert session._command("/revue src/app.py") == "Relis src/app.py sans rien changer."


def test_an_unknown_slash_command_is_not_sent_to_the_model(session):
    assert session._command("/nexistepas") is None


def test_a_session_where_nothing_was_said_is_not_history(session):
    """Launching Thot to glance at /status must not litter the log."""
    empty = session.session_id
    session._close_state()

    assert session.store.info(empty) is None


def test_a_session_that_was_used_is_kept_and_closed(session):
    session._record("user", "une vraie question")
    used = session.session_id
    session._close_state()

    info = session.store.info(used)
    assert info is not None
    assert info.ended_at


def test_skills_answers_with_an_index_before_it_answers_with_a_wall(session, capsys):
    session._command("/skills")
    listed = capsys.readouterr().out

    assert "90 méthodes" in listed or "méthodes" in listed
    assert "vulnerability-triage" in listed
    # An index, not ninety descriptions.
    assert "Turn taint candidates" not in listed


def test_compacting_keeps_the_last_exchanges_verbatim(session):
    """The whole point: a follow-up question must meet the answer, not a gloss."""
    for index in range(40):
        session.messages.append(Message(role="assistant",
                                        content=f"étape {index} " * 300))
        session.messages.append(Message(role="tool", content=f"sortie {index} " * 300))
    session.messages.append(Message(role="user", content="et le parseur JSON ?"))
    session.messages.append(Message(role="assistant", content="il valide en amont"))

    session.provider = ScriptedProvider(
        [Message(role="assistant", content="résumé du milieu")]
    )
    session._compact("")

    contents = [m.content for m in session.messages]
    assert "et le parseur JSON ?" in contents
    assert "il valide en amont" in contents
    assert any("résumé du milieu" in c for c in contents)
    assert len(session.messages) < 82


def test_compacting_a_short_session_does_nothing_and_costs_nothing(session):
    session.messages.append(Message(role="user", content="bonjour"))
    provider = ScriptedProvider([Message(role="assistant", content="jamais appelé")])
    session.provider = provider
    before = session.session_id

    session._compact("")

    assert provider.calls == [], "rien à compacter ne doit rien coûter"
    assert session.session_id == before


def test_what_was_learned_rides_into_every_briefing(session):
    session.harness.remember(title="team.shell.run",
                             content="échappe ses arguments")

    system = session._system()
    assert "team.shell.run" in system
    assert "échappe ses arguments" in system


def test_a_refutation_survives_the_session_that_paid_for_it(session, monkeypatch):
    """Minutes of model time must not die with the process.

    `recon` folds the memory in at every sweep, so a session that only reads
    it re-argues the same findings forever.
    """
    from thot.contracts import Confidence
    from thot.engine import AgentResult, EngineCapabilities
    from thot.memory import build_memory

    class Refuting:
        capabilities = EngineCapabilities(name="stub-engine", max_parallel=1)

        def run(self, task):
            if task.id.startswith("probe:"):
                return AgentResult(task_id=task.id, data={
                    "verdict": "confirmed", "scenario": "appel shell",
                    "severity": "high"})
            return AgentResult(task_id=task.id, data={
                "refuted": True, "raison": "la commande est une constante"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    monkeypatch.setattr("thot.engine.factory.build_engine", lambda *a, **k: Refuting())
    analysed = session._deep_analyse(session.recon.findings)
    assert any(f.confidence is Confidence.REFUTED for f in analysed)

    memory = build_memory(session.root)
    try:
        stored = memory.all_verdicts()
    finally:
        memory.close()

    assert stored, "la réfutation doit être mémorisée"
    reasons = " ".join(v.reason for v in stored)
    assert "constante" in reasons
    # A machine refutation attributed to the user would outrank the user.
    assert all(v.author == "stub-engine" for v in stored)


def test_the_next_sweep_stops_paying_for_a_refuted_finding(session, monkeypatch):
    from thot.analysis.probe import select_for_analysis
    from thot.engine import AgentResult, EngineCapabilities
    from thot.recon import sweep

    class Refuting:
        capabilities = EngineCapabilities(name="stub-engine", max_parallel=1)

        def run(self, task):
            if task.id.startswith("probe:"):
                return AgentResult(task_id=task.id, data={"verdict": "refuted"})
            return AgentResult(task_id=task.id, data={"refuted": True, "raison": "non"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    monkeypatch.setattr("thot.engine.factory.build_engine", lambda *a, **k: Refuting())
    session._deep_analyse(session.recon.findings)

    fresh = sweep(session.root)
    assert not select_for_analysis(fresh.findings, 10), (
        "un finding réfuté ne doit plus être soumis au modèle"
    )
