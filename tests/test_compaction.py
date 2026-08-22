"""Compressing a conversation without losing the part you are in.

Hermes Agent's trajectory-compression strategy, ported. The test that
matters most is the last one: `/compact` used to summarise everything, so
a follow-up question met a paraphrase of the answer instead of the answer.
"""

from __future__ import annotations

from pathlib import Path

from dataclasses import dataclass

from thot.state import compaction


@dataclass
class M:
    role: str
    content: str


def _conversation(middle: int = 30, size: int = 200) -> list[M]:
    messages = [M("user", "on cherche les injections " * 20),
                M("assistant", "d'accord " * 20)]
    for index in range(middle):
        messages.append(M("assistant", f"appel {index} " * size))
        messages.append(M("tool", f"résultat {index} " * size))
    messages += [M("user", "et le parseur JSON ?"),
                 M("assistant", "il valide en amont")]
    return messages


def test_a_short_conversation_is_left_alone():
    messages = _conversation(middle=1, size=5)
    proposal = compaction.plan(messages, budget=100_000)

    assert proposal.worth_doing is False
    assert "rien à compacter" in proposal.describe()
    assert compaction.apply(messages, proposal, "résumé",
                            make_message=M) == messages


def test_the_opening_and_the_closing_are_never_paraphrased():
    messages = _conversation()
    proposal = compaction.plan(messages, budget=3000)
    out = compaction.apply(messages, proposal, "résumé du milieu",
                           make_message=M)

    assert out[0] is messages[0], "l'ouverture cadre la tâche"
    assert out[-1] is messages[-1], "la fin, c'est la tâche"
    assert out[-2] is messages[-2]
    assert any(compaction.MARKER in (m.content or "") for m in out)


def test_only_as_much_as_needed_is_compressed():
    """A budget is a floor to reach, not an excuse to throw everything away."""
    messages = _conversation()
    tight = compaction.plan(messages, budget=2000)
    loose = compaction.plan(messages, budget=20_000)

    assert tight.end - tight.start > loose.end - loose.start
    assert loose.worth_doing
    assert loose.after <= loose.before


def test_a_tool_result_is_never_stranded_from_its_call():
    """Some providers reject an orphaned tool message outright."""
    messages = _conversation()
    proposal = compaction.plan(messages, budget=3000)
    out = compaction.apply(messages, proposal, "résumé", make_message=M)

    for index, message in enumerate(out):
        if message.role == "tool":
            assert out[index - 1].role == "assistant", (
                "un résultat d'outil doit suivre l'appel qui l'a demandé"
            )


def test_the_excerpt_carries_only_the_span_being_dropped():
    messages = _conversation(middle=12)
    proposal = compaction.plan(messages, budget=1000)
    assert proposal.worth_doing
    text = compaction.excerpt(messages, proposal.start, proposal.end)

    assert "et le parseur JSON ?" not in text, (
        "résumer la fin serait payer pour perdre ce qu'on garde"
    )
    assert "[assistant]" in text and "[tool]" in text


def test_the_excerpt_is_clipped_rather_than_unbounded():
    messages = _conversation(middle=60, size=400)
    text = compaction.excerpt(messages, 4, len(messages), limit=2000)
    assert len(text) <= 2100
    assert text.endswith("…")


def test_the_estimate_is_an_estimate_and_says_so():
    assert compaction.estimate_tokens("") == 1
    assert compaction.estimate_tokens("x" * 400) == 100
    assert compaction.total_tokens([M("user", "x" * 400)]) == 100


def test_compacting_reports_what_it_did():
    proposal = compaction.plan(_conversation(), budget=3000)
    described = proposal.describe()

    assert "message(s) résumés" in described
    assert "jetons" in described


def test_a_conversation_shorter_than_its_protections_is_left_whole():
    """Protecting four at the front and eight at the back leaves nothing
    in the middle of a ten-message session — and that is the right answer."""
    messages = _conversation(middle=3)
    proposal = compaction.plan(messages, budget=1)

    assert proposal.worth_doing is False
    assert compaction.apply(messages, proposal, "x", make_message=M) == messages


# -- compacting without being asked -------------------------------------------


def test_the_automatic_threshold_is_far_above_the_manual_one():
    """Compacting costs fidelity, so the unasked kind must be rarer.

    At the manual threshold the model's thread would restart every few
    exchanges — which is worse than the problem it solves.
    """
    from thot.state.compaction import AUTO_BUDGET, DEFAULT_BUDGET

    assert AUTO_BUDGET >= DEFAULT_BUDGET * 4


def test_a_long_conversation_plans_a_compaction_at_the_automatic_budget():
    from thot.state.compaction import AUTO_BUDGET, plan

    class _M:
        def __init__(self, content):
            self.role = "user"
            self.content = content

    big = "x" * (AUTO_BUDGET * 4 // 10)  # twenty of these is twice the budget
    messages = [_M(big) for _ in range(20)]

    proposal = plan(messages, budget=AUTO_BUDGET)

    assert proposal.worth_doing
    assert proposal.after < proposal.before


def test_a_short_conversation_is_left_alone():
    from thot.state.compaction import AUTO_BUDGET, plan

    class _M:
        role = "user"
        content = "court"

    assert not plan([_M(), _M()], budget=AUTO_BUDGET).worth_doing


def test_both_turn_paths_compact_themselves():
    """A long task filled the window, the next turn was refused, and the
    thread died with everything in it.

    Two paths end a turn — the tool-loop path and the account-mode path — and
    a guard wired into one of them protects half the sessions. Same shape as
    the tripwire, which landed on `thot audit --deep` and missed the session
    for an hour.
    """
    from pathlib import Path

    source = (Path(__file__).parent.parent / "src" / "thot"
              / "session.py").read_text(encoding="utf-8")
    calls = [
        line for line in source.splitlines()
        if "_compact_if_needed()" in line and not line.strip().startswith("#")
        and not line.strip().startswith("def ")
    ]
    assert len(calls) >= 2, (
        "les deux fins de tour doivent compacter, pas une seule"
    )


def test_the_automatic_compaction_is_reachable_from_a_session():
    """Wired, not merely defined: a method nobody calls is dead code that
    looks like a feature."""
    from thot.session import Session

    assert hasattr(Session, "_compact_if_needed")
    assert hasattr(Session, "_compact")


# --- le déclencheur automatique doit croire la mesure, pas l'estimation ----
#
# En mode compte le CLI possède le fil : `Session.messages` ne garde que les
# lignes de l'utilisateur et le texte final de l'assistant — jamais les
# fichiers lus ni le trafic d'outils. Mesuré sur un tour ordinaire (`claude
# -p` lisant un seul fichier) : 95 jetons vus par Thot contre 88 290
# réellement dans la fenêtre, soit 929x trop bas. Avec un seuil à 120 000, le
# compactage automatique ne se déclenchait donc jamais dans le mode que
# l'utilisateur emploie, et la tâche longue mourait de la panne que cette
# fonction existe pour éviter.


def test_the_measured_window_triggers_a_compaction_the_estimate_would_miss():
    from thot.state.compaction import AUTO_BUDGET, should_compact

    # ce qu'un tour réel produit : une estimation ridicule, une fenêtre pleine
    assert should_compact(estimated=95, measured=AUTO_BUDGET + 1)


def test_the_estimate_still_triggers_when_nothing_was_measured():
    from thot.state.compaction import AUTO_BUDGET, should_compact

    assert should_compact(estimated=AUTO_BUDGET + 1, measured=0)


def test_a_small_context_is_left_alone_by_both_signals():
    from thot.state.compaction import should_compact

    assert not should_compact(estimated=95, measured=88_290)


def test_the_session_asks_the_cli_what_the_window_really_holds():
    """The wiring, exercised rather than read."""
    from thot.session import Session
    from thot.state import compaction

    class _Cli:
        last_tokens = compaction.AUTO_BUDGET + 5_000
        forgotten = False

        def forget_thread(self):
            self.forgotten = True

    class _Fake:
        store = object()
        messages = [type("M", (), {"role": "user", "content": "salut"})()]
        claude = _Cli()
        compacted = None

        def _compact(self, argument, *, budget=None, force=False):
            self.compacted = (budget, force)

    fake = _Fake()
    Session._compact_if_needed(fake)

    assert fake.compacted is not None, "la mesure du CLI a été ignorée"
    budget, force = fake.compacted
    assert budget == compaction.AUTO_BUDGET
    assert force is True, "un plan vide ne doit pas annuler un contexte plein"


def test_a_local_session_without_a_cli_still_uses_its_own_estimate():
    from thot.session import Session
    from thot.state import compaction

    class _Fake:
        store = object()
        claude = None
        compacted = None
        messages = [
            type("M", (), {"role": "user", "content": "x " * 4_000})()
            for _ in range(60)
        ]

        def _compact(self, argument, *, budget=None, force=False):
            self.compacted = (budget, force)

    fake = _Fake()
    Session._compact_if_needed(fake)

    assert fake.compacted is not None
    assert fake.compacted[1] is False, "rien de mesuré : pas de forçage"


# --- le seuil se déduit de la fenêtre annoncée par le CLI ------------------
#
# Un seuil fixe à 120 000 est juste pour une fenêtre de 200k et huit fois trop
# bas pour une fenêtre de 1M : il compacterait une tâche longue qui avait
# encore 880 000 jetons devant elle. Inutile de deviner — le CLI publie
# `contextWindow` par modèle dans son événement de résultat, mesuré ici :
# {"claude-opus-5[1m]": {..., "contextWindow": 1000000}}.


def test_a_known_window_sets_the_threshold_instead_of_the_constant():
    from thot.state.compaction import AUTO_BUDGET, budget_for

    wide = budget_for(1_000_000)

    assert wide > AUTO_BUDGET * 4, wide
    assert wide < 1_000_000, "il faut de la place pour le tour suivant"


def test_an_unknown_window_falls_back_to_the_constant():
    from thot.state.compaction import AUTO_BUDGET, budget_for

    assert budget_for(0) == AUTO_BUDGET


def test_a_small_window_is_never_widened_by_the_fallback():
    from thot.state.compaction import budget_for

    # le repli ne doit jamais dépasser la fenêtre réelle
    assert budget_for(60_000) < 60_000


def test_the_cli_learns_its_window_from_the_result_event():
    from thot.llm.claude_cli import ClaudeCli, Events

    cli = ClaudeCli(root=Path("."))
    cli._consume(
        {
            "type": "result",
            "usage": {"input_tokens": 6, "output_tokens": 583},
            "modelUsage": {
                "claude-opus-5[1m]": {
                    "contextWindow": 1_000_000,
                    "maxOutputTokens": 64_000,
                }
            },
        },
        Events(), [], set(),
    )

    assert cli.context_window == 1_000_000


def test_a_result_event_without_the_field_leaves_the_window_unknown():
    from thot.llm.claude_cli import ClaudeCli, Events

    cli = ClaudeCli(root=Path("."))
    cli._consume({"type": "result", "usage": {}}, Events(), [], set())

    assert cli.context_window == 0
