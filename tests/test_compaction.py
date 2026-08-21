"""Compressing a conversation without losing the part you are in.

Hermes Agent's trajectory-compression strategy, ported. The test that
matters most is the last one: `/compact` used to summarise everything, so
a follow-up question met a paraphrase of the answer instead of the answer.
"""

from __future__ import annotations

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
