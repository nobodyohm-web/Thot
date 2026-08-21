"""Compress a conversation without throwing away the part you are in.

Ported from Hermes Agent's `trajectory_compressor.py`, whose strategy is
the reason this file exists at all:

1. protect the first turns — they frame what the task even is;
2. protect the last turns — that is where the work currently is;
3. compress only the middle, and only as much as needed to fit;
4. replace the compressed span with a single summary message;
5. never cut between a tool call and its result.

Thot's `/compact` used to summarise *everything* and start over from the
paraphrase. That loses precisely the exchanges the next turn depends on:
you ask a follow-up question and the model has a summary of the answer
instead of the answer. This keeps the head and the tail verbatim and pays
the model only for the middle.

Token counting is deliberately an estimate. Hermes loads a tokenizer;
Thot would need a dependency and a model-specific vocabulary for a number
that only decides *how much* to compress. Four characters per token is
wrong by a few percent and never wrong by enough to matter here.
"""

from __future__ import annotations

from dataclasses import dataclass

# What the compressed conversation should fit into, in estimated tokens.
DEFAULT_BUDGET = 24_000

# When the session compacts itself, unasked. Far above the manual target on
# purpose: `/compact` is someone deciding they want a clean slate, while this
# one fires in the middle of somebody's work. Compacting a conversation costs
# fidelity — the CLI thread is restarted and only a summary crosses over — so
# doing it at the manual threshold would reset the model's memory every few
# exchanges. This is the point where not compacting costs more: a long task
# that hits the window dies mid-sentence and takes the thread with it.
AUTO_BUDGET = 120_000

# The opening exchange sets the task; the closing ones are the task.
PROTECT_FIRST = 4
PROTECT_LAST = 8

CHARS_PER_TOKEN = 4

MARKER = "Résumé de la partie compactée de cette session"


def estimate_tokens(text: str) -> int:
    return max(1, len(text or "") // CHARS_PER_TOKEN)


def total_tokens(messages) -> int:
    return sum(estimate_tokens(getattr(m, "content", "") or "") for m in messages)


@dataclass(frozen=True)
class Plan:
    """Which messages survive verbatim, and which span gets summarised."""

    head: int          # keep messages[:head]
    start: int         # summarise messages[start:end]
    end: int
    tail: int          # keep messages[end:]
    before: int        # estimated tokens before
    after: int         # estimated tokens if the plan is applied

    @property
    def worth_doing(self) -> bool:
        return self.end > self.start

    def describe(self) -> str:
        if not self.worth_doing:
            return "rien à compacter"
        return (f"{self.end - self.start} message(s) résumés · "
                f"~{self.before} → ~{self.after} jetons")


def _is_orphaned(messages, index: int) -> bool:
    """True when cutting *before* `index` would strand a tool result.

    A tool message without the assistant turn that asked for it is noise the
    model cannot interpret, and some providers reject it outright.
    """
    if index >= len(messages):
        return False
    return getattr(messages[index], "role", "") == "tool"


def _snap_forward(messages, index: int, limit: int) -> int:
    """Move a boundary forward until it no longer splits a tool exchange."""
    while index < limit and _is_orphaned(messages, index):
        index += 1
    return index


def plan(messages, *, budget: int = DEFAULT_BUDGET,
         protect_first: int = PROTECT_FIRST,
         protect_last: int = PROTECT_LAST) -> Plan:
    """Decide what to compress. Compresses nothing when nothing needs it."""
    count = len(messages)
    before = total_tokens(messages)

    head = min(protect_first, count)
    tail_start = max(head, count - protect_last)

    if before <= budget or tail_start <= head:
        return Plan(head, head, head, count - head, before, before)

    # Only as much as needed: walk the middle forward, stopping as soon as
    # dropping what has been walked would bring the total under budget.
    end = head
    saved = 0
    target = before - budget
    while end < tail_start and saved < target:
        saved += estimate_tokens(getattr(messages[end], "content", "") or "")
        end += 1

    end = _snap_forward(messages, end, tail_start)
    start = _snap_forward(messages, head, end)

    # The summary itself costs something; assume a generous 400 tokens.
    after = before - sum(
        estimate_tokens(getattr(m, "content", "") or "")
        for m in messages[start:end]
    ) + 400
    return Plan(head, start, end, count - end, before, max(after, 0))


def excerpt(messages, start: int, end: int, *, limit: int = 12_000) -> str:
    """The text handed to the summariser, oldest first, clipped."""
    lines = []
    for message in messages[start:end]:
        role = getattr(message, "role", "?")
        content = (getattr(message, "content", "") or "").strip()
        if not content:
            continue
        lines.append(f"[{role}] {content}")
    text = "\n\n".join(lines)
    return text if len(text) <= limit else text[:limit] + "\n…"


def apply(messages, plan_: Plan, summary: str, *, make_message) -> list:
    """Rebuild the conversation with the middle replaced by one message.

    `make_message` builds whatever message type the caller uses, so this
    module stays free of any provider's schema.
    """
    if not plan_.worth_doing:
        return list(messages)

    body = f"{MARKER} :\n{summary.strip()}"
    return [
        *messages[: plan_.start],
        make_message("user", body),
        *messages[plan_.end :],
    ]
