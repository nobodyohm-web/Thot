"""Paying twice for the same prefix, every turn.

`engine/base.py` says `AgentTask` keeps `context` apart from `instructions`
"so an engine that supports prompt caching can cache the bulky half without
touching the question". The separation was made and the breakpoint was never
placed: `grep -rn cache_control src/thot` returned nothing at all, while the
system prompt carries the whole repository map on every single call.
"""

from __future__ import annotations

from thot.llm.anthropic import system_blocks


def test_the_system_prompt_is_sent_as_a_cacheable_block():
    blocks = system_blocks("la carte du dépôt, longue et stable")

    assert isinstance(blocks, list)
    assert blocks[-1]["cache_control"] == {"type": "ephemeral"}
    assert blocks[0]["text"].startswith("la carte")


def test_an_empty_system_carries_no_breakpoint():
    """A cache breakpoint on nothing is a header the API has to refuse."""
    assert system_blocks("") == []


def test_the_breakpoint_sits_at_the_end_of_the_stable_prefix():
    """Anthropic caches everything up to and including the marked block, and
    the request order is tools, then system, then messages — so one marker on
    the system block covers the tools too."""
    import inspect

    from thot.llm import anthropic

    source = inspect.getsource(anthropic.system_blocks)
    assert "ephemeral" in source
