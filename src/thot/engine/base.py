"""The port every execution backend implements.

The core never knows who runs its agents. It builds `AgentTask` objects,
hands them to an `Engine`, and reads `AgentResult` objects back. Whether the
work went to a subprocess, an HTTP API, Prime's kernel or a Hermes subagent
is not its business.

Synchronous on purpose. Every backend Thot targets is either a subprocess or
a blocking HTTP call, both of which a thread pool parallelises correctly, and
staying synchronous keeps the core importable from a notebook, a cron job and
a test without an event loop in the way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from thot.llm.base import Usage


@dataclass(frozen=True)
class AgentTask:
    """One unit of model work, self-contained.

    `context` is kept apart from `instructions` so an engine that supports
    prompt caching can cache the bulky half without touching the question.
    """

    id: str
    instructions: str
    context: str = ""
    schema: dict[str, Any] | None = None  # JSON Schema the answer must match
    tier: str = "standard"  # "cheap" | "standard" | "deep"

    def prompt(self) -> str:
        if not self.context:
            return self.instructions
        return f"{self.context}\n\n---\n\n{self.instructions}"


@dataclass(frozen=True)
class AgentResult:
    """What came back. An engine never raises for a failed task: it reports."""

    task_id: str
    text: str = ""
    data: dict[str, Any] | None = None
    error: str | None = None
    usage: Usage = field(default_factory=Usage)

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class EngineCapabilities:
    """What a backend can do, so the core adapts without knowing who it is."""

    name: str
    max_parallel: int = 1
    tiering: bool = False  # can route cheap work to a smaller model
    stateful: bool = False  # keeps heavy state outside the context window


class Engine(Protocol):
    """Two methods. Everything else is an implementation detail."""

    @property
    def capabilities(self) -> EngineCapabilities: ...

    def run(self, task: AgentTask) -> AgentResult: ...

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        """Run tasks concurrently. Results come back in the order given."""
        ...


def extract_json(text: str) -> dict[str, Any] | None:
    """Pull the JSON object out of a model answer.

    Models wrap JSON in prose and fences however they please. Rather than
    fight that with prompt threats, accept the three shapes that actually
    occur: bare object, fenced block, object embedded in commentary.
    """
    import json
    import re

    candidates: list[str] = []
    fenced = re.findall(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    candidates.extend(fenced)
    candidates.append(text)

    for candidate in candidates:
        candidate = candidate.strip()
        start, end = candidate.find("{"), candidate.rfind("}")
        if start == -1 or end <= start:
            continue
        try:
            parsed = json.loads(candidate[start : end + 1])
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None
