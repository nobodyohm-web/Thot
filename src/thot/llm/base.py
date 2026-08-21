"""The one shape every model provider speaks.

Keeping this tiny is deliberate: a provider is a function that takes a
conversation and gives back the next assistant message. Everything
provider-specific — wire format, tool-call encoding, streaming frames — stays
inside its own module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolCall:
    """A tool the model wants run, with arguments already parsed."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    """One turn. `tool_results` carries answers back to the model."""

    role: str  # "user" | "assistant" | "tool"
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None


@dataclass(frozen=True)
class ToolSpec:
    """A tool offered to the model, described once for every provider."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the arguments object


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class Reply:
    """What a provider returns: a message plus what it cost."""

    message: Message
    usage: Usage = field(default_factory=Usage)


class Provider(Protocol):
    """Implemented by every backend. Two attributes, one method."""

    name: str
    model: str

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec],
        on_text: Callable[[str], None] | None = None,
    ) -> Reply:
        """Produce the next assistant message.

        `on_text` receives text fragments as they arrive so the caller can
        stream them; providers that cannot stream call it once at the end.
        """
        ...


class ProviderError(RuntimeError):
    """A provider could not answer. The message is shown to the user as-is."""
