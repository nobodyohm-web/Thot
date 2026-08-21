"""What a chat platform has to be able to do, and nothing more.

Thot's port of Hermes Agent's platform adapters, narrowed to the two verbs
an audit tool needs: push a report out, and take a short command back.

Hermes's gateway carries voice, stickers, media policy and twenty-two
platforms because it is a general assistant you live with. Thot's carries
findings. Anything a platform can do beyond `send` and `poll` is deliberately
absent — a gateway with a smaller surface is a gateway with fewer ways to
reach the auditor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Chat platforms truncate, and a wall of findings is unreadable on a phone
# regardless. Reports are cut to this and say how much was cut.
MAX_MESSAGE_CHARS = 3500


@dataclass(frozen=True)
class Incoming:
    """One message a human sent to the bot."""

    text: str
    sender: str          # platform-native id, matched against the allowlist
    channel: str = ""    # where to reply, when it differs from the home channel
    sender_name: str = ""

    def command(self) -> tuple[str, str]:
        """`audit /repo` -> ("audit", "/repo"). Leading slash optional."""
        cleaned = self.text.strip().lstrip("/")
        verb, _, rest = cleaned.partition(" ")
        return verb.strip().lower(), rest.strip()


@dataclass(frozen=True)
class Delivery:
    """The outcome of one send. Never an exception: a channel that is down
    must cost its own notification, not the audit that produced it."""

    platform: str
    ok: bool
    detail: str = ""


@runtime_checkable
class Platform(Protocol):
    """A channel Thot can talk through."""

    name: str

    def configured(self) -> bool:
        """Whether this channel has what it needs to send."""

    def send(self, text: str, *, channel: str = "") -> Delivery:
        """Push a message out. Returns the outcome, never raises."""

    def poll(self) -> list[Incoming]:
        """Messages since the last call. Empty when the platform is one-way."""


@dataclass
class Channel:
    """One configured destination, and who may command through it."""

    platform: str
    settings: dict = field(default_factory=dict)
    allow: tuple[str, ...] = ()

    @property
    def two_way(self) -> bool:
        """Inbound commands need an allowlist. No allowlist, no commands.

        Hermes offers an `ALLOW_ALL_USERS` escape hatch for development.
        Thot does not: this gateway can start audits and record verdicts,
        so an unnamed commander is not a convenience, it is an open door.
        """
        return bool(self.allow)

    def allows(self, sender: str) -> bool:
        return bool(sender) and str(sender) in self.allow


def truncate(text: str, limit: int = MAX_MESSAGE_CHARS) -> str:
    """Cut to a length chat platforms accept, and say that you cut."""
    if len(text) <= limit:
        return text
    head = text[: limit - 60].rsplit("\n", 1)[0]
    hidden = len(text) - len(head)
    return f"{head}\n… {hidden} caractères de plus (voir `thot audit`)."
