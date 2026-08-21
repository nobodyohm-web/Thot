"""The line protocol between Thot and the Python it is running.

One JSON object per line, both directions. Deliberately not Jupyter's
wire protocol: Prime Agent talks to a real `ipykernel` over ZeroMQ because
it needs comms, display hooks and interrupt semantics. Thot needs three
verbs, and paying for ZeroMQ plus ipykernel to get them would put a heavy
dependency between the auditor and the audited code.

The direction that matters is the second one. The kernel can ask the host
for something mid-cell — that is how `rlm()` works, and it is why the
child never needs a credential of its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# Parent -> child
EXEC = "exec"
PING = "ping"
REPLY = "reply"
SHUTDOWN = "shutdown"

# Child -> parent
RESULT = "result"
HOST = "host"      # the cell is asking the host to do something
READY = "ready"


def encode(message: dict) -> str:
    return json.dumps(message, ensure_ascii=False) + "\n"


def decode(line: str) -> dict | None:
    try:
        parsed = json.loads(line)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


@dataclass(frozen=True)
class Outcome:
    """What one cell produced."""

    stdout: str = ""
    value: str = ""
    error: str = ""
    calls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.error

    def render(self, *, limit: int = 6000) -> str:
        """What goes back to the model: output first, then the value."""
        from thot.output import truncate_tail

        parts = []
        if self.stdout.strip():
            parts.append(truncate_tail(self.stdout.rstrip(),
                                       max_bytes=limit).rendered(tail=True))
        if self.value:
            parts.append(f"→ {self.value}")
        if self.error:
            parts.append(self.error)
        return "\n".join(parts) or "(aucune sortie)"
