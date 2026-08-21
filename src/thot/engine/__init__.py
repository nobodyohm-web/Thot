"""The execution port.

Only the port is re-exported here. Backends live in their own modules and are
imported explicitly, because importing one pulls in whatever it talks to —
`factory` reaches credentials, which reaches an HTTP client. Keeping this
namespace to the port alone is what lets the deterministic core import
`thot.engine.base` without dragging the network in behind it.
"""

from thot.engine.base import (
    AgentResult,
    AgentTask,
    Engine,
    EngineCapabilities,
    extract_json,
)

__all__ = [
    "AgentResult",
    "AgentTask",
    "Engine",
    "EngineCapabilities",
    "extract_json",
]
