"""Persistent, searchable session state.

Thot's port of Hermes Agent's `hermes_state*` modules, reduced to what a
local audit tool needs and keeping the hardening that was paid for in
production: additive schema, triggered full-text mirror, probed FTS5,
WAL with a silent fallback, and imports that never overwrite.
"""

from thot.state.portability import (
    export_session,
    import_session,
    read_import,
    write_export,
)
from thot.state.goals import Goal
from thot.state.search import Hit
from thot.state.store import SessionInfo, SessionStore, Turn

__all__ = [
    "Goal",
    "Hit",
    "SessionInfo",
    "SessionStore",
    "Turn",
    "export_session",
    "import_session",
    "read_import",
    "write_export",
]
