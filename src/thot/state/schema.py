"""Tables, indexes, and the full-text mirror, plus their migrations.

Ported from Hermes Agent's `hermes_state_schema.py`, keeping the decisions
that were paid for in production and dropping the gateway-specific ones:

* the schema is **additive** — a column is added, never repurposed, so an
  older Thot opening a newer database still reads every row it knows about;
* the FTS5 mirror is built by trigger, so no write path can forget to index;
* FTS5 is **probed**, not assumed. A Python built against a SQLite without
  it must lose search, not lose the session store.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    root          TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT '',
    parent_id     TEXT,
    started_at    TEXT NOT NULL,
    ended_at      TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    -- The conversation id owned by the backend, when it owns one. Thot
    -- indexes the thread; `claude --resume` is what actually reopens it.
    cli_session_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS sessions_by_root ON sessions(root, started_at DESC);
CREATE INDEX IF NOT EXISTS sessions_by_parent ON sessions(parent_id);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL DEFAULT '',
    tool_name  TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS messages_by_session ON messages(session_id, seq);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# External-content FTS: the text lives once, in `messages`. The mirror holds
# only the index, so a rebuild costs disk that is already there.
FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    content,
    tool_name,
    content='messages',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
"""

FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content, tool_name)
    VALUES (new.id, new.content, new.tool_name);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content, tool_name)
    VALUES ('delete', old.id, old.content, old.tool_name);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content, tool_name)
    VALUES ('delete', old.id, old.content, old.tool_name);
    INSERT INTO messages_fts(rowid, content, tool_name)
    VALUES (new.id, new.content, new.tool_name);
END;
"""


def has_fts5(connection: sqlite3.Connection) -> bool:
    """Whether this SQLite can build the search mirror.

    Asked by creating a throwaway table rather than by reading a version
    string: what matters is whether the module is compiled in *here*.
    """
    try:
        connection.execute("CREATE VIRTUAL TABLE temp._fts_probe USING fts5(x)")
    except sqlite3.Error:
        return False
    connection.execute("DROP TABLE temp._fts_probe")
    return True


def apply_pragmas(connection: sqlite3.Connection) -> str:
    """Concurrency settings, degrading rather than failing.

    WAL lets a scheduled audit write while a session reads. Network shares
    and some containers refuse it; there the store still works, so the
    fallback is silent and the journal mode is returned for `/status`.
    """
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    try:
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
    except sqlite3.Error:
        mode = "delete"
    return str(mode).lower()


def migrate(connection: sqlite3.Connection) -> bool:
    """Create or upgrade the schema. Returns whether search is available."""
    from thot.state import goals

    connection.executescript(SCHEMA_SQL)
    goals.migrate(connection)  # v2: Prime's persistent objective

    searchable = has_fts5(connection)
    if searchable:
        connection.executescript(FTS_SQL)
        connection.executescript(FTS_TRIGGERS)

    connection.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()
    return searchable
