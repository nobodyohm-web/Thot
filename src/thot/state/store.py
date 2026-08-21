"""Sessions that outlive the terminal window.

Thot's counterpart to Hermes Agent's `SessionDB` and to Prime Agent's
session manager. Every turn is written as it happens, so an audit that was
interrupted — closed laptop, lost ssh, `Ctrl-C` — is still there tomorrow,
and so is the reasoning that went with it.

One file, `~/.thot/sessions.db`. No server, no account, no export step.

Deliberately separate from the run store (`thot.store.db`) and from verdict
memory (`thot.memory`): runs are disposable evidence, verdicts are reviewed
judgement, and this is the conversation. Each has its own lifetime.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from thot.state import goals, schema, usage
from thot.state.search import DEFAULT_LIMIT, Hit, search

from thot.paths import sessions_db

# Long enough that a title says something, short enough for one terminal row.
TITLE_CHARS = 72


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass(frozen=True)
class SessionInfo:
    id: str
    root: str
    title: str
    model: str
    parent_id: str
    started_at: str
    ended_at: str
    message_count: int
    cli_session_id: str = ""

    @property
    def live(self) -> bool:
        return not self.ended_at

    def label(self) -> str:
        name = self.title or "(sans titre)"
        return f"{self.id}  {name}"


@dataclass(frozen=True)
class Turn:
    seq: int
    role: str
    content: str
    tool_name: str
    created_at: str


_SESSION_COLUMNS = (
    "id, root, title, model, COALESCE(parent_id, ''), started_at, "
    "COALESCE(ended_at, ''), message_count, COALESCE(cli_session_id, '')"
)


def _to_info(row) -> SessionInfo:
    return SessionInfo(*row)


class SessionStore:
    """One SQLite file holding every session, message, and audit note."""

    def __init__(self, connection: sqlite3.Connection, *, searchable: bool,
                 journal: str = "") -> None:
        self._connection = connection
        self.searchable = searchable
        self.journal = journal

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def open(cls, path: Path | None = None) -> "SessionStore":
        path = Path(path or sessions_db())
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), check_same_thread=False)
        journal = schema.apply_pragmas(connection)
        searchable = schema.migrate(connection)
        return cls(connection, searchable=searchable, journal=journal)

    def close(self) -> None:
        self._connection.close()

    # -- writing ---------------------------------------------------------

    def start(self, root: str | Path, *, model: str = "", title: str = "",
              parent_id: str = "") -> str:
        session_id = new_id()
        self._connection.execute(
            "INSERT INTO sessions (id, root, title, model, parent_id, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, str(root), title[:TITLE_CHARS], model,
             parent_id or None, _now()),
        )
        self._connection.commit()
        return session_id

    def append(self, session_id: str, role: str, content: str,
               *, tool_name: str = "") -> int:
        """Record one turn. The first thing a user says becomes the title."""
        row = self._connection.execute(
            "SELECT message_count, title FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"session inconnue : {session_id}")
        seq, title = int(row[0]), row[1]

        self._connection.execute(
            "INSERT INTO messages (session_id, seq, role, content, tool_name, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, seq, role, content, tool_name, _now()),
        )
        updates = "message_count = ?"
        params: list = [seq + 1]
        # A session opened only to set a goal is still about something.
        if not title and role in {"user", "goal"} and content.strip():
            updates += ", title = ?"
            params.append(" ".join(content.split())[:TITLE_CHARS])
        params.append(session_id)
        self._connection.execute(
            f"UPDATE sessions SET {updates} WHERE id = ?", params
        )
        self._connection.commit()
        return seq

    def note(self, session_id: str, text: str, *, kind: str = "audit") -> int:
        """Record something Thot did rather than said — an audit, a verdict.

        Notes go through the same table as speech on purpose: `/search` then
        finds "where did I see that SQL injection" without the user having
        to remember whether they read it or were told it.
        """
        return self.append(session_id, kind, text)

    def end(self, session_id: str) -> None:
        self._connection.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
            (_now(), session_id),
        )
        self._connection.commit()

    def link_cli(self, session_id: str, cli_session_id: str) -> None:
        """Remember which backend conversation this session is indexing.

        What makes `/resume` reopen the real thread instead of replaying a
        transcript at a model that has already forgotten it.
        """
        self._connection.execute(
            "UPDATE sessions SET cli_session_id = ? WHERE id = ?",
            (cli_session_id, session_id),
        )
        self._connection.commit()

    def reopen(self, session_id: str) -> None:
        """Mark a closed session live again — what `/resume` means on disk."""
        self._connection.execute(
            "UPDATE sessions SET ended_at = NULL WHERE id = ?", (session_id,)
        )
        self._connection.commit()

    def rename(self, session_id: str, title: str) -> None:
        self._connection.execute(
            "UPDATE sessions SET title = ? WHERE id = ?",
            (" ".join(title.split())[:TITLE_CHARS], session_id),
        )
        self._connection.commit()

    def branch(self, session_id: str, summary: str, *, title: str = "") -> str:
        """Continue a session in a fresh one that starts from a summary.

        This is compaction with a paper trail: the long session is closed
        and kept whole, and the new one begins knowing what it concluded.
        Hermes calls the link a compression child, Prime calls the act
        compaction; the chain is what makes either reversible.
        """
        parent = self.info(session_id)
        if parent is None:
            raise KeyError(f"session inconnue : {session_id}")
        child = self.start(
            parent.root,
            model=parent.model,
            title=title or parent.title,
            parent_id=session_id,
        )
        self.append(child, "summary", summary)
        self.end(session_id)
        return child

    def forget(self, session_id: str) -> bool:
        cursor = self._connection.execute(
            "DELETE FROM sessions WHERE id = ?", (session_id,)
        )
        self._connection.execute(
            "DELETE FROM messages WHERE session_id = ?", (session_id,)
        )
        self._connection.commit()
        return cursor.rowcount > 0

    # -- usage -----------------------------------------------------------

    def charge(self, session_id: str, input_tokens: int, output_tokens: int) -> None:
        usage.charge(self._connection, session_id, input_tokens, output_tokens)

    def usage(self, session_id: str) -> "usage.Usage":
        return usage.of(self._connection, session_id)

    def usage_across(self, root: str | Path | None = None) -> "usage.Usage":
        return usage.across(self._connection,
                            None if root is None else str(root))

    # -- goals -----------------------------------------------------------
    #
    # Thin delegation, the way Hermes composes SessionDB out of mixins: the
    # goal logic lives in its own module and the store is what owns the
    # connection.

    def set_goal(self, root: str | Path, objective: str,
                 *, token_budget: int | None = None) -> "goals.Goal":
        return goals.start(self._connection, str(root), objective,
                           token_budget=token_budget)

    def goal(self, root: str | Path) -> "goals.Goal | None":
        return goals.active(self._connection, str(root))

    def goal_history(self, root: str | Path | None = None,
                     *, limit: int = 20) -> list["goals.Goal"]:
        return goals.history(self._connection,
                             None if root is None else str(root), limit=limit)

    def charge_goal(self, goal_id: str, tokens: int,
                    *, calls: int = 1) -> "goals.Goal | None":
        return goals.charge(self._connection, goal_id, tokens, calls=calls)

    def raise_goal_budget(self, goal_id: str,
                          token_budget: int | None) -> "goals.Goal | None":
        return goals.raise_budget(self._connection, goal_id, token_budget)

    def finish_goal(self, goal_id: str, status: str = "complete",
                    *, note: str = "") -> "goals.Goal | None":
        return goals.finish(self._connection, goal_id, status, note=note)

    def pause_goal(self, goal_id: str, *, paused: bool = True) -> "goals.Goal | None":
        return goals.set_status(self._connection, goal_id,
                                "paused" if paused else "active")

    # -- reading ---------------------------------------------------------

    def info(self, session_id: str) -> SessionInfo | None:
        row = self._connection.execute(
            f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return _to_info(row) if row else None

    def sessions(self, root: str | Path | None = None,
                 *, limit: int = DEFAULT_LIMIT) -> list[SessionInfo]:
        sql = f"SELECT {_SESSION_COLUMNS} FROM sessions"
        params: list = []
        if root is not None:
            sql += " WHERE root = ?"
            params.append(str(root))
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        return [_to_info(row) for row in self._connection.execute(sql, params)]

    def latest(self, root: str | Path | None = None) -> SessionInfo | None:
        found = self.sessions(root, limit=1)
        return found[0] if found else None

    def turns(self, session_id: str, *, limit: int | None = None,
              roles: tuple[str, ...] = ()) -> list[Turn]:
        sql = ("SELECT seq, role, content, tool_name, created_at FROM messages "
               "WHERE session_id = ?")
        params: list = [session_id]
        if roles:
            sql += f" AND role IN ({','.join('?' * len(roles))})"
            params.extend(roles)
        sql += " ORDER BY seq"
        rows = list(self._connection.execute(sql, params))
        if limit is not None and len(rows) > limit:
            rows = rows[-limit:]  # the tail is what a resume needs
        return [Turn(*row) for row in rows]

    def ancestry(self, session_id: str) -> list[SessionInfo]:
        """The whole chain, oldest first, following compaction links."""
        chain: list[SessionInfo] = []
        seen: set[str] = set()
        current = self.info(session_id)
        while current and current.id not in seen:
            seen.add(current.id)
            chain.append(current)
            current = self.info(current.parent_id) if current.parent_id else None
        return list(reversed(chain))

    def find(self, query: str, *, root: str | Path | None = None,
             limit: int = DEFAULT_LIMIT) -> list[Hit]:
        return search(
            self._connection,
            query,
            searchable=self.searchable,
            root=str(root) if root is not None else "",
            limit=limit,
        )

    def resolve(self, prefix: str) -> str | None:
        """Accept the short id a user actually typed, if it is unambiguous."""
        rows = self._connection.execute(
            "SELECT id FROM sessions WHERE id LIKE ? LIMIT 2", (f"{prefix}%",)
        ).fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def stats(self) -> dict:
        sessions, messages = self._connection.execute(
            "SELECT (SELECT COUNT(*) FROM sessions), (SELECT COUNT(*) FROM messages)"
        ).fetchone()
        return {
            "sessions": int(sessions),
            "messages": int(messages),
            "search": "fts5" if self.searchable else "substring",
            "journal": self.journal,
        }
