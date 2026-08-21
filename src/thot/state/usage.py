"""What a session cost, and what is currently filling its context.

Two Prime Agent ideas, ported together because they answer the same
question from either side: `core/usage.ts` + `core/session-stats.ts` for
what has been spent, `core/context-tree.ts` for what is occupying the
window right now.

Thot's version is deliberately smaller than Prime's. Prime tracks a tree
of sub-agents with usage attributed so parents never double-count their
children; Thot has one conversation and an engine that fans out for
`--deep`, so there is no tree to draw — the honest shape here is a flat
breakdown.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

SCHEMA_SQL = """
ALTER TABLE sessions ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN output_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN calls INTEGER NOT NULL DEFAULT 0;
"""


def migrate(connection: sqlite3.Connection) -> None:
    """Add the usage columns, once. Additive, so an older Thot still reads."""
    existing = {row[1] for row in
                connection.execute("PRAGMA table_info(sessions)")}
    for statement in SCHEMA_SQL.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        column = statement.split("ADD COLUMN")[1].split()[0]
        if column not in existing:
            connection.execute(statement)


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def describe(self) -> str:
        if not self.calls:
            return "aucun appel modèle"
        return (f"{self.calls} appel(s) · {self.input_tokens} entrée + "
                f"{self.output_tokens} sortie = {self.total} jetons")


def charge(connection: sqlite3.Connection, session_id: str,
           input_tokens: int, output_tokens: int) -> None:
    connection.execute(
        "UPDATE sessions SET input_tokens = input_tokens + ?, "
        "output_tokens = output_tokens + ?, calls = calls + 1 WHERE id = ?",
        (max(0, input_tokens), max(0, output_tokens), session_id),
    )
    connection.commit()


def of(connection: sqlite3.Connection, session_id: str) -> Usage:
    row = connection.execute(
        "SELECT input_tokens, output_tokens, calls FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    return Usage(*row) if row else Usage()


def across(connection: sqlite3.Connection, root: str | None = None) -> Usage:
    """Everything spent, optionally on one repository."""
    sql = ("SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), "
           "COALESCE(SUM(calls), 0) FROM sessions")
    params: list = []
    if root is not None:
        sql += " WHERE root = ?"
        params.append(str(root))
    return Usage(*connection.execute(sql, params).fetchone())


# -- what is in the window right now -----------------------------------------


@dataclass(frozen=True)
class Slice:
    """One contributor to the context, with its estimated share."""

    label: str
    tokens: int
    detail: str = ""


def context_breakdown(*, brief: str = "", goal: str = "", messages=(),
                      skills: int = 0) -> list[Slice]:
    """Where the context window is actually going.

    The briefing is counted separately from the conversation because it is
    the part a user can do something about — a repository map that has
    grown to a third of the window is a `.thotignore` away from not being.
    """
    from thot.state.compaction import estimate_tokens

    by_role: dict[str, int] = {}
    for message in messages:
        role = getattr(message, "role", "?")
        by_role[role] = by_role.get(role, 0) + estimate_tokens(
            getattr(message, "content", "") or ""
        )

    slices = []
    if brief:
        slices.append(Slice("carte du dépôt", estimate_tokens(brief),
                            "réduis-la avec .thotignore"))
    if goal:
        slices.append(Slice("objectif", estimate_tokens(goal)))
    for role in ("user", "assistant", "tool", "summary"):
        if by_role.get(role):
            slices.append(Slice(f"messages · {role}", by_role[role],
                                f"{sum(1 for m in messages if getattr(m, 'role', '') == role)} message(s)"))
    if skills:
        slices.append(Slice("catalogue des méthodes", 0,
                            f"{skills} méthodes, chargées à la demande"))
    return sorted(slices, key=lambda s: -s.tokens)
