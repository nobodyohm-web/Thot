"""A goal that outlives the session, with a budget it cannot quietly exceed.

Ported from Prime Agent's `core/goals.ts`, whose model is kept: an
objective, a status, a token budget, and the fact that running out of
budget is a **state**, not an error. Prime's insight is that an agent
told to keep going until something is true needs somewhere to keep that
"something" other than the conversation it is about to compact away.

Thot's version is per repository rather than per thread, because the thing
being pursued here is a property of a codebase — "no HIGH left in the
parser" — and that outlives any one session.

Stored beside the sessions, in Hermes's schema style: additive columns,
one row per goal, the active one found by status rather than by a flag
that two writers could disagree about.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

# Prime's states, unchanged. `budget_limited` is the one that earns its
# place: it separates "gave up" from "was stopped", which a user needs in
# order to decide whether to raise the budget or change the objective.
STATUSES = ("active", "paused", "budget_limited", "complete", "abandoned")
LIVE_STATUSES = ("active", "paused", "budget_limited")

MAX_OBJECTIVE_CHARS = 4000

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS goals (
    id           TEXT PRIMARY KEY,
    root         TEXT NOT NULL,
    objective    TEXT NOT NULL,
    status       TEXT NOT NULL,
    token_budget INTEGER,
    tokens_used  INTEGER NOT NULL DEFAULT 0,
    calls_used   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS goals_by_root ON goals(root, status);
"""

_COLUMNS = (
    "id, root, objective, status, token_budget, tokens_used, calls_used, "
    "created_at, updated_at, note"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Goal:
    id: str
    root: str
    objective: str
    status: str
    token_budget: int | None
    tokens_used: int
    calls_used: int
    created_at: str
    updated_at: str
    note: str = ""

    @property
    def live(self) -> bool:
        return self.status in LIVE_STATUSES

    @property
    def remaining(self) -> int | None:
        if self.token_budget is None:
            return None
        return max(0, self.token_budget - self.tokens_used)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0 and self.token_budget is not None

    def progress(self) -> str:
        """One line: what is being pursued, and what it has cost so far."""
        if self.token_budget is None:
            return f"{self.tokens_used} jetons · {self.calls_used} appel(s)"
        share = int(100 * self.tokens_used / self.token_budget)
        return (
            f"{self.tokens_used}/{self.token_budget} jetons ({share} %) · "
            f"{self.calls_used} appel(s)"
        )

    def brief(self) -> str:
        """What the model is told, every turn, for as long as this is live."""
        lines = [f"Objectif en cours : {self.objective}"]
        if self.token_budget is not None:
            lines.append(
                f"Budget : {self.remaining} jetons restants sur "
                f"{self.token_budget}."
            )
        if self.status == "budget_limited":
            lines.append(
                "Le budget est épuisé. N'entame rien de nouveau : dis où en est "
                "l'objectif et ce qu'il resterait à faire."
            )
        elif self.status == "paused":
            lines.append("Objectif en pause — n'y travaille que si on te le demande.")
        return "\n".join(lines)


def _to_goal(row) -> Goal:
    return Goal(*row)


def migrate(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)


def start(connection: sqlite3.Connection, root: str, objective: str,
          *, token_budget: int | None = None) -> Goal:
    """Open a goal on this repository, replacing any live one.

    One live goal at a time is a deliberate limit: two objectives means
    neither is what the next turn is actually about.
    """
    objective = " ".join(objective.split())
    if not objective:
        raise ValueError("Un objectif vide n'est pas un objectif.")
    if len(objective) > MAX_OBJECTIVE_CHARS:
        raise ValueError(
            f"L'objectif dépasse {MAX_OBJECTIVE_CHARS} caractères."
        )
    if token_budget is not None and token_budget <= 0:
        raise ValueError("Le budget doit être un entier positif.")

    current = active(connection, root)
    if current is not None:
        finish(connection, current.id, "abandoned", note="remplacé")

    goal_id = uuid.uuid4().hex[:12]
    stamp = _now()
    connection.execute(
        "INSERT INTO goals (id, root, objective, status, token_budget, "
        "created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)",
        (goal_id, str(root), objective, token_budget, stamp, stamp),
    )
    connection.commit()
    return get(connection, goal_id)


def get(connection: sqlite3.Connection, goal_id: str) -> Goal | None:
    row = connection.execute(
        f"SELECT {_COLUMNS} FROM goals WHERE id = ?", (goal_id,)
    ).fetchone()
    return _to_goal(row) if row else None


def active(connection: sqlite3.Connection, root: str) -> Goal | None:
    """The live goal for this repository, newest first if history is messy."""
    placeholders = ",".join("?" * len(LIVE_STATUSES))
    row = connection.execute(
        f"SELECT {_COLUMNS} FROM goals WHERE root = ? "
        f"AND status IN ({placeholders}) ORDER BY created_at DESC LIMIT 1",
        (str(root), *LIVE_STATUSES),
    ).fetchone()
    return _to_goal(row) if row else None


def history(connection: sqlite3.Connection, root: str | None = None,
            *, limit: int = 20) -> list[Goal]:
    sql = f"SELECT {_COLUMNS} FROM goals"
    params: list = []
    if root is not None:
        sql += " WHERE root = ?"
        params.append(str(root))
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    return [_to_goal(row) for row in connection.execute(sql, params)]


def charge(connection: sqlite3.Connection, goal_id: str, tokens: int,
           *, calls: int = 1) -> Goal | None:
    """Bill a turn against the goal, and stop it when the budget runs out.

    Crossing the budget flips the status rather than raising: the turn that
    crossed it already happened, and the user is owed a report of where the
    objective stands, not an exception.
    """
    goal = get(connection, goal_id)
    if goal is None or not goal.live:
        return goal

    used = goal.tokens_used + max(0, tokens)
    status = goal.status
    if goal.token_budget is not None and used >= goal.token_budget and status == "active":
        status = "budget_limited"

    connection.execute(
        "UPDATE goals SET tokens_used = ?, calls_used = ?, status = ?, "
        "updated_at = ? WHERE id = ?",
        (used, goal.calls_used + max(0, calls), status, _now(), goal_id),
    )
    connection.commit()
    return get(connection, goal_id)


def raise_budget(connection: sqlite3.Connection, goal_id: str,
                 token_budget: int | None) -> Goal | None:
    """Give a stopped goal more room, and put it back to work."""
    goal = get(connection, goal_id)
    if goal is None:
        return None
    if token_budget is not None and token_budget <= 0:
        raise ValueError("Le budget doit être un entier positif.")

    status = "active" if goal.status == "budget_limited" else goal.status
    connection.execute(
        "UPDATE goals SET token_budget = ?, status = ?, updated_at = ? WHERE id = ?",
        (token_budget, status, _now(), goal_id),
    )
    connection.commit()
    return get(connection, goal_id)


def set_status(connection: sqlite3.Connection, goal_id: str, status: str) -> Goal | None:
    if status not in STATUSES:
        raise ValueError(f"Statut inconnu : {status}")
    connection.execute(
        "UPDATE goals SET status = ?, updated_at = ? WHERE id = ?",
        (status, _now(), goal_id),
    )
    connection.commit()
    return get(connection, goal_id)


def finish(connection: sqlite3.Connection, goal_id: str, status: str = "complete",
           *, note: str = "") -> Goal | None:
    if status not in {"complete", "abandoned"}:
        raise ValueError("Un objectif se termine par 'complete' ou 'abandoned'.")
    connection.execute(
        "UPDATE goals SET status = ?, note = ?, updated_at = ? WHERE id = ?",
        (status, note, _now(), goal_id),
    )
    connection.commit()
    return get(connection, goal_id)
