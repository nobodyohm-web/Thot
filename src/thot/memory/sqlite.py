"""The shipped memory: one SQLite file, no server, no account.

Kept separate from the run store on purpose. Runs are disposable history;
verdicts are the reviewed judgement of a codebase and must outlive any
particular run, any particular checkout, and `thot logout`.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from thot.memory.base import Decision, Verdict

from thot.paths import memory_db

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    finding_id TEXT PRIMARY KEY,
    decision   TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    author     TEXT NOT NULL DEFAULT '',
    rule       TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    symbol     TEXT NOT NULL DEFAULT '',
    ast_hash   TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS verdicts_by_path ON verdicts(path);
"""

_COLUMNS = (
    "finding_id, decision, reason, author, rule, path, symbol, ast_hash, decided_at"
)


class SqliteMemory:
    name = "sqlite"

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._connection.executescript(_SCHEMA)
        self._connection.commit()

    @classmethod
    def open(cls, path: Path | None = None) -> "SqliteMemory":
        target = Path(path or memory_db())
        target.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(target))
        connection.row_factory = sqlite3.Row
        return cls(connection)

    def is_available(self) -> bool:
        return True

    def remember(self, verdict: Verdict) -> None:
        self._connection.execute(
            f"INSERT INTO verdicts ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(finding_id) DO UPDATE SET "
            "decision=excluded.decision, reason=excluded.reason, "
            "author=excluded.author, decided_at=excluded.decided_at",
            (
                verdict.finding_id,
                verdict.decision.value,
                verdict.reason,
                verdict.author,
                verdict.rule,
                verdict.path,
                verdict.symbol,
                verdict.ast_hash,
                verdict.decided_at,
            ),
        )
        self._connection.commit()

    def recall(self, finding_id: str) -> Verdict | None:
        row = self._connection.execute(
            f"SELECT {_COLUMNS} FROM verdicts WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return _from_row(row) if row else None

    def all_verdicts(self) -> list[Verdict]:
        rows = self._connection.execute(
            f"SELECT {_COLUMNS} FROM verdicts ORDER BY decided_at DESC"
        ).fetchall()
        return [_from_row(row) for row in rows]

    def forget(self, finding_id: str) -> bool:
        cursor = self._connection.execute(
            "DELETE FROM verdicts WHERE finding_id = ?", (finding_id,)
        )
        self._connection.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        self._connection.close()


def _from_row(row: sqlite3.Row) -> Verdict:
    return Verdict(
        finding_id=row["finding_id"],
        decision=Decision(row["decision"]),
        reason=row["reason"],
        author=row["author"],
        rule=row["rule"],
        path=row["path"],
        symbol=row["symbol"],
        ast_hash=row["ast_hash"],
        decided_at=row["decided_at"],
    )
