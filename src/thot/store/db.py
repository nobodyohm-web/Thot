"""SQLite store. Local, volume-tolerant, never versioned."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL,
    commit_sha TEXT,
    started_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER NOT NULL,
    id TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    symbol TEXT,
    ast_hash TEXT,
    taint_path TEXT NOT NULL DEFAULT '[]',
    failure_scenario TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, id)
);

CREATE TABLE IF NOT EXISTS symbol_cache (
    symbol TEXT PRIMARY KEY,
    ast_hash TEXT NOT NULL
);
"""


class Store:
    """Every write commits immediately: an interrupted audit keeps its findings."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, path: Path) -> "Store":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.executescript(_SCHEMA)
        connection.commit()
        return cls(connection)

    def start_run(self, root: str, commit: str | None) -> int:
        cursor = self._connection.execute(
            "INSERT INTO runs (root, commit_sha) VALUES (?, ?)", (root, commit)
        )
        self._connection.commit()
        return int(cursor.lastrowid)

    def save_findings(self, run_id: int, findings: list[Finding]) -> None:
        rows = [
            (
                run_id,
                f.id,
                f.rule,
                f.severity.value,
                f.confidence.value,
                f.location.path,
                f.location.line,
                f.location.symbol,
                f.location.ast_hash,
                json.dumps([[r.path, r.line, r.symbol] for r in f.taint_path]),
                f.failure_scenario,
            )
            for f in findings
        ]
        self._connection.executemany(
            "INSERT OR REPLACE INTO findings "
            "(run_id, id, rule, severity, confidence, path, line, symbol, "
            " ast_hash, taint_path, failure_scenario) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._connection.commit()

    def findings_for_run(self, run_id: int) -> list[Finding]:
        cursor = self._connection.execute(
            "SELECT id, rule, severity, confidence, path, line, symbol, ast_hash, "
            "taint_path, failure_scenario FROM findings WHERE run_id = ? "
            "ORDER BY severity, path, line",
            (run_id,),
        )
        findings = []
        for row in cursor.fetchall():
            path_entries = json.loads(row[8])
            findings.append(
                Finding(
                    id=row[0],
                    rule=row[1],
                    severity=Severity(row[2]),
                    confidence=Confidence(row[3]),
                    location=CodeRef(
                        path=row[4], line=row[5], symbol=row[6], ast_hash=row[7]
                    ),
                    taint_path=tuple(
                        CodeRef(path=entry[0], line=entry[1], symbol=entry[2])
                        for entry in path_entries
                    ),
                    failure_scenario=row[9],
                )
            )
        return findings

    def previous_finding_ids(self, root: str) -> set[str]:
        """What the most recent stored run on this repository already knew.

        The basis for a scheduled audit reporting a diff rather than a census.
        Call it *before* starting the new run — afterwards the newest row is
        the run you are comparing against itself. An empty set means first
        run, and everything being new is then the correct answer.
        """
        row = self._connection.execute(
            "SELECT id FROM runs WHERE root = ? ORDER BY id DESC LIMIT 1",
            (root,),
        ).fetchone()
        if row is None:
            return set()
        rows = self._connection.execute(
            "SELECT id FROM findings WHERE run_id = ?", (row[0],)
        ).fetchall()
        return {r[0] for r in rows}

    def remember_symbols(self, mapping: dict[str, str]) -> None:
        if not mapping:
            return
        self._connection.executemany(
            "INSERT OR REPLACE INTO symbol_cache (symbol, ast_hash) VALUES (?, ?)",
            list(mapping.items()),
        )
        self._connection.commit()

    def cached_symbol_hashes(self) -> dict[str, str]:
        cursor = self._connection.execute("SELECT symbol, ast_hash FROM symbol_cache")
        return dict(cursor.fetchall())

    def close(self) -> None:
        self._connection.close()
