"""Search across everything Thot has ever been told, and ever answered.

Ported from Hermes Agent's `hermes_state_search.py`. Two lessons from that
file survive here because both were real defects:

* a user's query is **not** an FTS5 expression. Typing ``run_command(``
  makes the MATCH raise, and the raise is swallowed at the call site into
  "no results" — a search that lies. Terms are quoted before they reach it.
* when FTS5 is missing, falling back to LIKE keeps search working slowly
  instead of removing it silently.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

# How much text rides back per hit. Enough to recognise the moment, short
# enough that twenty hits stay readable in a terminal.
SNIPPET_TOKENS = 12
DEFAULT_LIMIT = 20

_TERM = re.compile(r"[^\W_]+(?:[-_.][^\W_]+)*\*?", re.UNICODE)

OPEN, CLOSE = "\x02", "\x03"  # match markers, styled by the caller


@dataclass(frozen=True)
class Hit:
    session_id: str
    seq: int
    role: str
    snippet: str
    created_at: str
    root: str = ""
    title: str = ""

    def plain(self) -> str:
        return self.snippet.replace(OPEN, "").replace(CLOSE, "")


def to_match_query(text: str) -> str:
    """A user's words as an expression FTS5 will accept.

    Every term is quoted, so parentheses, colons and hyphens are searched
    for rather than interpreted. A trailing ``*`` survives outside the
    quotes, which keeps prefix search available on purpose.
    """
    terms = []
    for raw in _TERM.findall(text or ""):
        prefix = raw.endswith("*")
        word = raw.rstrip("*").replace('"', "")
        if not word:
            continue
        terms.append(f'"{word}"*' if prefix else f'"{word}"')
    return " AND ".join(terms)


def _rows_to_hits(rows) -> list[Hit]:
    return [
        Hit(
            session_id=row[0],
            seq=row[1],
            role=row[2],
            snippet=row[3],
            created_at=row[4],
            root=row[5] or "",
            title=row[6] or "",
        )
        for row in rows
    ]


def search(
    connection: sqlite3.Connection,
    query: str,
    *,
    searchable: bool,
    root: str = "",
    limit: int = DEFAULT_LIMIT,
) -> list[Hit]:
    """Messages matching `query`, newest first, optionally scoped to a repo."""
    if not (query or "").strip():
        return []
    if searchable:
        hits = _fts_search(connection, query, root=root, limit=limit)
        if hits:
            return hits
        # An empty FTS answer can mean "absent" or "unindexed"; LIKE tells
        # them apart at a cost only paid when the fast path found nothing.
    return _like_search(connection, query, root=root, limit=limit)


def _fts_search(
    connection: sqlite3.Connection, query: str, *, root: str, limit: int
) -> list[Hit]:
    match = to_match_query(query)
    if not match:
        return []

    # The cut happens in the inner select, before the joins and before
    # snippet(): ordering on the FTS rowid is the order fts5 already walks,
    # so it returns `limit` rows and stops. Ordering on `m.id` instead reads
    # every match, joins it, renders its snippet and sorts the lot in a temp
    # b-tree, whose cost is the whole match set: measured on 150 000 short
    # messages, 58 ms against 1.3 ms, and the gap widens with message length
    # because the sorter renders every snippet before it sorts.
    inner = (
        "SELECT messages_fts.rowid AS rid FROM messages_fts "
        "JOIN messages mm ON mm.id = messages_fts.rowid "
        "JOIN sessions ss ON ss.id = mm.session_id "
        "WHERE messages_fts MATCH ?"
    )
    params: list = [match]
    if root:
        # Inside, not outside: cutting on the unscoped set would hand back
        # the twenty newest matches anywhere and then filter them down.
        inner += " AND ss.root = ?"
        params.append(root)
    inner += " ORDER BY messages_fts.rowid DESC LIMIT ?"
    params.append(limit)

    # messages_fts is joined a second time, with the same MATCH, because
    # snippet() needs the query it is highlighting.
    sql = (
        f"SELECT m.session_id, m.seq, m.role, "
        f"snippet(messages_fts, 0, '{OPEN}', '{CLOSE}', '…', {SNIPPET_TOKENS}), "
        "m.created_at, s.root, s.title "
        f"FROM ({inner}) f "
        "JOIN messages_fts ON messages_fts.rowid = f.rid AND messages_fts MATCH ? "
        "JOIN messages m ON m.id = f.rid "
        "JOIN sessions s ON s.id = m.session_id "
        "ORDER BY f.rid DESC"
    )
    params.append(match)

    try:
        return _rows_to_hits(connection.execute(sql, params).fetchall())
    except sqlite3.Error:
        return []


def _like_search(
    connection: sqlite3.Connection, query: str, *, root: str, limit: int
) -> list[Hit]:
    """The slow path: substring matching, always available."""
    # Escaped, not stripped: `find_symbol` and `run_command` are the names
    # one actually searches for in a Python repository, and deleting their
    # underscore made every one of them unfindable. The backslash goes first
    # so it does not double-escape what the next two replacements add.
    body = query.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    needle = f"%{body}%"
    sql = (
        "SELECT m.session_id, m.seq, m.role, m.content, m.created_at, s.root, s.title "
        "FROM messages m JOIN sessions s ON s.id = m.session_id "
        "WHERE m.content LIKE ? ESCAPE '\\'"
    )
    params: list = [needle]
    if root:
        sql += " AND s.root = ?"
        params.append(root)
    sql += " ORDER BY m.id DESC LIMIT ?"
    params.append(limit)

    rows = connection.execute(sql, params).fetchall()
    return [
        Hit(
            session_id=row[0],
            seq=row[1],
            role=row[2],
            snippet=_excerpt(row[3], query),
            created_at=row[4],
            root=row[5] or "",
            title=row[6] or "",
        )
        for row in rows
    ]


def _excerpt(content: str, query: str, *, width: int = 90) -> str:
    """Centre the window on the match, the way snippet() would."""
    lowered, needle = content.lower(), query.strip().lower()
    position = lowered.find(needle)
    if position == -1:
        return content[:width].strip()
    start = max(0, position - width // 3)
    end = min(len(content), position + len(needle) + width // 2)
    body = (
        content[start:position]
        + OPEN
        + content[position : position + len(needle)]
        + CLOSE
        + content[position + len(needle) : end]
    )
    return ("…" if start else "") + body.strip() + ("…" if end < len(content) else "")
