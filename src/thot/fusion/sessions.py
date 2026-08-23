"""One history across the three programs.

Each keeps its own, in its own store, and that is right: a session is the
private record of one program's conversation, with its own schema and its
own retention. Merging the storage would mean one program's migration
breaking another's history.

What can be merged is the *view*. "What was I doing on this repository last
Tuesday" is a question about the work, not about which of three binaries
happened to be in front of you at the time.

    thot    `~/.thot/store.db`             table `sessions`
    hermes  `~/.hermes/state.db`           table `sessions`
    prime   `~/.prime/agent/sessions/*.jsonl`  première ligne : l'en-tête

Read-only, and fail-soft per source: a program that is not installed, or a
database locked by a session running right now, costs its own rows and never
the listing.
"""

from __future__ import annotations

from thot.output import local_time

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from thot.fusion.wiring import hermes_home, prime_home

DEFAULT_LIMIT = 30


@dataclass(frozen=True)
class Session:
    """One conversation, however it was recorded."""

    source: str
    id: str
    started_at: str  # ISO 8601, UTC — the only shape the three can share
    where: str = ""
    messages: int = 0
    title: str = ""

    def line(self, *, width: int = 34) -> str:
        when = local_time(self.started_at)
        label = self.title or _shorten(self.where, width) or "—"
        return (f"{self.source:<7} {self.id[:12]:<13} {when}  "
                f"{self.messages:>4} msg  {label}")


def _shorten(path: str, width: int) -> str:
    if len(path) <= width:
        return path
    return "…" + path[-(width - 1):]


def _iso(value) -> str:
    """Whatever the store recorded, as one comparable string.

    Three stores, three shapes: an ISO string, a Unix float, a JavaScript
    timestamp. Sorting them together needs one of them.
    """
    if isinstance(value, str):
        return value
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return ""
    if seconds > 1e11:  # milliseconds, as JavaScript writes them
        seconds /= 1000
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds")


def hermes_state_db() -> Path:
    return hermes_home() / "state.db"


def prime_sessions_dir() -> Path:
    return prime_home() / "sessions"


def read_thot(root: Path | str | None, *, limit: int = DEFAULT_LIMIT) -> list[Session]:
    from thot.state.store import SessionStore

    try:
        state = SessionStore.open()
    except Exception:
        return []
    try:
        found = state.sessions(root, limit=limit)
    except Exception:
        return []
    finally:
        getattr(state, "close", lambda: None)()

    return [
        Session("thot", info.id, _iso(info.started_at), info.root,
                info.message_count, info.title)
        for info in found
    ]


def read_hermes(root: Path | str | None = None, *,
                limit: int = DEFAULT_LIMIT) -> list[Session]:
    path = hermes_state_db()
    if not path.is_file():
        return []
    try:
        # Read-only URI: listing someone's history must never create a
        # journal file next to a database another process is using.
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return []
    try:
        sql = ("SELECT id, started_at, cwd, git_repo_root, message_count, title "
               "FROM sessions")
        params: list = []
        if root is not None:
            sql += " WHERE git_repo_root = ? OR cwd = ?"
            params += [str(root), str(root)]
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        rows = connection.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
    finally:
        connection.close()

    return [
        Session("hermes", str(row[0]), _iso(row[1]),
                str(row[3] or row[2] or ""), int(row[4] or 0), str(row[5] or ""))
        for row in rows
    ]


def read_prime(root: Path | str | None = None, *,
               limit: int = DEFAULT_LIMIT) -> list[Session]:
    directory = prime_sessions_dir()
    if not directory.is_dir():
        return []

    found: list[Session] = []
    for path in sorted(directory.glob("*.jsonl"), reverse=True):
        header, messages = _prime_header(path)
        if header is None:
            continue
        where = str(header.get("cwd") or "")
        if root is not None and where != str(root):
            continue
        found.append(Session("prime", str(header.get("id") or path.stem),
                             _iso(header.get("timestamp")), where, messages))
        if len(found) >= limit:
            break
    return found


# What a *stored* session records. The live `--mode json` stream emits
# `turn_end`; the log on disk does not — counting that marker reported every
# session as empty.
MESSAGE_MARKER = '"type":"message"'


def _prime_header(path: Path) -> tuple[dict | None, int]:
    """The session event, and how many messages the file records.

    Scanned rather than parsed: a long session is megabytes of events, and a
    listing must not pay for the transcript it is not showing. Prime writes
    compact JSON, so the marker is an exact match and not a guess — and it
    does not collide with `custom_message`, which spells its type
    differently.
    """
    header: dict | None = None
    messages = 0
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if MESSAGE_MARKER in line:
                    messages += 1
                    continue
                if header is not None:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get("type") == "session":
                    header = event
    except OSError:
        return None, 0
    return header, messages


def merged(root: Path | str | None = None, *,
           limit: int = DEFAULT_LIMIT) -> list[Session]:
    """The three histories, newest first."""
    found = (read_thot(root, limit=limit)
             + read_hermes(root, limit=limit)
             + read_prime(root, limit=limit))
    found.sort(key=lambda session: session.started_at, reverse=True)
    return found[:limit]
