"""Cutting output down, from the right end.

Ported from Prime Agent's `core/tools/truncate.ts`, whose two decisions
are the whole point:

* **two independent limits**, lines and bytes, whichever is hit first. A
  file of a million short lines and a file with one enormous line are both
  unreadable, and one limit only catches one of them.
* **never a partial line** — except the single case where one line is
  itself over the byte limit, which is reported rather than hidden.

And the reason this replaces what Thot did: Thot truncated from the head.
The useful part of a failing test run is at the **end** — the traceback,
the assertion, the summary line. Keeping the collection banner and
dropping the failure is precisely backwards, and it is what a model was
being handed to reason about.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_MAX_LINES = 2000
DEFAULT_MAX_BYTES = 50 * 1024

UNITS = ("o", "ko", "Mo", "Go")


def format_size(size: int) -> str:
    value = float(size)
    for unit in UNITS:
        if value < 1024 or unit == UNITS[-1]:
            return f"{value:.0f} {unit}" if unit == "o" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} o"


@dataclass(frozen=True)
class Truncation:
    content: str
    truncated: bool = False
    by: str = ""              # "lines" | "bytes" | ""
    total_lines: int = 0
    total_bytes: int = 0
    kept_lines: int = 0
    partial_line: bool = False

    def note(self, *, tail: bool = False) -> str:
        """The sentence appended to the output, saying exactly what was lost."""
        if not self.truncated:
            return ""
        dropped = self.total_lines - self.kept_lines
        where = "au début" if tail else "à la fin"
        detail = (f"{dropped} ligne(s) coupées {where}"
                  if dropped > 0 else f"coupé {where}")
        extra = " · une ligne dépassait la limite à elle seule" \
            if self.partial_line else ""
        return (f"\n… {detail} sur {self.total_lines} "
                f"({format_size(self.total_bytes)}){extra}")

    def rendered(self, *, tail: bool = False) -> str:
        return self.content + self.note(tail=tail)


def _measure(text: str) -> tuple[list[str], int, int]:
    lines = text.split("\n")
    return lines, len(lines), len(text.encode("utf-8"))


def _clip_bytes(text: str, limit: int, *, from_end: bool) -> str:
    """Cut a single oversized line on a character boundary, never mid-UTF-8."""
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    piece = raw[-limit:] if from_end else raw[:limit]
    return piece.decode("utf-8", errors="ignore")


def truncate_head(text: str, *, max_lines: int = DEFAULT_MAX_LINES,
                  max_bytes: int = DEFAULT_MAX_BYTES) -> Truncation:
    """Keep the beginning. For a file, whose top is what you asked for."""
    lines, total_lines, total_bytes = _measure(text)
    if total_lines <= max_lines and total_bytes <= max_bytes:
        return Truncation(text, total_lines=total_lines, total_bytes=total_bytes,
                          kept_lines=total_lines)

    kept: list[str] = []
    used = 0
    by = "lines"
    partial = False
    for line in lines[:max_lines]:
        cost = len(line.encode("utf-8")) + (1 if kept else 0)
        if used + cost > max_bytes:
            by = "bytes"
            if not kept:
                kept.append(_clip_bytes(line, max_bytes, from_end=False))
                partial = True
            break
        kept.append(line)
        used += cost

    return Truncation("\n".join(kept), True, by, total_lines, total_bytes,
                      len(kept), partial)


def truncate_tail(text: str, *, max_lines: int = DEFAULT_MAX_LINES,
                  max_bytes: int = DEFAULT_MAX_BYTES) -> Truncation:
    """Keep the end. For a command, whose failure is at the bottom."""
    lines, total_lines, total_bytes = _measure(text)
    if total_lines <= max_lines and total_bytes <= max_bytes:
        return Truncation(text, total_lines=total_lines, total_bytes=total_bytes,
                          kept_lines=total_lines)

    kept: list[str] = []
    used = 0
    by = "lines"
    partial = False
    for line in reversed(lines):
        if len(kept) >= max_lines:
            break
        cost = len(line.encode("utf-8")) + (1 if kept else 0)
        if used + cost > max_bytes:
            by = "bytes"
            if not kept:
                kept.append(_clip_bytes(line, max_bytes, from_end=True))
                partial = True
            break
        kept.insert(0, line)
        used += cost

    return Truncation("\n".join(kept), True, by, total_lines, total_bytes,
                      len(kept), partial)


def local_time(stamp: str, *, zone=None, seconds: bool = False) -> str:
    """A stored timestamp as the reader's own clock shows it.

    Two conventions reach here and only one of them says so. SQLite's
    `datetime('now')` writes UTC with no marker at all — a run started at
    02:36 is filed as 00:36 and was printed that way — while `decided_at`
    writes an ISO string carrying its offset. A stamp that names no zone is
    read as UTC, which is what both of them mean.

    Anything unparseable comes back untouched: a timestamp nobody can read
    is still worth more on screen than an empty column.
    """
    from datetime import datetime, timezone

    text = (stamp or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return stamp
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    shape = "%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M"
    return parsed.astimezone(zone).strftime(shape)
