"""What Thot has learned about a codebase, kept between sessions.

Ported from Prime Agent's `prime-agent-runtime/src/rlm/harness.py`, which
is already Python — so this is a translation of purpose rather than of
language. Prime calls the act *refinement*: when the agent notices a
repeated failure, a reusable tactic, or a policy it should hold to, it
writes an entry rather than rediscovering it next week.

For an audit tool the entries are facts about *this* repository that no
static analysis will ever derive:

    « `team.shell.run` échappe ses arguments — les findings dessus sont faux »
    « `generated/` est régénéré à chaque build, ne rien y corriger »
    « les handlers Flask sont enregistrés par décorateur, la teinte les rate »

Two scopes, as in Prime: `local` for this repository, `global` for what
you know everywhere. Local entries live in `<repo>/.thot/harness.json` so
a team shares them the way it shares verdicts — reviewed, in the pull
request that made them true.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

FILENAME = "harness.json"
FORMAT = "thot.harness"
FORMAT_VERSION = 1

# Prime's kinds, minus the ones that only make sense with sub-agent records.
KINDS = ("memory", "policy", "tactic")

# Long enough to be a fact, short enough that thirty fit in a briefing.
MAX_CONTENT = 600
BRIEF_ENTRIES = 12


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entry:
    """One thing learned. `kind` decides how it reads in the briefing."""

    id: str
    kind: str
    title: str
    content: str
    scope: str = "local"
    source: str = "agent"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def line(self) -> str:
        return f"- {self.title} : {self.content}"


def _valid(kind: str) -> str:
    key = (kind or "memory").strip().lower()
    return key if key in KINDS else "memory"


class Harness:
    """Entries for one repository, plus whatever is known everywhere."""

    def __init__(self, local: Path, glob: Path) -> None:
        self.local_path = Path(local)
        self.global_path = Path(glob)
        self._local = self._read(self.local_path)
        self._global = self._read(self.global_path)

    @classmethod
    def open(cls, root: Path | str) -> "Harness":
        from thot.paths import home

        return cls(Path(root) / ".thot" / FILENAME, home() / FILENAME)

    # -- storage ---------------------------------------------------------

    @staticmethod
    def _read(path: Path) -> dict[str, Entry]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        found: dict[str, Entry] = {}
        for record in (data.get("entries") or []) if isinstance(data, dict) else []:
            if not isinstance(record, dict) or not record.get("id"):
                continue
            try:
                found[str(record["id"])] = Entry(
                    id=str(record["id"]),
                    kind=_valid(str(record.get("kind") or "")),
                    title=str(record.get("title") or ""),
                    content=str(record.get("content") or ""),
                    scope=str(record.get("scope") or "local"),
                    source=str(record.get("source") or "agent"),
                    created_at=str(record.get("created_at") or _now()),
                    updated_at=str(record.get("updated_at") or _now()),
                )
            except (TypeError, ValueError):
                continue
        return found

    def _write(self, path: Path, entries: dict[str, Entry]) -> None:
        payload = {
            "format": FORMAT,
            "version": FORMAT_VERSION,
            "entries": [asdict(entries[key]) for key in sorted(entries)],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    # -- reading ---------------------------------------------------------

    def all(self) -> list[Entry]:
        """Local first: what this repository knows outranks what you assume."""
        merged = {**self._global, **self._local}
        return sorted(merged.values(), key=lambda e: (e.kind, e.title))

    def get(self, entry_id: str) -> Entry | None:
        return self._local.get(entry_id) or self._global.get(entry_id)

    def brief(self, *, limit: int = BRIEF_ENTRIES) -> str:
        """The block that rides into the system prompt, or nothing at all."""
        entries = self.all()[:limit]
        if not entries:
            return ""
        lines = ["Ce que tu sais déjà sur ce dépôt :"]
        lines += [entry.line() for entry in entries]
        return "\n".join(lines)

    # -- writing ---------------------------------------------------------

    def remember(self, *, title: str, content: str, kind: str = "memory",
                 scope: str = "local", source: str = "agent") -> Entry:
        title = " ".join((title or "").split())[:120]
        content = " ".join((content or "").split())[:MAX_CONTENT]
        if not title or not content:
            raise ValueError("un titre et un contenu sont obligatoires")

        store = self._global if scope == "global" else self._local
        # Same title, same subject: update rather than accumulate near
        # duplicates a briefing would then have to carry all of.
        existing = next((e for e in store.values()
                         if e.title.lower() == title.lower()), None)
        if existing is not None:
            # `updated_at` means "last updated". Re-saving the identical note
            # is not an update, and this file is tracked by git — the only one
            # in `.thot/` that is — so bumping the stamp put a diff line in a
            # committed file for a change nobody made. Same family as the
            # verdicts store, same remedy.
            if existing.content == content and existing.kind == _valid(kind):
                return existing
            existing.content = content
            existing.kind = _valid(kind)
            existing.updated_at = _now()
            entry = existing
        else:
            entry = Entry(id=uuid.uuid4().hex[:12], kind=_valid(kind),
                          title=title, content=content, scope=scope,
                          source=source)
            store[entry.id] = entry

        self._write(self.global_path if scope == "global" else self.local_path,
                    store)
        return entry

    def forget(self, entry_id: str) -> bool:
        for store, path in ((self._local, self.local_path),
                            (self._global, self.global_path)):
            if entry_id in store:
                del store[entry_id]
                self._write(path, store)
                return True
        return False
