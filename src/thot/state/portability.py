"""Take a session with you: export to JSON, import it back anywhere.

Ported from Hermes Agent's `hermes_state_portability.py`. The rule kept
from it: an import **never overwrites**. Sessions arrive under fresh ids
with their original recorded, because the most common import is onto a
machine that already has a session with that id — your own.
"""

from __future__ import annotations

import json
from pathlib import Path

from thot.state.store import SessionStore, _now

FORMAT = "thot.sessions"
FORMAT_VERSION = 1


def export_session(store: SessionStore, session_id: str,
                   *, with_ancestry: bool = True) -> dict:
    """One session as a plain dict, its compaction chain included by default.

    Exporting a compacted session without its parents would hand over a
    summary whose evidence is missing — which is exactly the case where
    someone needs the evidence.
    """
    chain = store.ancestry(session_id) if with_ancestry else []
    if not chain:
        info = store.info(session_id)
        if info is None:
            raise KeyError(f"session inconnue : {session_id}")
        chain = [info]

    return {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "exported_at": _now(),
        "sessions": [
            {
                "id": info.id,
                "root": info.root,
                "title": info.title,
                "model": info.model,
                "parent_id": info.parent_id,
                "started_at": info.started_at,
                "ended_at": info.ended_at,
                "messages": [
                    {
                        "seq": turn.seq,
                        "role": turn.role,
                        "content": turn.content,
                        "tool_name": turn.tool_name,
                        "created_at": turn.created_at,
                    }
                    for turn in store.turns(info.id)
                    # The import note is provenance about *this* copy, not
                    # part of the conversation: re-exporting it would make
                    # every round trip grow by one message.
                    if turn.role != "meta"
                ],
            }
            for info in chain
        ],
    }


def write_export(store: SessionStore, session_id: str, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = export_session(store, session_id)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def import_session(store: SessionStore, payload: dict,
                   *, root: str | Path | None = None) -> list[str]:
    """Load an export, returning the new ids in the order they were created.

    Chain links are rewritten to the new ids, so an imported compaction
    chain stays navigable instead of pointing at sessions that are not here.
    """
    if payload.get("format") != FORMAT:
        raise ValueError("ce fichier n'est pas un export Thot")
    version = int(payload.get("version") or 0)
    if version > FORMAT_VERSION:
        raise ValueError(
            f"export en version {version} : cette version de Thot lit jusqu'à "
            f"{FORMAT_VERSION}"
        )

    remap: dict[str, str] = {}
    created: list[str] = []

    for record in payload.get("sessions") or []:
        old_id = str(record.get("id") or "")
        parent = remap.get(str(record.get("parent_id") or ""), "")
        # The recorded moments are carried over rather than restamped: an
        # export is a copy of a conversation, and a conversation that claims
        # to have happened at import time has lost the only thing that made
        # it findable in time.
        new_id = store.start(
            root if root is not None else record.get("root", ""),
            model=str(record.get("model") or ""),
            title=str(record.get("title") or ""),
            parent_id=parent,
            at=str(record.get("started_at") or ""),
        )
        remap[old_id] = new_id
        created.append(new_id)

        for message in record.get("messages") or []:
            store.append(
                new_id,
                str(message.get("role") or "user"),
                str(message.get("content") or ""),
                tool_name=str(message.get("tool_name") or ""),
                at=str(message.get("created_at") or ""),
            )
        if record.get("ended_at"):
            store.end(new_id, at=str(record.get("ended_at")))
        if old_id:
            store.note(new_id, f"importé depuis la session {old_id}", kind="meta")

    return created


def read_import(store: SessionStore, path: Path,
                *, root: str | Path | None = None) -> list[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return import_session(store, payload, root=root)
