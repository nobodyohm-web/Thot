"""Verdicts a team shares through git.

The most useful backend for an audit tool, and the one neither source
program had: a plain JSON file at `<repo>/.thot/verdicts.json`, committed
with the code it judges.

Why that beats a server for the common case — the decision "this
`os.system` call is safe because the argument is a literal" is a fact about
*this revision of this code*. It travels with the code, it is reviewed in
the pull request that changes the code, and a new clone has it before it
has network access.

The file is written sorted and stable, because a file whose diff is noise
is a file nobody reviews.
"""

from __future__ import annotations

import json
from pathlib import Path

from thot.memory.base import Decision, Verdict

FILENAME = "verdicts.json"
FORMAT = "thot.verdicts"
FORMAT_VERSION = 1

_FIELDS = ("finding_id", "decision", "reason", "author", "rule", "path",
           "symbol", "ast_hash", "decided_at")


def repo_path(root: Path | str) -> Path:
    return Path(root) / ".thot" / FILENAME


def _to_dict(verdict: Verdict) -> dict:
    data = {field: getattr(verdict, field) for field in _FIELDS}
    data["decision"] = verdict.decision.value
    return data


def _from_dict(data: dict) -> Verdict | None:
    decision = Decision.parse(str(data.get("decision") or ""))
    if decision is None or not data.get("finding_id"):
        return None
    return Verdict(
        finding_id=str(data["finding_id"]),
        decision=decision,
        reason=str(data.get("reason") or ""),
        author=str(data.get("author") or ""),
        rule=str(data.get("rule") or ""),
        path=str(data.get("path") or ""),
        symbol=str(data.get("symbol") or ""),
        ast_hash=str(data.get("ast_hash") or ""),
        decided_at=str(data.get("decided_at") or ""),
    )


class JsonMemory:
    """Verdicts in one file. Read on open, written on every change."""

    name = "json"

    def __init__(self, path: Path, verdicts: dict[str, Verdict]) -> None:
        self.path = Path(path)
        self._verdicts = verdicts

    @classmethod
    def open(cls, path: Path | str) -> "JsonMemory":
        path = Path(path)
        verdicts: dict[str, Verdict] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for entry in (data.get("verdicts") or []) if isinstance(data, dict) else []:
            if isinstance(entry, dict):
                verdict = _from_dict(entry)
                if verdict is not None:
                    verdicts[verdict.finding_id] = verdict
        return cls(path, verdicts)

    @classmethod
    def for_repo(cls, root: Path | str) -> "JsonMemory":
        return cls.open(repo_path(root))

    def is_available(self) -> bool:
        # A file that does not exist yet is still a usable destination; only
        # a directory that cannot be created makes this backend unavailable.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        return True

    def exists(self) -> bool:
        return self.path.is_file()

    def _flush(self) -> None:
        payload = {
            "format": FORMAT,
            "version": FORMAT_VERSION,
            "verdicts": [
                _to_dict(self._verdicts[key]) for key in sorted(self._verdicts)
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def remember(self, verdict: Verdict) -> None:
        self._verdicts[verdict.finding_id] = verdict
        self._flush()

    def recall(self, finding_id: str) -> Verdict | None:
        return self._verdicts.get(finding_id)

    def all_verdicts(self) -> list[Verdict]:
        return [self._verdicts[key] for key in sorted(self._verdicts)]

    def forget(self, finding_id: str) -> bool:
        if finding_id not in self._verdicts:
            return False
        del self._verdicts[finding_id]
        self._flush()
        return True

    def close(self) -> None:
        return None
