"""What has been tried and did not settle.

Candidates are selected worst-first, which is right — until one of them
cannot be settled at all. A finding whose agent times out, or whose model
will not commit, keeps its severity, so it is picked first again on the next
round, and the next, and the one after that. Measured here on a single
finding in a 1 660-line file: four attempts across three runs, three of them
paying for the same wall.

So failures are counted. Not as verdicts — nothing was decided, and pretending
otherwise would silence the finding — but as a note that this one has already
cost more than it returned. After two failures it goes to the back of the
queue: still eligible, never first, so a large budget still reaches it and a
small one spends itself on candidates that can actually be judged.

One success clears the count. A wall that was a busy afternoon or an expired
subscription should not follow a finding for ever.
"""

from __future__ import annotations

import json
from pathlib import Path

from thot.paths import ensure_home, home

FILENAME = "attempts.json"

# Two, not one: a single failure is usually the world, not the finding.
DEMOTE_AFTER = 2


def ledger_path() -> Path:
    return home() / FILENAME


def load() -> dict[str, int]:
    try:
        data = json.loads(ledger_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): int(v) for k, v in data.items() if isinstance(v, int)}


def _save(data: dict[str, int]) -> None:
    ensure_home()
    ledger_path().write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )


def record_failure(finding_id: str) -> int:
    """Count one failed attempt. Returns the running total."""
    data = load()
    data[finding_id] = data.get(finding_id, 0) + 1
    _save(data)
    return data[finding_id]


def clear(finding_id: str) -> None:
    """Forget the failures of a finding that has now been settled."""
    data = load()
    if data.pop(finding_id, None) is not None:
        _save(data)


def demoted(threshold: int = DEMOTE_AFTER) -> set[str]:
    """The findings that have already cost more than they returned."""
    return {key for key, count in load().items() if count >= threshold}


def forget_all() -> None:
    """Drop the ledger — for tests, and for a fresh start."""
    try:
        ledger_path().unlink()
    except OSError:
        pass
