"""One JSONL line per thing Thot decided, on this machine only.

Hermes ships observability plugins that post to Langfuse or Datadog. The
useful half of that idea does not need a vendor: what a user actually wants
is to be able to answer "what did this tool do to my repository, and when",
months later, without having sent their code anywhere.

Append-only, one line per event, `~/.thot/journal.jsonl`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

FILENAME = "journal.jsonl"

# A write hook fires on every save; the content itself belongs in git, not
# here. Only its shape is recorded.
MAX_REASON = 400


def _append(event: dict) -> None:
    """Never raise: a journal that breaks an audit is worse than no journal."""
    from thot.paths import home

    event["at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        directory = home()
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / FILENAME).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def post_audit(*, result=None, root=None, **_: object) -> None:
    if result is None:
        return
    counts: dict[str, int] = {}
    for finding in result.findings:
        key = finding.severity.value
        counts[key] = counts.get(key, 0) + 1
    _append({
        "event": "audit",
        "root": str(root or ""),
        "findings": len(result.findings),
        "par_gravité": counts,
        "moteur": getattr(result, "engine", None),
        "secondes": round(getattr(result, "elapsed", 0.0), 2),
    })


def on_verdict(*, verdict=None, **_: object) -> None:
    if verdict is None:
        return
    _append({
        "event": "verdict",
        "finding": getattr(verdict, "finding_id", ""),
        "règle": getattr(verdict, "rule", ""),
        "chemin": getattr(verdict, "path", ""),
        "décision": getattr(getattr(verdict, "decision", None), "value", ""),
        "auteur": getattr(verdict, "author", ""),
        "raison": str(getattr(verdict, "reason", ""))[:MAX_REASON],
    })


def post_write(*, path: str = "", content: str = "", **_: object) -> None:
    _append({
        "event": "écriture",
        "chemin": str(path),
        "lignes": content.count("\n") + 1 if content else 0,
        "octets": len(content.encode("utf-8")),
    })
