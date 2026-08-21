"""Fire the hooks from the places that actually know something happened.

A hook declared and never called is worse than no hook: the plugin loads,
reports itself healthy, and silently never runs. These three wrappers exist
so `on_finding`, `post_write` and `on_verdict` have exactly one call site
each, and so every caller gets the same isolation `invoke_hook` provides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from thot.plugins.loader import Plugin, discover, invoke_hook

# Discovery walks the disk; an audit calls these once per finding.
_CACHE: dict[str, list[Plugin]] = {}


def plugins_for(root: Path | str | None) -> list[Plugin]:
    key = str(root or "")
    if key not in _CACHE:
        _CACHE[key] = discover(Path(root)) if root else discover()
    return _CACHE[key]


def forget_plugins() -> None:
    """Drop the cache — for tests, and for a plugin installed mid-session."""
    _CACHE.clear()


def annotate_findings(findings: list, root: Path | str | None = None) -> list:
    """Let plugins annotate each finding before it is reported or stored.

    A plugin returning None means "leave it alone", which is the common case
    and must not cost the finding.
    """
    subscribers = [p for p in plugins_for(root) if "on_finding" in p.callbacks]
    if not subscribers:
        return findings

    annotated = []
    for finding in findings:
        replacements = [
            r for r in invoke_hook(subscribers, "on_finding", finding=finding,
                                   root=root)
            if r is not None
        ]
        annotated.append(replacements[-1] if replacements else finding)
    return annotated


def notify_write(path: str, content: str, root: Path | str | None = None) -> None:
    subscribers = plugins_for(root)
    invoke_hook(subscribers, "post_write", path=path, content=content)


def notify_verdict(verdict: Any, root: Path | str | None = None) -> None:
    subscribers = plugins_for(root)
    invoke_hook(subscribers, "on_verdict", verdict=verdict)
