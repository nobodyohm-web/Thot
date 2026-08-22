"""Thot does not follow a redirect it was not asked to follow.

It does not today, and by luck rather than by decision: every outbound call
goes through `httpx`, whose default is `follow_redirects=False`, where
`requests` and `urllib` both follow by default. Swap the library — or pass
the flag once for a provider that needs it — and the property disappears
without a word.

It is worth an explicit test because the shape it protects against cost
seven fixes in one day, in the vendored tree next door: a URL validated once
and then handed to a client that quietly went somewhere else. Thot's own
outbound URLs come from the operator's configuration rather than from a
model, which makes it a smaller risk and not a different one.
"""

from __future__ import annotations

import re
from pathlib import Path

SOURCE = Path(__file__).parent.parent / "src" / "thot"


def _python_files():
    return sorted(SOURCE.rglob("*.py"))


def test_no_module_turns_redirect_following_on():
    offenders = []
    for path in _python_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"(follow_redirects|allow_redirects)\s*=\s*True", line):
                offenders.append(f"{path.name}:{number}")
    assert not offenders, (
        "une redirection suivie sans contrôle : " + ", ".join(offenders)
    )


def test_the_outbound_client_is_the_one_that_does_not_follow():
    """`requests` and `urllib` follow by default; `httpx` does not.

    If Thot ever reaches for one of the other two, this test is the place
    that says why it must then check each hop itself.
    """
    import httpx
    import inspect

    default = inspect.signature(httpx.Client.__init__).parameters[
        "follow_redirects"
    ].default
    assert default is False, (
        "httpx a changé de défaut : Thot doit désormais contrôler chaque saut"
    )

    reaching = []
    for path in _python_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or "patterns=" in stripped:
                continue
            if re.search(r"^\s*(import requests|from requests|"
                         r"import urllib\.request|from urllib\.request)", line):
                reaching.append(f"{path.name}:{number}")
    assert not reaching, (
        "client qui suit les redirections par défaut : " + ", ".join(reaching)
        + " — contrôler chaque saut, comme hermes/utils.py"
    )
