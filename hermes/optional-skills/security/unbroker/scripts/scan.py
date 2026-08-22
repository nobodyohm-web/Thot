"""Stdlib fetch helper for simple url_pattern brokers (osint-style).

For JS-rendered or anti-bot pages the agent should use the `web_extract` or
`browser_navigate` tools (and the `scrapling` skill for stealth/Cloudflare).
This helper only covers plain static pages and is intentionally network-light so
it can be mocked in tests.
"""
from __future__ import annotations

import urllib.error
import urllib.request

USER_AGENT = "Mozilla/5.0 (compatible; unbroker/1.0; data opt-out)"


def fetch(url: str, timeout: int = 20) -> tuple[int, str]:
    # The suppression here used to read "https only by convention", and a
    # convention is not a check: `urlopen` reads `file:///etc/passwd` as
    # happily as it fetches a page, and this function is a helper in a script
    # people copy into their own work — where the URL will come from wherever
    # they get theirs.
    #
    # Enforced inline rather than through a shared guard: this script has to
    # keep working when it is copied out of the tree, which is the whole
    # point of the library it lives in.
    if not str(url).lower().startswith(("http://", "https://")):
        return 0, ""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme enforced above
            charset = resp.headers.get_content_charset() or "utf-8"
            return getattr(resp, "status", 200), resp.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, ""


def looks_listed(html: str, match_signal: str | None) -> bool:
    """Naive confirmation heuristic for static pages: does the match signal appear?"""
    if not html or not match_signal:
        return False
    return match_signal.lower() in html.lower()
