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


def _public_http(url: str) -> bool:
    """http(s) only, and only towards an address other people can reach.

    The suppression here used to read "https only by convention", and a
    convention is not a check: `urlopen` reads `file:///etc/passwd` as
    happily as it fetches a page. The scheme check that replaced it was not
    one either — `urlopen` follows redirects, so the site being scanned chose
    the next destination and could name `127.0.0.1`.

    Standard library only, and inline: this script exists to be copied out of
    the tree, and an import of anything else breaks it on the first machine
    it lands on.
    """
    import ipaddress
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(str(url))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except OSError:
        return False
    for entry in resolved:
        try:
            address = ipaddress.ip_address(entry[4][0])
        except (ValueError, IndexError):
            continue
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast
                or address.is_unspecified):
            return False
    return True


def _opener():
    """An opener that re-checks every redirect hop."""
    class _PublicOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not _public_http(newurl):
                raise urllib.error.URLError(f"refused redirect to {newurl!r}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return urllib.request.build_opener(_PublicOnly)


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
    if not _public_http(url):
        return 0, ""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _opener().open(req, timeout=timeout) as resp:  # noqa: S310 - every hop checked
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
