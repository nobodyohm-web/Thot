"""Ask OSV.dev what is known about these exact versions.

Ported from Hermes Agent's `hermes_cli/security_audit.py`: the same two
endpoints, the same batch cap, the same severity mapping, and the same
parallel fetch of details. Free, public, no account, maintained by Google.

Two behaviours are kept because they were paid for upstream:

* **fail open.** A network error means no answer, never a fabricated
  clean bill of health — and never a failed audit. The caller is told the
  lookup did not happen.
* **cache the verdict, not the failure.** From `tools/osv_check.py`, whose
  comment records 779k DNS queries in 16 hours from a retry loop with no
  cache. Advisories do not appear and vanish second to second; connectivity
  does.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{vid}"
BATCH_MAX = 1000        # OSV's documented hard cap per request
TIMEOUT = 20.0
DETAIL_WORKERS = 8
CACHE_TTL = 3600.0

# OSV writes both MODERATE and MEDIUM; they are the same rung.
SEVERITY_ORDER = {
    "UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

# A malware advisory is not a vulnerability rating, it is a verdict.
MALWARE_PREFIX = "MAL-"


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str = ""
    severity: str = "UNKNOWN"
    fixed: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()

    @property
    def malware(self) -> bool:
        return self.id.startswith(MALWARE_PREFIX) or any(
            alias.startswith(MALWARE_PREFIX) for alias in self.aliases
        )

    def rank(self) -> int:
        return 4 if self.malware else SEVERITY_ORDER.get(self.severity, 0)


def severity_from(record: dict) -> str:
    """The database's own rating, preferring the ecosystem's own words."""
    for entry in record.get("database_specific") or {}, :
        label = str((entry or {}).get("severity") or "").upper()
        if label in SEVERITY_ORDER:
            return label
    for affected in record.get("affected") or []:
        label = str((affected.get("database_specific") or {})
                    .get("severity") or "").upper()
        if label in SEVERITY_ORDER:
            return label
    # CVSS vectors carry a score, not a word; map the score back to a rung.
    for entry in record.get("severity") or []:
        score = str(entry.get("score") or "")
        if "/" not in score:
            try:
                value = float(score)
            except ValueError:
                continue
            return ("CRITICAL" if value >= 9 else "HIGH" if value >= 7
                    else "MEDIUM" if value >= 4 else "LOW")
    return "UNKNOWN"


def fixed_versions(record: dict) -> tuple[str, ...]:
    found: list[str] = []
    for affected in record.get("affected") or []:
        for span in affected.get("ranges") or []:
            for event in span.get("events") or []:
                if event.get("fixed"):
                    found.append(str(event["fixed"]))
    return tuple(dict.fromkeys(found))


@dataclass
class OsvClient:
    transport: object | None = None
    last_error: str = ""
    _client: httpx.Client | None = field(default=None, init=False, repr=False)
    _cache: dict = field(default_factory=dict, init=False, repr=False)

    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=TIMEOUT, transport=self.transport,
                headers={"Content-Type": "application/json"},
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # -- lookups ---------------------------------------------------------

    def query(self, components) -> dict:
        """{component: [advisory id, …]} for everything OSV knows about.

        Returns an empty mapping and sets `last_error` when the lookup did
        not happen, so "nothing found" and "nothing asked" stay distinct.
        """
        components = list(components)
        answers: dict = {}
        self.last_error = ""

        for start in range(0, len(components), BATCH_MAX):
            chunk = components[start : start + BATCH_MAX]
            payload = {"queries": [
                {"package": {"name": c.name, "ecosystem": c.ecosystem},
                 "version": c.version}
                for c in chunk
            ]}
            try:
                response = self.client().post(BATCH_URL, json=payload)
                response.raise_for_status()
                results = response.json().get("results") or []
            except (httpx.HTTPError, ValueError) as exc:
                self.last_error = str(exc) or exc.__class__.__name__
                return {}

            for component, result in zip(chunk, results):
                ids = [str(v.get("id")) for v in (result or {}).get("vulns") or []
                       if v.get("id")]
                if ids:
                    answers[component] = ids
        return answers

    def details(self, ids) -> dict[str, Advisory]:
        """Fetch each advisory once, in parallel, cached by id."""
        wanted = [str(i) for i in dict.fromkeys(ids)]
        now = time.monotonic()
        found: dict[str, Advisory] = {}
        missing: list[str] = []

        for identifier in wanted:
            entry = self._cache.get(identifier)
            if entry and entry[0] > now:
                found[identifier] = entry[1]
            else:
                missing.append(identifier)

        if missing:
            with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
                for advisory in pool.map(self._one, missing):
                    if advisory is not None:
                        found[advisory.id] = advisory
                        # Only successes are cached: a cached failure could
                        # hide a real advisory once the network returns.
                        self._cache[advisory.id] = (now + CACHE_TTL, advisory)
        return found

    def _one(self, identifier: str) -> Advisory | None:
        try:
            response = self.client().get(VULN_URL.format(vid=identifier))
            response.raise_for_status()
            record = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.last_error = str(exc) or exc.__class__.__name__
            # An id with no detail is still an id worth reporting.
            return Advisory(id=identifier)
        return Advisory(
            id=str(record.get("id") or identifier),
            summary=str(record.get("summary") or record.get("details") or "")
            .strip().split("\n")[0][:300],
            severity=severity_from(record),
            fixed=fixed_versions(record),
            aliases=tuple(str(a) for a in record.get("aliases") or []),
        )
