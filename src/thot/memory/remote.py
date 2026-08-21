"""Verdicts held by something other than this machine.

Two backends, both HTTP, both with an injectable transport so their
contract is tested rather than trusted:

* `HttpMemory` speaks a four-route contract a team can implement in an
  afternoon — the shape Thot would want from a shared verdict server;
* `Mem0Memory` speaks the self-hosted mem0 contract exactly as Hermes
  Agent's own client does (`X-API-Key`, `POST /memories`, `POST /search`),
  so a mem0 server already running for Hermes serves Thot too.

Both fail soft. A verdict store that is unreachable must cost the memory of
past decisions, never the audit — an auditor that stops working when the
network does is an auditor nobody keeps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

from thot.memory.base import Decision, Verdict
from thot.memory.jsonfile import _from_dict, _to_dict

TIMEOUT = 15.0


def check_credential(label: str, value: str) -> str:
    """Refuse a header value HTTP cannot carry, loudly.

    Found by a test that pasted an accented API key: httpx encodes headers
    as ASCII, the UnicodeEncodeError is a ValueError, and the `except
    (HTTPError, ValueError)` that keeps this backend from breaking an audit
    swallowed every single call. The store stayed silent and empty forever.

    Fail-soft must never mean fail-silent about the thing you configured.
    """
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(
            f"{label} contient un caractère non ASCII — une en-tête HTTP ne "
            f"peut pas le transporter. Vérifie ce qui a été collé."
        ) from None
    return value

# The user_id every Thot verdict is filed under in a mem0 server, so a
# shared instance can also hold whatever else the team keeps there.
MEM0_USER = "thot-verdicts"


@dataclass
class HttpMemory:
    """A shared verdict server.

    The contract, in full:

        GET    {base}/verdicts            -> {"verdicts": [ … ]}
        GET    {base}/verdicts/{id}       -> verdict, or 404
        PUT    {base}/verdicts/{id}       <- verdict
        DELETE {base}/verdicts/{id}
    """

    base_url: str
    token: str = ""
    name: str = field(default="http", init=False)
    transport: object | None = None
    last_error: str = field(default="", init=False)
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def client(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = (
                    f"Bearer {check_credential('Le jeton', self.token)}"
                )
            self._client = httpx.Client(
                base_url=self.base_url.rstrip("/"), headers=headers,
                timeout=TIMEOUT, transport=self.transport,
            )
        return self._client

    def _json(self, method: str, path: str, **kwargs):
        response = self.client().request(method, path, **kwargs)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        self.last_error = ""
        return response.json() if response.content else {}

    def _failed(self, exc: Exception) -> None:
        self.last_error = str(exc) or exc.__class__.__name__

    def is_available(self) -> bool:
        try:
            self._json("GET", "/verdicts")
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return False
        self.last_error = ""
        return True

    def remember(self, verdict: Verdict) -> None:
        try:
            self._json("PUT", f"/verdicts/{verdict.finding_id}",
                       json=_to_dict(verdict))
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)

    def recall(self, finding_id: str) -> Verdict | None:
        try:
            data = self._json("GET", f"/verdicts/{finding_id}")
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return None
        return _from_dict(data) if isinstance(data, dict) else None

    def all_verdicts(self) -> list[Verdict]:
        try:
            data = self._json("GET", "/verdicts") or {}
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return []
        found = [_from_dict(entry) for entry in (data.get("verdicts") or [])
                 if isinstance(entry, dict)]
        return [verdict for verdict in found if verdict is not None]

    def forget(self, finding_id: str) -> bool:
        try:
            return self._json("DELETE", f"/verdicts/{finding_id}") is not None
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return False

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


@dataclass
class Mem0Memory:
    """A self-hosted mem0 server, spoken the way Hermes speaks to it.

    A verdict is stored as one memory whose text is the sentence a human
    would write, with the machine-readable fields in metadata. `infer` is
    off on purpose: mem0's inference rewrites what it is given, and a
    verdict that gets paraphrased is a verdict that stops matching the
    finding it was about.
    """

    host: str
    api_key: str = ""
    name: str = field(default="mem0", init=False)
    transport: object | None = None
    last_error: str = field(default="", init=False)
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def client(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-API-Key"] = check_credential(
                    "La clé d'API", self.api_key
                )
            self._client = httpx.Client(
                base_url=self.host.rstrip("/"), headers=headers,
                timeout=TIMEOUT, transport=self.transport,
            )
        return self._client

    def _json(self, method: str, path: str, **kwargs):
        response = self.client().request(method, path, **kwargs)
        response.raise_for_status()
        self.last_error = ""
        return response.json() if response.content else {}

    def _failed(self, exc: Exception) -> None:
        self.last_error = str(exc) or exc.__class__.__name__

    @staticmethod
    def _sentence(verdict: Verdict) -> str:
        where = f"{verdict.path}" + (f" ({verdict.symbol})" if verdict.symbol else "")
        return (f"{verdict.rule} à {where} — {verdict.decision.value}. "
                f"{verdict.reason}").strip()

    def is_available(self) -> bool:
        try:
            self._json("POST", "/search",
                       json={"query": "thot", "top_k": 1,
                             "filters": {"user_id": MEM0_USER}})
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return False
        self.last_error = ""
        return True

    def remember(self, verdict: Verdict) -> None:
        try:
            self._json(
                "POST", "/memories",
                json={
                    "messages": [{"role": "user",
                                  "content": self._sentence(verdict)}],
                    "user_id": MEM0_USER,
                    "agent_id": "thot",
                    "infer": False,
                    "metadata": {"thot_verdict": _to_dict(verdict)},
                },
            )
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)

    def _harvest(self, payload) -> list[Verdict]:
        """Pull our own metadata back out, whatever shape the server wraps it in."""
        rows = payload
        if isinstance(payload, dict):
            rows = payload.get("results") or payload.get("memories") or []
        found = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            raw = (row.get("metadata") or {}).get("thot_verdict")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except ValueError:
                    continue
            if isinstance(raw, dict):
                verdict = _from_dict(raw)
                if verdict is not None:
                    found.append(verdict)
        return found

    def recall(self, finding_id: str) -> Verdict | None:
        try:
            payload = self._json(
                "POST", "/search",
                json={"query": finding_id, "top_k": 20,
                      "filters": {"user_id": MEM0_USER}},
            )
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return None
        for verdict in self._harvest(payload):
            if verdict.finding_id == finding_id:
                return verdict
        return None

    def all_verdicts(self) -> list[Verdict]:
        try:
            payload = self._json("GET", "/memories",
                                 params={"user_id": MEM0_USER})
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return []
        return sorted(self._harvest(payload), key=lambda v: v.finding_id)

    def forget(self, finding_id: str) -> bool:
        """mem0 deletes by its own id, so the memory has to be found first."""
        try:
            payload = self._json(
                "POST", "/search",
                json={"query": finding_id, "top_k": 20,
                      "filters": {"user_id": MEM0_USER}},
            )
        except (httpx.HTTPError, ValueError) as exc:
            self._failed(exc)
            return False

        rows = payload.get("results") if isinstance(payload, dict) else payload
        for row in rows if isinstance(rows, list) else []:
            raw = (row.get("metadata") or {}).get("thot_verdict") or {}
            if isinstance(raw, dict) and raw.get("finding_id") == finding_id:
                try:
                    self._json("DELETE", f"/memories/{row.get('id')}")
                    return True
                except (httpx.HTTPError, ValueError):
                    return False
        return False

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
