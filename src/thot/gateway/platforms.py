"""The channels themselves. Five, each one file's worth of HTTP.

Ported from Hermes Agent's `plugins/platforms/*` adapters, reduced to what
`send` and `poll` need. Only Telegram is two-way here, and for a reason
worth stating: it offers long polling, so a laptop behind a NAT can receive
commands without exposing a port. Discord, Slack and mail would need a
public endpoint or an SDK to receive, and a gateway that asks you to open a
port to the internet is a gateway that audits you back.
"""

from __future__ import annotations

import json
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage

import httpx

from thot.gateway.base import Delivery, Incoming, truncate

TIMEOUT = 20.0
# Long polling: the request is held open by Telegram until something arrives.
# Shorter than the HTTP timeout, so a quiet minute is a clean return.
POLL_SECONDS = 10


def _post(url: str, *, json_body: dict | None = None, content: bytes | None = None,
          headers: dict | None = None) -> tuple[bool, str]:
    """One HTTP call, with every failure turned into a sentence."""
    try:
        response = httpx.post(url, json=json_body, content=content,
                              headers=headers, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        return False, f"réseau : {exc}"
    if response.status_code >= 400:
        detail = (response.text or "").strip().replace("\n", " ")[:160]
        return False, f"HTTP {response.status_code} — {detail}"
    return True, ""


@dataclass
class Telegram:
    """Two-way. The only channel that can take a command back."""

    token: str = ""
    chat_id: str = ""
    name: str = field(default="telegram", init=False)
    _offset: int = field(default=0, init=False)

    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self.token}/{method}"

    def send(self, text: str, *, channel: str = "") -> Delivery:
        if not self.configured():
            return Delivery(self.name, False, "token ou chat_id manquant")
        ok, detail = _post(
            self._url("sendMessage"),
            json_body={
                "chat_id": channel or self.chat_id,
                "text": truncate(text),
                "disable_web_page_preview": True,
            },
        )
        return Delivery(self.name, ok, detail)

    def poll(self) -> list[Incoming]:
        if not self.configured():
            return []
        params = {"timeout": POLL_SECONDS, "allowed_updates": ["message"]}
        if self._offset:
            params["offset"] = self._offset
        try:
            response = httpx.get(self._url("getUpdates"), params=params,
                                 timeout=TIMEOUT + POLL_SECONDS)
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            return []
        if not payload.get("ok"):
            return []

        received: list[Incoming] = []
        for update in payload.get("result") or []:
            # Acknowledge every update, including ones we ignore: an update
            # that is never acknowledged is replayed forever.
            self._offset = max(self._offset, int(update.get("update_id", 0)) + 1)
            message = update.get("message") or {}
            text = (message.get("text") or "").strip()
            if not text:
                continue
            sender = message.get("from") or {}
            received.append(Incoming(
                text=text,
                sender=str(sender.get("id") or ""),
                channel=str((message.get("chat") or {}).get("id") or ""),
                sender_name=str(sender.get("username") or sender.get("first_name") or ""),
            ))
        return received


@dataclass
class Discord:
    """Outbound only: receiving would mean a gateway socket or a public URL."""

    webhook: str = ""
    name: str = field(default="discord", init=False)

    def configured(self) -> bool:
        return bool(self.webhook)

    def send(self, text: str, *, channel: str = "") -> Delivery:
        if not self.configured():
            return Delivery(self.name, False, "webhook manquant")
        # Discord's own cap is 2000; truncate() already reports what it cut.
        ok, detail = _post(self.webhook, json_body={"content": truncate(text, 1900)})
        return Delivery(self.name, ok, detail)

    def poll(self) -> list[Incoming]:
        return []


@dataclass
class Slack:
    """Outbound only, same reason as Discord."""

    webhook: str = ""
    name: str = field(default="slack", init=False)

    def configured(self) -> bool:
        return bool(self.webhook)

    def send(self, text: str, *, channel: str = "") -> Delivery:
        if not self.configured():
            return Delivery(self.name, False, "webhook manquant")
        ok, detail = _post(self.webhook, json_body={"text": truncate(text)})
        return Delivery(self.name, ok, detail)

    def poll(self) -> list[Incoming]:
        return []


@dataclass
class Ntfy:
    """Push notifications, no account, self-hostable.

    ntfy has no identity primitive: anyone who knows the topic can publish
    to it. Hermes says so in its adapter and so does Thot — this channel
    reports, it never commands.
    """

    topic: str = ""
    server: str = "https://ntfy.sh"
    token: str = ""
    name: str = field(default="ntfy", init=False)

    def configured(self) -> bool:
        return bool(self.topic)

    def send(self, text: str, *, channel: str = "") -> Delivery:
        if not self.configured():
            return Delivery(self.name, False, "topic manquant")
        headers = {"Title": "Thot", "Markdown": "yes"}
        if self.token:
            headers["Authorization"] = (
                self.token if self.token.lower().startswith(("bearer ", "basic "))
                else f"Bearer {self.token}"
            )
        url = f"{self.server.rstrip('/')}/{channel or self.topic}"
        ok, detail = _post(url, content=truncate(text).encode("utf-8"),
                           headers=headers)
        return Delivery(self.name, ok, detail)

    def poll(self) -> list[Incoming]:
        return []


@dataclass
class Mail:
    """SMTP. For the nightly report you want in an inbox, not a chat."""

    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    to: str = ""
    name: str = field(default="mail", init=False)

    def configured(self) -> bool:
        return bool(self.host and self.to)

    def send(self, text: str, *, channel: str = "") -> Delivery:
        if not self.configured():
            return Delivery(self.name, False, "host ou destinataire manquant")

        message = EmailMessage()
        first = text.strip().splitlines()[0] if text.strip() else "Thot"
        message["Subject"] = first[:120]
        message["From"] = self.user or f"thot@{self.host}"
        message["To"] = channel or self.to
        message.set_content(text)

        try:
            port = int(self.port or 587)
            if port == 465:
                server = smtplib.SMTP_SSL(self.host, port, timeout=TIMEOUT)
            else:
                server = smtplib.SMTP(self.host, port, timeout=TIMEOUT)
                server.starttls()
            with server:
                if self.user:
                    server.login(self.user, self.password)
                server.send_message(message)
        except (OSError, smtplib.SMTPException, ValueError) as exc:
            return Delivery(self.name, False, str(exc))
        return Delivery(self.name, True)

    def poll(self) -> list[Incoming]:
        return []


BUILDERS = {
    "telegram": lambda s: Telegram(token=str(s.get("token", "")),
                                   chat_id=str(s.get("chat_id", ""))),
    "discord": lambda s: Discord(webhook=str(s.get("webhook", ""))),
    "slack": lambda s: Slack(webhook=str(s.get("webhook", ""))),
    "ntfy": lambda s: Ntfy(topic=str(s.get("topic", "")),
                           server=str(s.get("server") or "https://ntfy.sh"),
                           token=str(s.get("token", ""))),
    "mail": lambda s: Mail(host=str(s.get("host", "")), port=s.get("port", 587),
                           user=str(s.get("user", "")),
                           password=str(s.get("password", "")),
                           to=str(s.get("to", ""))),
}


def build(channel) -> object | None:
    """Turn one configured channel into the adapter that serves it."""
    builder = BUILDERS.get(channel.platform)
    return builder(channel.settings) if builder else None
