"""Reach Thot from somewhere other than the terminal.

Ported from Hermes Agent's gateway, narrowed to two verbs: push a report
out, take a short command back. Five channels — Telegram, Discord, Slack,
ntfy, e-mail — of which only Telegram can receive, because it long-polls
and therefore needs no port open to the internet.
"""

from thot.gateway.base import Channel, Delivery, Incoming, Platform, truncate
from thot.gateway.commands import Board, handle
from thot.gateway.platforms import build
from thot.gateway.render import report
from thot.gateway.server import broadcast, channels, serve

__all__ = [
    "Board",
    "Channel",
    "Delivery",
    "Incoming",
    "Platform",
    "broadcast",
    "build",
    "channels",
    "handle",
    "report",
    "serve",
    "truncate",
]
