"""The gateway loop: push reports out, take short commands back.

Hermes runs a gateway because you live with the agent. Thot runs one for a
narrower reason: an audit that finishes at 03:00 is worth nothing until
someone is told, and the person who should be told is not at the terminal.

Outbound needs no daemon at all — the `gateway-notify` plugin fires on
`post_audit`, so a launchd-scheduled audit reports by itself. This loop
exists only for the way back.
"""

from __future__ import annotations

import sys
import time

from thot import logs
from thot.gateway import config
from thot.gateway.base import Channel, Delivery
from thot.gateway.commands import Board, handle
from thot.gateway.platforms import build

# How long to wait after a polling round that returned nothing. Telegram's
# long poll already blocks, so this only paces channels that return at once.
IDLE_SECONDS = 3


_logger = logs.get("gateway")


def _log(message: str) -> None:
    """On screen for whoever started the daemon, and in the file for later.

    A daemon that ran for three days and then misbehaved leaves nothing on
    a terminal that has since been closed.
    """
    print(f"[thot-gateway] {message}", file=sys.stderr, flush=True)
    _logger.info(message)


def channels() -> list[Channel]:
    return config.load()


def broadcast(text: str, *, only: tuple[str, ...] = ()) -> list[Delivery]:
    """Send to every configured channel. One dead channel costs only itself."""
    results: list[Delivery] = []
    for channel in channels():
        if only and channel.platform not in only:
            continue
        platform = build(channel)
        if platform is None or not platform.configured():
            continue
        results.append(platform.send(text))
    return results


def _reply(platform, incoming, text: str) -> None:
    delivery = platform.send(text, channel=incoming.channel)
    if not delivery.ok:
        _log(f"réponse non délivrée sur {delivery.platform} : {delivery.detail}")


def serve(*, once: bool = False, idle: float = IDLE_SECONDS) -> int:
    """Listen for commands until interrupted. Returns a process exit code."""
    configured = channels()
    if not configured:
        _log("aucun canal configuré — `thot gateway add telegram …`")
        return 2

    listening = [c for c in configured if c.two_way]
    for channel in configured:
        if not channel.two_way:
            _log(f"{channel.platform} : sortant seulement "
                 f"(pas de liste d'autorisation, ou plateforme sans réception)")
    if not listening:
        _log("aucun canal ne peut recevoir de commande. Les rapports partiront "
             "quand même ; pour répondre, ajoute une liste d'autorisation.")
        return 2

    boards: dict[str, Board] = {c.platform: Board() for c in listening}
    adapters = {c.platform: build(c) for c in listening}
    _log("à l'écoute sur " + ", ".join(sorted(adapters)))

    while True:
        acted = False
        for channel in listening:
            platform = adapters[channel.platform]
            if platform is None or not platform.configured():
                continue
            try:
                messages = platform.poll()
            except Exception as exc:  # a platform outage is not a crash
                _log(f"{channel.platform} : {exc}")
                continue

            for incoming in messages:
                acted = True
                if not channel.allows(incoming.sender):
                    _log(f"refus : {incoming.sender_name or '?'} "
                         f"({incoming.sender}) n'est pas autorisé")
                    _reply(platform, incoming,
                           "Non autorisé. Ajoute cet identifiant avec "
                           f"`thot gateway allow {channel.platform} "
                           f"{incoming.sender}`.")
                    continue

                verb, argument = incoming.command()
                _log(f"{channel.platform} · {incoming.sender_name or incoming.sender}"
                     f" : {verb}")
                try:
                    answer = handle(verb, argument,
                                    board=boards[channel.platform],
                                    author=incoming.sender_name or incoming.sender)
                except Exception as exc:
                    answer = f"La commande a échoué : {exc}"
                    _log(answer)
                _reply(platform, incoming, answer)

        if once:
            return 0
        if not acted:
            time.sleep(idle)
