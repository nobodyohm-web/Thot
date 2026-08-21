"""Where the gateway's channels are configured.

`~/.thot/gateway.json`, mode 0600, because it holds bot tokens and SMTP
passwords. Environment variables win over the file for every field, so a
container can be configured without one — the arrangement Hermes uses, kept.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from thot.gateway.base import Channel
from thot.paths import home

FILENAME = "gateway.json"

# platform -> {setting: environment variable}. Names follow Hermes's, so a
# machine already configured for Hermes needs nothing new for the shared ones.
ENV = {
    "telegram": {
        "token": "TELEGRAM_BOT_TOKEN",
        "chat_id": "TELEGRAM_HOME_CHANNEL",
        "allow": "TELEGRAM_ALLOWED_USERS",
    },
    "discord": {"webhook": "DISCORD_WEBHOOK_URL"},
    "slack": {"webhook": "SLACK_WEBHOOK_URL"},
    "ntfy": {
        "topic": "NTFY_TOPIC",
        "server": "NTFY_SERVER_URL",
        "token": "NTFY_TOKEN",
        "allow": "NTFY_ALLOWED_USERS",
    },
    "mail": {
        "host": "THOT_SMTP_HOST",
        "port": "THOT_SMTP_PORT",
        "user": "THOT_SMTP_USER",
        "password": "THOT_SMTP_PASSWORD",
        "to": "THOT_MAIL_TO",
    },
}

PLATFORMS = tuple(ENV)


def config_file() -> Path:
    return home() / FILENAME


def _split(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.replace(";", ",").split(",") if part.strip())


def load() -> list[Channel]:
    """Configured channels, file first, environment overriding field by field."""
    try:
        data = json.loads(config_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}

    by_platform: dict[str, Channel] = {}
    for entry in (data.get("channels") or []):
        if not isinstance(entry, dict):
            continue
        platform = str(entry.get("platform") or "").lower()
        if platform not in ENV:
            continue
        allow = entry.get("allow") or ()
        by_platform[platform] = Channel(
            platform=platform,
            settings={k: v for k, v in entry.items() if k not in {"platform", "allow"}},
            allow=tuple(str(a) for a in allow),
        )

    for platform, mapping in ENV.items():
        settings = dict(by_platform.get(platform, Channel(platform)).settings)
        allow = by_platform.get(platform, Channel(platform)).allow
        touched = platform in by_platform
        for key, variable in mapping.items():
            value = os.environ.get(variable, "").strip()
            if not value:
                continue
            touched = True
            if key == "allow":
                allow = _split(value)
            else:
                settings[key] = value
        if touched:
            by_platform[platform] = Channel(platform, settings, allow)

    return [by_platform[name] for name in PLATFORMS if name in by_platform]


def save(channels: list[Channel]) -> Path:
    """Write the file back at 0600. It holds tokens; it is not a config file
    you want group-readable."""
    path = config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "channels": [
            {"platform": c.platform, **c.settings, "allow": list(c.allow)}
            for c in channels
        ]
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def upsert(platform: str, settings: dict, allow: tuple[str, ...] = ()) -> Path:
    channels = [c for c in load() if c.platform != platform]
    channels.append(Channel(platform=platform, settings=settings, allow=allow))
    return save(channels)


def remove(platform: str) -> bool:
    channels = load()
    kept = [c for c in channels if c.platform != platform]
    if len(kept) == len(channels):
        return False
    save(kept)
    return True
