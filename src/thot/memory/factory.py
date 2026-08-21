"""Choose the verdict store, without every call site knowing how.

Default, with no configuration at all: the repository's committed verdicts
if the file exists, then this machine's SQLite. That is the behaviour a
team gets by checking in `.thot/verdicts.json`, and it needs no setup.

`~/.thot/memory.json` adds a remote layer:

    {"remote": {"kind": "http",
                "base_url": "https://audit.equipe.example",
                "token": "…"}}
    {"remote": {"kind": "mem0", "host": "http://localhost:8888",
                "api_key": "…"}}

Environment wins over the file, the way it does for the gateway.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from thot.memory.base import Memory
from thot.memory.jsonfile import JsonMemory, repo_path
from thot.memory.layered import LayeredMemory
from thot.paths import home

FILENAME = "memory.json"
KINDS = ("sqlite", "json", "http", "mem0")


def config_file() -> Path:
    return home() / FILENAME


def load_config() -> dict:
    try:
        data = json.loads(config_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    remote = dict(data.get("remote") or {})
    if os.environ.get("THOT_MEMORY_URL"):
        remote.setdefault("kind", "http")
        remote["base_url"] = os.environ["THOT_MEMORY_URL"]
    if os.environ.get("THOT_MEMORY_TOKEN"):
        remote["token"] = os.environ["THOT_MEMORY_TOKEN"]
    if os.environ.get("MEM0_HOST"):
        remote["kind"] = "mem0"
        remote["host"] = os.environ["MEM0_HOST"]
    if os.environ.get("MEM0_API_KEY"):
        remote["api_key"] = os.environ["MEM0_API_KEY"]
    if remote:
        data["remote"] = remote
    return data


def build_remote(settings: dict) -> Memory | None:
    kind = str(settings.get("kind") or "").lower()
    if kind == "http" and settings.get("base_url"):
        from thot.memory.remote import HttpMemory

        return HttpMemory(base_url=str(settings["base_url"]),
                          token=str(settings.get("token") or ""))
    if kind == "mem0" and settings.get("host"):
        from thot.memory.remote import Mem0Memory

        return Mem0Memory(host=str(settings["host"]),
                          api_key=str(settings.get("api_key") or ""))
    return None


def build_memory(root: Path | str | None = None, *, config: dict | None = None):
    """The verdict store for this repository, layered when it should be.

    Always returns something. A misconfigured remote costs the remote layer,
    never the audit: an auditor that stops working when a server is down is
    an auditor nobody keeps.
    """
    from thot.memory.sqlite import SqliteMemory

    config = load_config() if config is None else config
    layers: list[Memory] = []

    if root is not None and repo_path(root).is_file():
        layers.append(JsonMemory.for_repo(root))

    remote = build_remote(config.get("remote") or {})
    if remote is not None:
        layers.append(remote)

    local = SqliteMemory.open()
    layers.append(local)

    if len(layers) == 1:
        return local  # no chain to build; hand back the plain store
    return LayeredMemory(layers)  # writes land on the last layer: local
