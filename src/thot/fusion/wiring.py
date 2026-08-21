"""Plug Thot's deterministic map into Hermes and Prime.

This is the point of putting the three in one repository. Hermes and Prime
discover a codebase the way every conversational agent does — by opening
files with the model, slowly, partially, and paid for by the token. Thot
already has the answer: an AST index, a call graph, and an audit, computed
offline in a second. Exposing that over MCP means both agents start knowing
the terrain instead of buying it back every session.

Nothing here is automatic. Both files belong to the user's live agents, so
writing them is an explicit act (`thot fusion wire`), it says what it wrote,
and it can be undone.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

PLUGIN_SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

SERVER_NAME = "thot"


def hermes_home() -> Path:
    raw = os.environ.get("HERMES_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".hermes"


def prime_home() -> Path:
    raw = os.environ.get("PRIME_AGENT_CONFIG_DIR", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".prime" / "agent"


def hermes_plugin_dir() -> Path:
    return hermes_home() / "plugins" / SERVER_NAME


def prime_settings_path() -> Path:
    return prime_home() / "settings.json"


def server_entry() -> dict:
    """How either agent should start Thot's MCP server.

    A bare `thot` on PATH, not `sys.executable -m`: Hermes refuses a plugin
    whose command is an absolute path, so that a plugin cannot point at an
    arbitrary binary. The bare token satisfies both agents and survives the
    virtualenv being moved.

    `THOT_ROOT` is deliberately not set: the server falls back to its working
    directory, so the map is of whatever project the agent was launched in.
    Pinning it here would hand every project the same stale map.
    """
    return {"type": "stdio", "command": "thot", "args": ["mcp", "serve"]}


def on_path() -> Path | None:
    """Where a bare `thot` resolves — None when it resolves nowhere.

    Both agents start the server by name. Writing a config that names a
    command the machine cannot find would look like success and fail at the
    first tool call.
    """
    import shutil

    found = shutil.which("thot")
    return Path(found) if found else None


def _plugin_manifest() -> dict:
    return {
        "$schema": PLUGIN_SCHEMA_V1,
        "name": SERVER_NAME,
        "version": _thot_version(),
        "description": (
            "La carte déterministe de Thot : index AST, graphe d'appels, "
            "audit et méthodes, sans appel modèle."
        ),
    }


def _mcp_manifest() -> dict:
    # The shape is validated strictly by Hermes: exactly these two keys.
    return {"$schema": MCP_SCHEMA_V1, "mcpServers": {SERVER_NAME: server_entry()}}


def _thot_version() -> str:
    from thot import __version__

    return __version__


@dataclass(frozen=True)
class Step:
    """One file the wiring would touch, and what it would do to it."""

    target: Path
    action: str  # "créer" | "mettre à jour" | "déjà en place"
    detail: str = ""

    def line(self) -> str:
        detail = f" — {self.detail}" if self.detail else ""
        return f"{self.action:<14} {self.target}{detail}"

    @property
    def changes(self) -> bool:
        return self.action != "déjà en place"


def _read_json(path: Path) -> dict | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def plan_hermes() -> list[Step]:
    folder = hermes_plugin_dir()
    steps: list[Step] = []
    for name, wanted in (("plugin.json", _plugin_manifest()),
                         ("mcp.json", _mcp_manifest())):
        target = folder / name
        current = _read_json(target)
        if current == wanted:
            steps.append(Step(target, "déjà en place"))
        elif current is None:
            steps.append(Step(target, "créer", "plugin agent Hermes"))
        else:
            steps.append(Step(target, "mettre à jour", "contenu différent"))
    return steps


def plan_prime() -> list[Step]:
    target = prime_settings_path()
    current = _read_json(target)
    if current is None:
        return [Step(target, "créer", "settings.json de Prime")]
    servers = current.get("mcpServers")
    if isinstance(servers, dict) and servers.get(SERVER_NAME) == server_entry():
        return [Step(target, "déjà en place")]
    return [Step(target, "mettre à jour",
                 f"ajoute mcpServers.{SERVER_NAME}, garde le reste")]


def plan() -> list[Step]:
    return plan_hermes() + plan_prime()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written whole then moved: an agent reading the file while Thot writes it
    # must never see half a document.
    temporary = path.with_suffix(path.suffix + ".thot-tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def wire_hermes() -> list[Step]:
    folder = hermes_plugin_dir()
    done: list[Step] = []
    for step, payload in zip(plan_hermes(),
                             (_plugin_manifest(), _mcp_manifest())):
        if step.changes:
            _write_json(step.target, payload)
        done.append(step)
    del folder
    return done


def wire_prime() -> list[Step]:
    steps = plan_prime()
    step = steps[0]
    if not step.changes:
        return steps

    target = step.target
    settings = _read_json(target) or {}
    if target.is_file():
        # The user's own settings. One backup, on the first change only, so a
        # mistake here is recoverable without a git history they may not have.
        backup = target.with_suffix(".json.thot-backup")
        if not backup.exists():
            backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")

    servers = settings.get("mcpServers")
    settings["mcpServers"] = {**(servers if isinstance(servers, dict) else {}),
                              SERVER_NAME: server_entry()}
    _write_json(target, settings)
    return steps


def wire() -> list[Step]:
    return wire_hermes() + wire_prime()


def unwire() -> list[Step]:
    """Remove Thot from both agents. Leaves everything else untouched."""
    done: list[Step] = []

    for name in ("plugin.json", "mcp.json"):
        target = hermes_plugin_dir() / name
        if target.is_file():
            target.unlink()
            done.append(Step(target, "retiré"))
    folder = hermes_plugin_dir()
    if folder.is_dir() and not any(folder.iterdir()):
        folder.rmdir()

    target = prime_settings_path()
    settings = _read_json(target)
    if settings and isinstance(settings.get("mcpServers"), dict):
        if settings["mcpServers"].pop(SERVER_NAME, None) is not None:
            if not settings["mcpServers"]:
                settings.pop("mcpServers")
            _write_json(target, settings)
            done.append(Step(target, "retiré", f"mcpServers.{SERVER_NAME}"))

    return done
