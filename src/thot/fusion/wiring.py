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
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PLUGIN_SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

SERVER_NAME = "thot"


# The SDK Hermes needs to be an MCP *client*. Thot's own server does not use
# it — `mcp_server` speaks JSON-RPC by hand, on purpose — so its absence is
# invisible from Thot's side and total from Hermes's: `_ensure_mcp_sdk()`
# returns False and every server is skipped, at debug level, with no user
# visible message at all.
MCP_SDK = "mcp"


def can_import(interpreter: Path, module: str) -> bool | None:
    """Whether another environment's interpreter can import a module.

    A subprocess and not an import: Thot never loads Hermes into its own
    process — each program authenticates and resolves as itself — and the
    interpreter being asked about is by construction not this one.

    Three answers, not two. `None` is "the question could not be put" — no
    such interpreter, it would not start — and reporting that as "no" would
    send someone installing a package to fix a path.
    """
    try:
        done = subprocess.run(
            [str(interpreter), "-c", f"import {module}"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode == 0


def hermes_speaks_mcp() -> bool | None:
    """Whether the Hermes this checkout runs can connect to any MCP server."""
    from thot.fusion.locate import hermes_python

    interpreter = hermes_python()
    if interpreter is None:
        return None
    return can_import(interpreter, MCP_SDK)


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


def prime_auth_path() -> Path:
    return prime_home() / "auth.json"


# The key Prime looks the credential up under: `mcp:<server>`, matching the
# `mcpServers` key. Both have to be `thot` or nothing connects.
PRIME_AUTH_KEY = f"mcp:{SERVER_NAME}"

PRIME_SKILL_DIRNAME = "prime-skill"


def prime_skill_dir() -> Path | None:
    """The Prime skill package Thot ships, editable install or wheel.

    A configuration entry is not an integration. Prime reaches an MCP server
    through a Python class that subclasses `rlm.McpIntegration` and names the
    server — that is how the Linear and Notion integrations it ships work,
    and there is no generic path that connects a declared server without
    one. So Thot carries its own, and the wiring points Prime's `skills` at
    the directory holding it.
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / PRIME_SKILL_DIRNAME,  # repository root / editable
        here.parents[1] / PRIME_SKILL_DIRNAME,  # packaged under thot/
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def server_entry() -> dict:
    """How Hermes should start Thot's MCP server: itself, over a pipe.

    A bare `thot` on PATH, not `sys.executable -m`: Hermes refuses a plugin
    whose command is an absolute path, so that a plugin cannot point at an
    arbitrary binary. The bare token satisfies it and survives the
    virtualenv being moved.

    `THOT_ROOT` is deliberately not set: the server falls back to its working
    directory, so the map is of whatever project the agent was launched in.
    Pinning it here would hand every project the same stale map.
    """
    return {"type": "stdio", "command": "thot", "args": ["mcp", "serve"]}


def prime_server_entry(port: int | None = None) -> dict:
    """How Prime should reach Thot's MCP server: over HTTP, or not at all.

    `mcp-manager.js` drops every configured entry whose `type` is not
    `"http"` — its comment says "stdio servers self-manage in Python", and
    that Python does not exist: not one occurrence of `stdio_client` in the
    whole of `prime/`. The `stdio` entry written here before was read by
    nobody, while `thot fusion status` counted the file and reported the
    fusion wired.

    Prime cannot start the server itself, which is the price of the
    transport: `thot mcp serve --http` has to be running.
    """
    from thot.mcp_http import DEFAULT_PORT, ENDPOINT, LOOPBACK

    chosen = DEFAULT_PORT if port is None else port
    return {
        "type": "http",
        "url": f"http://{LOOPBACK}:{chosen}{ENDPOINT}",
        "enabled": True,
    }


def prime_endpoint() -> str | None:
    """The URL Prime is configured to dial, or None when it is not.

    Read from the file Prime reads, never from `prime_server_entry()` — that
    one says what Thot *would* write, and the whole point of asking is that
    the two can differ: an upgrade rewrote the entry, somebody set
    `enabled: false`, a port was changed by hand. A check built on what we
    intended cannot notice any of those.
    """
    settings = _read_json(prime_settings_path()) or {}
    servers = settings.get("mcpServers")
    entry = servers.get(SERVER_NAME) if isinstance(servers, dict) else None
    if not isinstance(entry, dict) or entry.get("type") != "http":
        return None
    if entry.get("enabled") is False:
        return None
    url = entry.get("url")
    return url if isinstance(url, str) and url else None


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


def _prime_settings_wanted(current: dict | None) -> dict:
    """The user's settings, plus the two things Prime needs to reach Thot.

    Merged, never replaced: this is a live file belonging to another program,
    and the model, the theme and the skill paths in it are not Thot's to
    rewrite.
    """
    settings = dict(current or {})
    servers = settings.get("mcpServers")
    settings["mcpServers"] = {
        **(servers if isinstance(servers, dict) else {}),
        SERVER_NAME: prime_server_entry(),
    }
    directory = prime_skill_dir()
    if directory is not None:
        listed = settings.get("skills")
        paths = [item for item in listed if isinstance(item, str)] \
            if isinstance(listed, list) else []
        if str(directory) not in paths:
            paths = [*paths, str(directory)]
        settings["skills"] = paths
    return settings


def plan_prime() -> list[Step]:
    """Two files, because reaching Prime takes two.

    The settings carry the endpoint and the skill package; `auth.json` carries
    the credential. Without the second, `McpIntegration._resolve_token` raises
    `NotEnabled` before a single byte is sent, and the entry in the settings
    is decoration.
    """
    steps: list[Step] = []

    target = prime_settings_path()
    current = _read_json(target)
    wanted = _prime_settings_wanted(current)
    if current is None:
        steps.append(Step(target, "créer", "settings.json de Prime"))
    elif current != wanted:
        steps.append(Step(target, "mettre à jour",
                          f"mcpServers.{SERVER_NAME} en http, et la bibliothèque"))
    else:
        steps.append(Step(target, "déjà en place"))

    auth = prime_auth_path()
    held = _read_json(auth)
    entry = (held or {}).get(PRIME_AUTH_KEY)
    if isinstance(entry, dict) and entry.get("key"):
        steps.append(Step(auth, "déjà en place", "jeton du serveur local"))
    else:
        steps.append(Step(auth, "créer" if not auth.is_file() else "mettre à jour",
                          f"{PRIME_AUTH_KEY} — sans lui Prime lève NotEnabled"))
    return steps


def hermes_config_path() -> Path:
    return hermes_home() / "config.yaml"


def hermes_enabled() -> bool | None:
    """Whether Hermes will actually load the plugin. None when unreadable.

    Hermes installs portable Agent Plugins disabled, on purpose. Writing the
    two files therefore wires nothing on its own — and a status that counted
    files would report success while Hermes ignored the plugin. Presence is
    not function.
    """
    import yaml

    path = hermes_config_path()
    if not path.is_file():
        # No config at all: Hermes has never been configured here, so nothing
        # enables anything. That is a definite no, not an unknown.
        return False
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError:
        # A config Hermes itself cannot parse. Answering False here would
        # claim the plugin is off; the truth is that nobody knows.
        return None
    if loaded is None:
        return False
    if not isinstance(loaded, dict):
        return None
    plugins = loaded.get("plugins")
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    return bool(isinstance(enabled, list) and SERVER_NAME in enabled)


def plan_enable() -> list[Step]:
    state = hermes_enabled()
    target = hermes_config_path()
    if state is None:
        return [Step(target, "à vérifier", "config Hermes illisible")]
    if state:
        return [Step(target, "déjà en place", f"plugins.enabled contient {SERVER_NAME}")]
    return [Step(target, "activer", f"`hermes plugins enable {SERVER_NAME}`")]


def enable_hermes_plugin() -> tuple[bool, str]:
    """Enable through Hermes's own CLI, never by editing its config.

    `config.yaml` is Hermes's file, with its own schema, its own comments and
    its own migrations. Hand-editing it from outside would work until the day
    it did not.
    """
    import subprocess

    from thot.fusion.locate import hermes_command

    command = hermes_command()
    if command is None:
        return False, "Hermes n'est pas installé — `uv sync` à la racine."
    try:
        done = subprocess.run(
            [*command, "plugins", "enable", SERVER_NAME],
            capture_output=True, text=True, timeout=180, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else f"code {done.returncode}"
    return True, ""


def plan() -> list[Step]:
    return plan_hermes() + plan_enable() + plan_prime()


def _write_json(path: Path, payload: dict, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written whole then moved: an agent reading the file while Thot writes it
    # must never see half a document.
    temporary = path.with_suffix(path.suffix + ".thot-tmp")
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if mode is None:
        temporary.write_text(text, encoding="utf-8")
    else:
        # The mode goes on at creation, not after. A credentials file that is
        # world-readable for the width of one `chmod` call has been readable,
        # and nothing about the window is bounded.
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
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
    settings_step, auth_step = steps[0], steps[1]

    if settings_step.changes:
        target = settings_step.target
        if target.is_file():
            # The user's own settings. One backup, on the first change only,
            # so a mistake here is recoverable without a git history they may
            # not have.
            backup = target.with_suffix(".json.thot-backup")
            if not backup.exists():
                backup.write_text(target.read_text(encoding="utf-8"),
                                  encoding="utf-8")
        _write_json(target, _prime_settings_wanted(_read_json(target)))

    if auth_step.changes:
        target = auth_step.target
        held: dict | None = {}
        if target.is_file():
            held = _read_json(target)
            if held is None:
                # Refusing beats rewriting. This file holds the credentials
                # for the user's model; reconstructing it from an unreadable
                # original would log them out of Prime to install a token.
                steps[1] = Step(target, "refusé",
                                "auth.json illisible — laissé intact")
                return steps
        from thot.mcp_http import read_or_make_token

        held[PRIME_AUTH_KEY] = {"type": "api_key", "key": read_or_make_token()}
        _write_json(target, held, mode=0o600)

    return steps


def wire() -> list[Step]:
    done = wire_hermes()

    step = plan_enable()[0]
    if step.action == "activer":
        ok, why = enable_hermes_plugin()
        done.append(
            Step(step.target, "activé" if ok else "échec",
                 "" if ok else why)
        )
    else:
        done.append(step)

    return done + wire_prime()


def unwire() -> list[Step]:
    """Remove Thot from both agents. Leaves everything else untouched."""
    done: list[Step] = []

    # The config is cleaned while the plugin files are still on disk: Hermes
    # refuses `plugins disable` for a plugin whose manifest is gone ("Plugin
    # 'thot' is not installed or bundled.", rc=1) and leaves `plugins.enabled`
    # untouched. Removing first therefore left Hermes loading a plugin whose
    # every file had just been deleted, under a line saying "désactivé".
    if hermes_enabled():
        import subprocess

        from thot.fusion.locate import hermes_command

        command = hermes_command()
        if command is not None:
            try:
                off = subprocess.run(
                    [*command, "plugins", "disable", SERVER_NAME],
                    capture_output=True, text=True, timeout=180, check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                # Reporting nothing would replace a false claim with a silence,
                # which is the same defect one step further away.
                done.append(Step(hermes_config_path(), "échec", str(exc)))
            else:
                if off.returncode == 0:
                    done.append(Step(hermes_config_path(), "désactivé"))
                else:
                    said = (off.stderr or off.stdout or "").strip().splitlines()
                    done.append(Step(hermes_config_path(), "échec",
                                     said[-1] if said else f"code {off.returncode}"))

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
    if settings is not None:
        removed: list[str] = []
        servers = settings.get("mcpServers")
        if isinstance(servers, dict) and servers.pop(SERVER_NAME, None) is not None:
            if not servers:
                settings.pop("mcpServers")
            removed.append(f"mcpServers.{SERVER_NAME}")
        directory = prime_skill_dir()
        listed = settings.get("skills")
        if directory is not None and isinstance(listed, list) and str(directory) in listed:
            settings["skills"] = [item for item in listed if item != str(directory)]
            removed.append("la bibliothèque de méthodes")
        if removed:
            _write_json(target, settings)
            done.append(Step(target, "retiré", " et ".join(removed)))

    auth = prime_auth_path()
    held = _read_json(auth)
    if held is not None and held.pop(PRIME_AUTH_KEY, None) is not None:
        # Same mode it was written with: taking one key out of a credentials
        # file must not be the moment it becomes world-readable.
        _write_json(auth, held, mode=0o600)
        done.append(Step(auth, "retiré", PRIME_AUTH_KEY))

    return done
