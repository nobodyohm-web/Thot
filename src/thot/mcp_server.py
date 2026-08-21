"""A minimal MCP server exposing Thot's deterministic tools.

Run by the official `claude` CLI as a subprocess, so the graph tools are
available to a session driven by the user's own Claude account. Speaks
JSON-RPC 2.0 over stdio — the three methods a tool server needs, no more.

Nothing here talks to a model: every answer comes from the precomputed map.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "thot"

# Only the deterministic tools are exposed. Reading, writing and running
# commands stay with the CLI, which already has them and asks for permission.
EXPOSED = ("code_map", "find_symbol", "callers", "audit", "skills", "skill")


def _log(message: str) -> None:
    """Diagnostics go to stderr; stdout belongs to the protocol."""
    print(f"[thot-mcp] {message}", file=sys.stderr, flush=True)


# What the agent must be able to say. Neither Hermes nor Prime advertises
# workspace roots over MCP, and Hermes starts a plugin server with its cwd
# pinned inside the plugin directory — so a server that inferred the project
# from its own cwd would map the plugin folder and answer "0 files" forever.
# The agent knows which project it is working on; the schema asks it.
ROOT_PROPERTY = {
    "type": "string",
    "description": (
        "Racine du projet à cartographier (chemin absolu). À fournir : le "
        "serveur est démarré depuis un dossier de configuration, pas depuis "
        "le projet."
    ),
}


class Server:
    def __init__(self, root: Path) -> None:
        self.root = root
        # One map per project. An agent that moves between repositories in a
        # single session must not be handed the first one's map.
        self._contexts: dict[Path, object] = {}

    def resolve_root(self, argument: str | None) -> Path:
        if argument:
            candidate = Path(argument).expanduser()
            if candidate.is_dir():
                return candidate.resolve()
            raise ValueError(f"Dossier introuvable : {argument}")
        return self.root

    def _tool_context(self, root: Path):
        cached = self._contexts.get(root)
        if cached is not None:
            return cached

        from thot.agent_tools import ToolContext
        from thot.recon import sweep

        recon = sweep(root)
        context = ToolContext(
            root=root,
            recon=recon,
            confirm=lambda action, detail: False,  # never mutates
            refresh=lambda: None,
        )
        _log(
            f"carte prête pour {root} : {recon.file_count} fichiers, "
            f"{len(recon.symbols)} symboles, {len(recon.findings)} findings"
        )
        self._contexts[root] = context
        return context

    def refresh(self) -> None:
        self._contexts.clear()

    # -- protocol --------------------------------------------------------

    def handle(self, request: dict) -> dict | None:
        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            return _result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": _version()},
                },
            )

        if method in {"notifications/initialized", "initialized"}:
            return None  # notification: no reply

        if method == "tools/list":
            from thot import agent_tools

            tools = [
                {
                    "name": spec.name,
                    "description": spec.description,
                    "inputSchema": _with_root(spec.parameters),
                }
                for spec in agent_tools.SPECS
                if spec.name in EXPOSED
            ]
            return _result(request_id, {"tools": tools})

        if method == "tools/call":
            from thot import agent_tools

            params = request.get("params") or {}
            name = params.get("name", "")
            arguments = params.get("arguments") or {}
            if name not in EXPOSED:
                return _error(request_id, -32602, f"Outil inconnu : {name}")
            arguments = dict(arguments)
            try:
                root = self.resolve_root(arguments.pop("root", None))
            except ValueError as exc:
                return _error(request_id, -32602, str(exc))
            # A fresh sweep per call would be wasteful; the CLI's own edits
            # invalidate it, so refresh when the map is stale for writes only.
            text = agent_tools.dispatch(self._tool_context(root), name, arguments)
            return _result(
                request_id, {"content": [{"type": "text", "text": text}]}
            )

        if method == "ping":
            return _result(request_id, {})

        return _error(request_id, -32601, f"Méthode inconnue : {method}")


def _with_root(parameters: dict) -> dict:
    """The tool's own schema, plus the project it should answer about.

    Copied, never mutated: `agent_tools.SPECS` is shared with the session,
    where the root is not a parameter because the session already has one.
    """
    schema = dict(parameters or {})
    properties = dict(schema.get("properties") or {})
    properties.setdefault("root", ROOT_PROPERTY)
    schema["properties"] = properties
    schema.setdefault("type", "object")
    return schema


def _version() -> str:
    from thot import __version__

    return __version__


def _result(request_id: Any, payload: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id: Any, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def serve(root: Path | None = None) -> int:
    root = Path(root or os.environ.get("THOT_ROOT") or Path.cwd()).resolve()
    server = Server(root)
    _log(f"démarré sur {root}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            response = server.handle(request)
        except Exception as exc:  # never take the CLI down with us
            _log(f"erreur : {exc}")
            response = _error(request.get("id"), -32603, str(exc))

        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    return 0


def config_payload(root: Path) -> dict:
    """The --mcp-config value that points the CLI back at this server."""
    return {
        "mcpServers": {
            SERVER_NAME: {
                "command": sys.executable,
                "args": ["-m", "thot.mcp_server"],
                "env": {"THOT_ROOT": str(root)},
            }
        }
    }


if __name__ == "__main__":
    raise SystemExit(serve())
