"""Read the shipped MCP manifests, and hand installation to the `claude` CLI.

Ported from Hermes Agent's `optional-mcps/`, whose manifest format this
reads unchanged: presence in the directory is the approval, and each entry
says what the server is, how it is reached, and how it authenticates.

The install path is deliberately thin. Nineteen of the twenty servers use
OAuth over HTTP, and the official CLI already implements that flow against
the user's own account. Thot registering its own client would mean a second
token store to leak — so `thot mcp add` shells out to `claude mcp add` and
says which one command finishes the job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CATALOG_DIRNAME = "mcp-catalog"
MANIFEST = "manifest.yaml"

# Long enough to say what the server does, short enough for one row.
SUMMARY_CHARS = 64


@dataclass(frozen=True)
class Server:
    name: str
    description: str
    transport: str          # http | sse | stdio
    url: str = ""
    command: str = ""
    args: tuple[str, ...] = ()
    auth: str = "none"      # oauth | api_key | none
    source: str = ""
    env: dict = field(default_factory=dict)

    @property
    def remote(self) -> bool:
        return self.transport in {"http", "sse"}

    @property
    def needs_hermes(self) -> bool:
        """Entries whose command is filled in by a Hermes-side installer.

        `${INSTALL_DIR}` is expanded by Hermes when it vendors the server
        locally. Thot has nowhere to expand it from, so the honest answer
        is to say the entry is not installable here rather than register a
        command that will fail at first use.
        """
        return "${" in self.command or any("${" in a for a in self.args)

    def summary(self) -> str:
        text = " ".join(self.description.split())
        if len(text) > SUMMARY_CHARS:
            text = text[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…"
        return text

    def add_command(self, *, scope: str = "user") -> list[str]:
        """The exact `claude mcp add` invocation that registers this server."""
        base = ["claude", "mcp", "add", "--scope", scope]
        if self.remote:
            return [*base, "--transport", self.transport, self.name, self.url]
        parts = [*base, self.name]
        for key, value in self.env.items():
            parts += ["-e", f"{key}={value}"]
        return [*parts, "--", self.command, *self.args]


def catalog_dir() -> Path | None:
    """Where the shipped manifests live, editable install or wheel."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / CATALOG_DIRNAME,
                      here.parent / CATALOG_DIRNAME):
        if candidate.is_dir():
            return candidate
    return None


def _read(path: Path) -> Server | None:
    """Parse one manifest. A malformed entry is skipped, never fatal."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None

    transport = data.get("transport") or {}
    auth = data.get("auth") or {}
    args = transport.get("args") or []
    return Server(
        name=str(data.get("name") or path.parent.name),
        description=str(data.get("description") or "").strip(),
        transport=str(transport.get("type") or "stdio"),
        url=str(transport.get("url") or ""),
        command=str(transport.get("command") or ""),
        args=tuple(str(a) for a in args),
        auth=str(auth.get("type") or "none"),
        source=str(data.get("source") or ""),
        env={k: str(v) for k, v in (transport.get("env") or {}).items()},
    )


def catalog() -> list[Server]:
    directory = catalog_dir()
    if directory is None:
        return []
    found = [_read(path) for path in sorted(directory.glob(f"*/{MANIFEST}"))]
    return sorted((s for s in found if s), key=lambda s: s.name)


def find(name: str) -> Server | None:
    wanted = name.strip().lower()
    entries = catalog()
    for server in entries:
        if server.name.lower() == wanted:
            return server
    for server in entries:
        if wanted in server.name.lower():
            return server
    return None


def installed(root: Path | None = None) -> tuple[str, ...]:
    """Which MCP servers this user already has, per the official CLI."""
    from thot.llm.claude_cli import user_mcp_servers

    return user_mcp_servers(Path(root or Path.cwd()))


def install(server: Server, *, scope: str = "user") -> tuple[bool, str]:
    """Register the server with the official CLI. Returns (done, message).

    Never silent: an OAuth server is registered but not yet authorised, and
    saying so is the difference between "installed" and "works".
    """
    if server.needs_hermes:
        return False, (
            f"{server.name} est vendu localement par l'installateur d'Hermes "
            f"(chemin ${{INSTALL_DIR}}). Installe-le toi-même, puis "
            f"`claude mcp add {server.name} -- <commande>`."
        )
    if shutil.which("claude") is None:
        return False, (
            "Le CLI `claude` est introuvable — "
            "npm install -g @anthropic-ai/claude-code"
        )

    command = server.add_command(scope=scope)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Échec : {exc}"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else f"code {result.returncode}"

    if server.auth == "oauth":
        return True, (
            f"{server.name} enregistré. Il reste à l'autoriser : lance `claude`, "
            f"puis `/mcp` et choisis {server.name}."
        )
    if server.auth == "api_key":
        return True, (
            f"{server.name} enregistré. Il attend une clé API — "
            f"voir {server.source or 'la documentation du serveur'}."
        )
    return True, f"{server.name} enregistré."


def remove(name: str, *, scope: str = "user") -> tuple[bool, str]:
    if shutil.which("claude") is None:
        return False, "Le CLI `claude` est introuvable."
    try:
        result = subprocess.run(
            ["claude", "mcp", "remove", "--scope", scope, name],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Échec : {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else f"code {result.returncode}"
    return True, f"{name} retiré."


def as_json(servers: list[Server]) -> str:
    """The catalogue as data, for anything that would rather not parse rows."""
    return json.dumps(
        [
            {
                "name": s.name,
                "description": s.description,
                "transport": s.transport,
                "url": s.url,
                "auth": s.auth,
                "source": s.source,
            }
            for s in servers
        ],
        indent=2,
        ensure_ascii=False,
    )
