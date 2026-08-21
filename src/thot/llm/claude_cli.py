"""Drive the official `claude` CLI as Thot's inference engine.

This is how a Claude subscription powers Thot without any impersonation: the
official client makes the request under the user's own account, exactly as it
would if they had typed `claude` themselves. Thot supplies the briefing, plugs
its deterministic tools in over MCP, and renders the event stream.

The CLI owns the conversation — history, tool loop, permissions. Thot keeps the
session id so each turn resumes the same thread.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from thot.llm.base import ProviderError
from thot.mcp_server import EXPOSED, config_payload

# Editing is allowed without a prompt: a non-interactive CLI cannot ask, and
# every tool call is echoed live so nothing happens silently.
PERMISSION_MODE = "acceptEdits"

# The permission mode does not cover MCP tools, so Thot's own are allowed by
# name. They only read the precomputed map — none of them touches the disk.
ALLOWED_TOOLS = tuple(f"mcp__thot__{name}" for name in EXPOSED)


CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
CLAUDE_CONFIG = Path.home() / ".claude.json"


def user_mcp_servers(root: Path) -> tuple[str, ...]:
    """The MCP servers this user already has, global and per-project.

    Thot adds one server; it has no business removing the rest. Passing
    --strict-mcp-config did exactly that — inside Thot the user silently lost
    their whole toolbelt, with nothing on screen to explain it. Discovering
    the names lets them be allowed through by name, since the permission mode
    does not cover MCP tools.
    """
    names: set[str] = set()

    try:
        data = json.loads(CLAUDE_CONFIG.read_text())
    except (OSError, ValueError):
        data = {}
    if isinstance(data, dict):
        names.update(data.get("mcpServers") or {})
        project = (data.get("projects") or {}).get(str(root)) or {}
        names.update(project.get("mcpServers") or {})

    try:
        local = json.loads((Path(root) / ".mcp.json").read_text())
        names.update(local.get("mcpServers") or {})
    except (OSError, ValueError, AttributeError):
        pass

    names.discard("thot")  # ours is supplied inline, not from their config
    return tuple(sorted(names))


def configured_model() -> str:
    """The model the official CLI would use, read from its own settings.

    Best effort: an empty answer just means Thot shows the model after the
    first turn instead of before it.
    """
    try:
        return str(json.loads(CLAUDE_SETTINGS.read_text()).get("model", "") or "")
    except (OSError, ValueError):
        return ""


@dataclass
class Events:
    """Callbacks the session provides to render the stream."""

    on_text: Callable[[str], None] = lambda chunk: None
    on_tool: Callable[[str, dict], None] = lambda name, args: None
    on_error: Callable[[str], None] = lambda message: None


@dataclass
class ClaudeCli:
    """One conversation, carried across turns by its session id."""

    root: Path
    model: str = ""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    active_model: str = ""  # what the CLI actually used, learned from the stream
    last_tokens: int = 0  # what the last turn cost, learned from the result event
    isolated: bool = False  # cut the user's own MCP servers out of the session
    _started: bool = False

    def resume(self, session_id: str) -> None:
        """Continue an existing CLI conversation instead of opening a new one.

        Thot indexes threads; the CLI owns them. Handing the id back is what
        makes `/resume` restore the model's actual context rather than replay
        a transcript at a model that has forgotten it.
        """
        self.session_id = session_id
        self._started = True

    def forget_thread(self) -> None:
        """Start a fresh CLI conversation — the point of `/compact`."""
        self.session_id = str(uuid.uuid4())
        self._started = False
        self.active_model = ""

    @staticmethod
    def available() -> bool:
        return shutil.which("claude") is not None

    def _command(self, prompt: str, brief: str) -> list[str]:
        binary = shutil.which("claude")
        if not binary:
            raise ProviderError(
                "Le CLI `claude` est introuvable.\n"
                "   Installe-le avec : npm install -g @anthropic-ai/claude-code"
            )

        allowed = list(ALLOWED_TOOLS)
        allowed += [f"mcp__{name}" for name in user_mcp_servers(self.root)]

        command = [
            binary,
            "-p",
            "--output-format", "stream-json",
            "--include-partial-messages",
            "--verbose",
            "--permission-mode", PERMISSION_MODE,
            "--mcp-config", json.dumps(config_payload(self.root)),
            "--allowed-tools", " ".join(allowed),
        ]
        if self.isolated:
            command.append("--strict-mcp-config")
        if self.model:
            command += ["--model", self.model]
        if self._started:
            command += ["--resume", self.session_id]
        else:
            command += ["--session-id", self.session_id]
        if brief:
            command += ["--append-system-prompt", brief]
        command.append(prompt)
        return command

    def send(self, prompt: str, *, brief: str = "", events: Events | None = None) -> str:
        """Run one turn. Returns the assistant's final text."""
        events = events or Events()
        command = self._command(prompt, brief)

        try:
            process = subprocess.Popen(
                command,
                cwd=str(self.root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise ProviderError(f"Impossible de lancer `claude` : {exc}") from exc

        answer: list[str] = []
        seen_tools: set[str] = set()

        assert process.stdout is not None
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._consume(event, events, answer, seen_tools)

        process.wait()
        if process.returncode != 0:
            stderr = (process.stderr.read() if process.stderr else "").strip()
            raise ProviderError(_explain(process.returncode, stderr))

        self._started = True
        return "".join(answer)

    def _consume(
        self,
        event: dict,
        events: Events,
        answer: list[str],
        seen_tools: set[str],
    ) -> None:
        kind = event.get("type")

        if kind == "stream_event":
            inner = event.get("event") or {}
            if inner.get("type") == "content_block_delta":
                delta = inner.get("delta") or {}
                if delta.get("type") == "text_delta":
                    chunk = delta.get("text", "")
                    answer.append(chunk)
                    events.on_text(chunk)
            return

        if kind == "assistant":
            for block in (event.get("message") or {}).get("content", []):
                if block.get("type") == "tool_use":
                    key = block.get("id", "")
                    if key in seen_tools:
                        continue
                    seen_tools.add(key)
                    events.on_tool(block.get("name", "?"), block.get("input") or {})
            return

        if kind == "system" and event.get("subtype") == "init":
            self.active_model = event.get("model", "") or self.active_model
            return

        if kind == "result":
            usage = event.get("usage") or {}
            self.last_tokens = sum(
                int(usage.get(key) or 0)
                for key in ("input_tokens", "output_tokens",
                            "cache_read_input_tokens",
                            "cache_creation_input_tokens")
            )
            if event.get("is_error"):
                events.on_error(str(event.get("result", "erreur inconnue")))


def _explain(code: int, stderr: str) -> str:
    lowered = stderr.lower()
    if "not logged in" in lowered or "authentication" in lowered:
        return (
            "Le CLI `claude` n'est pas connecté.\n"
            "   Lance `claude` dans un terminal, connecte-toi, puis reviens."
        )
    if "usage limit" in lowered or "rate limit" in lowered:
        return "Limite d'usage de ton abonnement atteinte. Réessaie plus tard."
    detail = stderr.splitlines()[-1] if stderr else f"code {code}"
    return f"`claude` s'est arrêté : {detail}"
