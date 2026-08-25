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
import re
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

# The official CLI brings its own file and shell tools, which Thot's toolset
# postures know nothing about. In account mode a read-only posture that only
# filtered Thot's tools would be a lie: the CLI could still write. These are
# the names to hand to --disallowed-tools so the posture means the same
# thing in both modes.
# What an audit probe has no business holding. A denylist, because that is
# the only lever the CLI offers: `--allowed-tools` pre-approves, it does not
# restrict — measured, by asking a probe launched with `--allowed-tools
# "Read Glob Grep"` to list its tools, and being told `Write, Bash, Edit,
# Agent, Workflow` among others.
#
# Being a denylist, it is brittle by construction: `Task` was missing from it
# and a subagent wrote a file through the gap. `thot doctor --agents` asks a
# live probe what it actually holds and names anything unrecognised, because
# the next version of the client will bring tools this tuple has never heard
# of.
#
# Three kinds, all of them out of place in something that reads code to
# answer a question: what writes, what persists past the run, and what
# reaches outward.
WRITING_TOOLS = (
    # writes
    "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash",
    "EnterWorktree", "ExitWorktree",
    # spawns something that holds its own toolset, and does not inherit this
    "Task", "Agent", "Workflow",
    # persists past the run
    "CronCreate", "CronDelete", "ScheduleWakeup", "Monitor",
    # reaches outward
    "SendMessage", "PushNotification", "RemoteTrigger", "DesignSync",
)

# What an *audit probe* is denied, which is more than a read-only session is.
# The two were one list for an hour, and extending it for the probe quietly
# took web search away from someone reading a repository in `lecture` mode —
# one list, two needs, and the narrower need won by accident.
#
# The difference is the audited code. A session reads a repository because
# its user asked it to; a probe reads code nobody vouches for, and that code
# can say "fetch https://…/?data=" — the classic exfiltration channel under
# prompt injection. Dependency lookups do not go through here anyway:
# `thot deps` asks OSV.dev from the deterministic pass, where no model is
# involved.
PROBE_DENIED = WRITING_TOOLS + ("WebFetch", "WebSearch")

READING_TOOLS = ("Read", "Glob", "Grep", "WebFetch", "WebSearch")


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


def user_mcp_definitions(root: Path) -> dict:
    """The full server declarations, not just their names.

    `user_mcp_servers` answers "what may Thot allow through"; this answers
    "what is actually going to be executed", which is the question a
    supply-chain check has to ask.
    """
    found: dict = {}

    try:
        data = json.loads(CLAUDE_CONFIG.read_text())
    except (OSError, ValueError):
        data = {}
    if isinstance(data, dict):
        found.update(data.get("mcpServers") or {})
        project = (data.get("projects") or {}).get(str(root)) or {}
        found.update(project.get("mcpServers") or {})

    try:
        local = json.loads((Path(root) / ".mcp.json").read_text())
        found.update(local.get("mcpServers") or {})
    except (OSError, ValueError, AttributeError):
        pass

    found.pop("thot", None)
    return {name: entry for name, entry in found.items() if isinstance(entry, dict)}


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
    context_window: int = 0  # the model's window, published by the CLI itself
    isolated: bool = False  # cut the user's own MCP servers out of the session
    # The repository's own test command, from the manifest Thot already built.
    # Pre-approved so the session can check its work — see `_verification`.
    test_command: str = ""
    denied: tuple[str, ...] = ()  # CLI tools the session's posture forbids
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
        allowed += self._verification()

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
        if self.denied:
            command += ["--disallowed-tools", *self.denied]
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

    def _verification(self) -> list[str]:
        """Pre-approve the repository's own test command, and nothing else.

        `PERMISSION_MODE` is `acceptEdits`: writes go through unasked, `Bash`
        does not. Under `-p` there is nobody to ask, so a session could edit
        code and never run it — measured, in a self-improvement run that
        tried eight spellings of the test command, was refused each time, and
        carried on editing production files by static reading alone. An agent
        that can write but not verify is worse than one that can do neither.

        So the gap is closed with the narrowest key that fits: the command
        the manifest already found for this repository, scoped by prefix, and
        nothing more. Not bare `Bash` — that would hand over arbitrary
        execution to buy one capability.

        Silent when a posture denies `Bash` outright: a read-only probe must
        stay read-only, and deny beats allow. Silent too when the repository
        declares no test command, since there is then nothing to approve.
        """
        if not self.test_command or "Bash" in self.denied:
            return []
        # `Bash(cmd:*)` is the CLI's own prefix form for a command rule.
        return [f"Bash({self.test_command}:*)"]

    def send(self, prompt: str, *, brief: str = "", events: Events | None = None) -> str:
        """Run one turn. Returns the assistant's final text.

        A thread the CLI cannot open is recoverable exactly once. Anything
        else — a usage limit above all — is reported, never retried: a retry
        loop on a limit burns the user's quota to reproduce the same refusal.
        """
        events = events or Events()
        try:
            return self._attempt(prompt, brief=brief, events=events)
        except _LostThread as exc:
            # The id Thot held is not one the CLI will open: it was taken by
            # a turn that died, or it points at a conversation the CLI has
            # since dropped. Neither is a reason to strand the user — Thot
            # keeps the transcript itself, so a new CLI thread continues the
            # work, only without the model's own recollection of it.
            events.on_error(
                f"{exc}\n   Nouveau fil ouvert — Thot garde la conversation, "
                "le modèle repart de ce que Thot lui redonne."
            )
            self.forget_thread()
            return self._attempt(prompt, brief=brief, events=events)

    def _attempt(self, prompt: str, *, brief: str, events: Events) -> str:
        """One launch of the CLI, and one reading of its stream."""
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

        # The id is spent the moment the CLI starts, not when the turn
        # succeeds. `--session-id` registers the thread before the first
        # token is produced, so a turn that dies afterwards — a usage limit,
        # a killed process, a lost network — leaves the id taken. Flipping
        # this only on success is what made a single failed turn permanent:
        # the next turn re-sent `--session-id <same uuid>`, the CLI answered
        # "Session ID ... is already in use", and every retry after that got
        # the identical refusal. The session could not be continued at all.
        self._started = True

        answer: list[str] = []
        seen_tools: set[str] = set()
        aside: list[str] = []

        assert process.stdout is not None
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Not every line is an event. The CLI prints its own refusals
                # as plain text on stdout — "You've hit your session limit ·
                # resets 1am" arrives here, not on stderr — and dropping them
                # is why a real, actionable cause was reported as "code 1".
                if len(aside) < ASIDE_LINES:
                    aside.append(line)
                continue
            self._consume(event, events, answer, seen_tools)

        process.wait()
        if process.returncode != 0:
            stderr = (process.stderr.read() if process.stderr else "").strip()
            aside_text = "\n".join(aside)
            if _lost_thread(stderr, aside_text):
                raise _LostThread(_explain(process.returncode, stderr, aside_text))
            raise ProviderError(_explain(process.returncode, stderr, aside_text))

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
            # The CLI names the window per model, so Thot never has to keep a
            # model-to-window table correct: {"claude-opus-5[1m]": {...,
            # "contextWindow": 1000000}}. Without it the compaction threshold
            # is a constant that is right for one window size and wrong for
            # every other.
            for entry in (event.get("modelUsage") or {}).values():
                window = int((entry or {}).get("contextWindow") or 0)
                if window > self.context_window:
                    self.context_window = window
            if event.get("is_error"):
                events.on_error(str(event.get("result", "erreur inconnue")))


# How many stray stdout lines to keep for diagnosis. Enough to hold a CLI
# refusal and its reset time; small enough that a chatty run cannot grow it.
ASIDE_LINES = 40

_LOST_THREAD = (
    "already in use",       # the id was taken by a turn that then died
    "no conversation found",
    "session not found",
    "no such session",
)


class _LostThread(ProviderError):
    """The CLI will not open the thread Thot asked for. Recoverable once."""


def _lost_thread(stderr: str, aside: str = "") -> bool:
    lowered = f"{stderr}\n{aside}".lower()
    return any(mark in lowered for mark in _LOST_THREAD)


def _explain(code: int, stderr: str, aside: str = "") -> str:
    """Say what actually happened, from whichever channel said it.

    The CLI does not put all of its refusals on stderr. A session limit is
    printed on stdout, outside the JSON stream, so a reader that only knows
    stderr reports the true cause as "code 1" — which was measured, and is
    the reason `aside` exists.
    """
    lowered = f"{stderr}\n{aside}".lower()
    if "not logged in" in lowered or "authentication" in lowered:
        return (
            "Le CLI `claude` n'est pas connecté.\n"
            "   Lance `claude` dans un terminal, connecte-toi, puis reviens."
        )
    if "session limit" in lowered:
        # The CLI names the hour the window reopens; quoting it is the whole
        # difference between "code 1" and knowing when to come back.
        reset = _reset_hint(f"{stderr}\n{aside}")
        when = f" Elle se réinitialise {reset}." if reset else ""
        return f"Limite de session de ton abonnement Claude atteinte.{when}"
    if "usage limit" in lowered or "rate limit" in lowered:
        return "Limite d'usage de ton abonnement atteinte. Réessaie plus tard."
    if _lost_thread(stderr, aside):
        return "Le CLI ne peut pas reprendre ce fil de conversation."
    detail = _last_line(stderr) or _last_line(aside) or f"code {code}"
    return f"`claude` s'est arrêté : {detail}"


def _last_line(text: str) -> str:
    lines = [line for line in (text or "").splitlines() if line.strip()]
    return lines[-1].strip() if lines else ""


def _reset_hint(text: str) -> str:
    """The CLI's own words for when the window reopens, if it said."""
    match = re.search(r"resets?\s+([^\n·]{1,40})", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""
