"""Run audit tasks through Prime Agent, one-shot.

`prime-agent -p --mode json` prints a JSON event stream and exits. Unlike
Hermes's one-shot mode it carries real token counts and a cost estimate, so
this is the one engine whose `/cost` figures are measured rather than absent.

Prime is a TypeScript program; Thot drives its CLI and never imports it.
"""

from __future__ import annotations

import json
import subprocess

from thot.engine import process as process_group
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from thot.engine.base import AgentResult, AgentTask, EngineCapabilities, extract_json
from thot.llm.base import Usage

SYSTEM = (
    "Tu es un auditeur de code au sein de Thot. Tu réponds de façon factuelle "
    "et vérifiable, sans hypothèse invérifiable. Si une information manque pour "
    "conclure, tu le dis explicitement plutôt que de supposer."
)

DEFAULT_PARALLEL = 4

TIER_THINKING = {"cheap": "low", "standard": "medium", "deep": "high"}

MAX_PROMPT = 100_000


@dataclass
class PrimeEngine:
    root: Path
    max_parallel: int = DEFAULT_PARALLEL
    system: str = SYSTEM
    timeout: int = 600

    @staticmethod
    def available() -> bool:
        from thot.fusion.locate import prime_command

        return prime_command() is not None

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="prime",
            max_parallel=self.max_parallel,
            tiering=True,
            stateful=False,
        )

    def _command(self, task: AgentTask, prompt: str) -> list[str]:
        from thot.fusion.locate import prime_command

        base = prime_command()
        if base is None:
            raise FileNotFoundError(
                "Prime est introuvable ou non compilé — "
                "`npm install && npm run build` dans prime/"
            )
        command = [
            *base,
            "-p",
            "--mode", "json",
            "--no-session",  # an audit probe is not a conversation to resume
            "--cwd", str(self.root),
            "--append-system-prompt", self.system,
        ]
        thinking = TIER_THINKING.get(task.tier)
        if thinking:
            command += ["--thinking", thinking]
        # `--` first: an audit prompt can start with a dash, and without this
        # Prime would read the beginning of the question as a flag.
        command += ["--", prompt]
        return command

    def run(self, task: AgentTask) -> AgentResult:
        prompt = task.prompt()
        if len(prompt) > MAX_PROMPT:
            return AgentResult(
                task_id=task.id,
                error=f"prompt trop long pour la ligne de commande "
                      f"({len(prompt)} caractères, maximum {MAX_PROMPT})",
            )

        try:
            command = self._command(task, prompt)
        except FileNotFoundError as exc:
            return AgentResult(task_id=task.id, error=str(exc))

        # stdin closed, and the child in its own process group: an engine
        # task is non-interactive by definition, and a task that runs past
        # its budget must take its children with it rather than leave them
        # running for hours.
        try:
            completed = process_group.run(
                command, cwd=str(self.root), timeout=self.timeout
            )
        except process_group.Timeout as exc:
            return AgentResult(task_id=task.id, error=str(exc))
        except OSError as exc:
            return AgentResult(task_id=task.id, error=f"lancement impossible : {exc}")

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip().splitlines()
            return AgentResult(
                task_id=task.id,
                error=detail[-1] if detail else f"code {completed.returncode}",
            )

        return self._parse(task, completed.stdout or "")

    def _parse(self, task: AgentTask, stdout: str) -> AgentResult:
        text = ""
        usage = Usage()

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue

            # Every message event carries the whole message, so the last one
            # wins: no need to reassemble the deltas.
            if event.get("type") in {"turn_end", "message_end", "agent_end"}:
                message = event.get("message")
                if isinstance(message, dict) and message.get("role") == "assistant":
                    text = _text_of(message) or text
                    usage = _usage_of(message) or usage
                for message in event.get("messages") or []:
                    if isinstance(message, dict) and message.get("role") == "assistant":
                        text = _text_of(message) or text
                        usage = _usage_of(message) or usage

        text = text.strip()
        if not text:
            return AgentResult(task_id=task.id, error="réponse vide de Prime")

        data = extract_json(text) if task.schema else None
        if task.schema and data is None:
            return AgentResult(
                task_id=task.id, text=text, usage=usage,
                error="réponse non conforme au schéma attendu",
            )
        return AgentResult(task_id=task.id, text=text, data=data, usage=usage)

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        if not tasks:
            return []
        if len(tasks) == 1 or self.max_parallel <= 1:
            return [self.run(task) for task in tasks]
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            return list(pool.map(self.run, tasks))


def _text_of(message: dict) -> str:
    blocks = message.get("content")
    if not isinstance(blocks, list):
        return ""
    return "".join(
        str(block.get("text", ""))
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    )


def _usage_of(message: dict) -> Usage | None:
    counts = message.get("usage")
    if not isinstance(counts, dict):
        return None
    # Cache reads are input the user paid for once and is now reusing. They
    # belong in the input column: leaving them out would report a 6000-token
    # turn as costing two.
    read = int(counts.get("cacheRead") or 0)
    written = int(counts.get("cacheWrite") or 0)
    return Usage(
        input_tokens=int(counts.get("input") or 0) + read + written,
        output_tokens=int(counts.get("output") or 0),
    )
