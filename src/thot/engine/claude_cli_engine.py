"""Fan work out across parallel `claude -p` invocations, on the user's account.

This is the engine that makes a subscription behave like a fleet. Each task is
an independent, stateless call to the official CLI, so N analyses run at once
without any shared conversation — and without Thot ever holding a token or
impersonating a client.

The prompt goes over stdin, not argv: audit context routinely exceeds what an
argument list can carry, and `--allowed-tools` is variadic, so a trailing
positional prompt is silently swallowed.
"""

from __future__ import annotations

import json
import shutil
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

# A subscription is not an API farm: too many concurrent calls trip rate limits
# and make the whole run slower than a smaller pool would have been.
DEFAULT_PARALLEL = 4

TIER_MODELS = {"cheap": "haiku", "deep": "opus"}


@dataclass
class ClaudeCliEngine:
    root: Path
    max_parallel: int = DEFAULT_PARALLEL
    system: str = SYSTEM
    timeout: int = 300

    @staticmethod
    def available() -> bool:
        return shutil.which("claude") is not None

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="claude-cli",
            max_parallel=self.max_parallel,
            tiering=True,
            stateful=False,
        )

    def _command(self, task: AgentTask) -> list[str]:
        binary = shutil.which("claude")
        if not binary:
            raise FileNotFoundError("le CLI `claude` est introuvable")
        command = [
            binary,
            "-p",
            "--output-format", "stream-json",
            "--verbose",
            "--append-system-prompt", self.system,
        ]
        model = TIER_MODELS.get(task.tier)
        if model:
            command += ["--model", model]
        return command

    def run(self, task: AgentTask) -> AgentResult:
        try:
            command = self._command(task)
        except FileNotFoundError as exc:
            return AgentResult(task_id=task.id, error=str(exc))

        # In its own process group: `claude` runs tools of its own, and a
        # task killed for running long must not leave them behind.
        try:
            completed = process_group.run(
                command, cwd=str(self.root), timeout=self.timeout,
                stdin_text=task.prompt(),
            )
        except process_group.Timeout as exc:
            return AgentResult(task_id=task.id, error=str(exc))
        except OSError as exc:
            return AgentResult(task_id=task.id, error=f"lancement impossible : {exc}")

        if completed.returncode != 0:
            detail = (completed.stderr or "").strip().splitlines()
            return AgentResult(
                task_id=task.id,
                error=detail[-1] if detail else f"code {completed.returncode}",
            )

        return self._parse(task, completed.stdout)

    def _parse(self, task: AgentTask, stdout: str) -> AgentResult:
        text = ""
        blocks: list[str] = []
        usage = Usage()

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue

            kind = event.get("type")
            if kind == "assistant":
                for block in (event.get("message") or {}).get("content", []):
                    if block.get("type") == "text":
                        blocks.append(block.get("text", ""))
            elif kind == "result":
                if event.get("is_error"):
                    return AgentResult(
                        task_id=task.id,
                        error=str(event.get("result", "erreur inconnue")),
                    )
                text = str(event.get("result", ""))
                counts = event.get("usage") or {}
                usage = Usage(
                    input_tokens=int(counts.get("input_tokens", 0) or 0),
                    output_tokens=int(counts.get("output_tokens", 0) or 0),
                )

        text = text or "".join(blocks)
        if not text:
            return AgentResult(task_id=task.id, error="réponse vide du CLI")

        data = extract_json(text) if task.schema else None
        if task.schema and data is None:
            return AgentResult(
                task_id=task.id,
                text=text,
                error="réponse non conforme au schéma attendu",
                usage=usage,
            )
        return AgentResult(task_id=task.id, text=text, data=data, usage=usage)

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        if not tasks:
            return []
        if len(tasks) == 1 or self.max_parallel <= 1:
            return [self.run(task) for task in tasks]
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            return list(pool.map(self.run, tasks))
