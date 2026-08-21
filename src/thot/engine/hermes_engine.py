"""Run audit tasks through Hermes Agent, one-shot.

`hermes -z` sends a single prompt and prints only the final response: no
banner, no spinner, no tool previews. That is exactly the shape an engine
needs, and it means Thot drives Hermes the way a user would rather than
reaching inside it — Hermes keeps its own tools, its own memory, its own
credentials, and Thot never holds a token.

Hermes reports no token count in one-shot mode, so `usage` comes back empty.
An empty count is the honest answer; inventing one would put a made-up
number in `/cost`.
"""

from __future__ import annotations

import subprocess

from thot.engine import process as process_group
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from thot.engine.base import AgentResult, AgentTask, EngineCapabilities, extract_json

SYSTEM = (
    "Tu es un auditeur de code au sein de Thot. Tu réponds de façon factuelle "
    "et vérifiable, sans hypothèse invérifiable. Si une information manque pour "
    "conclure, tu le dis explicitement plutôt que de supposer."
)

# Hermes is one agent with one session per call, not an API farm. Four at a
# time is what a subscription tolerates without tripping rate limits.
DEFAULT_PARALLEL = 4

# `--reasoning` rather than `-m`: the tier is about how hard to think, and
# picking a model by name would override whatever the user configured.
TIER_REASONING = {"cheap": "minimal", "deep": "high"}

# execve fails with E2BIG well before this, and a truncated audit prompt
# would produce a confident answer about the wrong code. Refuse instead.
MAX_PROMPT = 100_000


@dataclass
class HermesEngine:
    root: Path
    max_parallel: int = DEFAULT_PARALLEL
    system: str = SYSTEM
    timeout: int = 600

    @staticmethod
    def available() -> bool:
        from thot.fusion.locate import hermes_command

        return hermes_command() is not None

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="hermes",
            max_parallel=self.max_parallel,
            tiering=True,
            stateful=False,
            reports_usage=False,  # `-z` prints the answer and nothing else
        )

    def _command(self, task: AgentTask, prompt: str) -> list[str]:
        from thot.fusion.locate import hermes_command

        base = hermes_command()
        if base is None:
            raise FileNotFoundError(
                "Hermes est introuvable — `uv sync` à la racine du dépôt"
            )
        command = [*base, "-z", prompt, "--in", str(self.root)]
        reasoning = TIER_REASONING.get(task.tier)
        if reasoning:
            command += ["--reasoning", reasoning]
        return command

    def run(self, task: AgentTask) -> AgentResult:
        # No system-prompt flag in one-shot mode, so the instruction rides at
        # the head of the prompt itself.
        prompt = f"{self.system}\n\n{task.prompt()}"
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

        text = (completed.stdout or "").strip()
        if not text:
            return AgentResult(task_id=task.id, error="réponse vide de Hermes")

        data = extract_json(text) if task.schema else None
        if task.schema and data is None:
            return AgentResult(
                task_id=task.id, text=text,
                error="réponse non conforme au schéma attendu",
            )
        return AgentResult(task_id=task.id, text=text, data=data)

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        if not tasks:
            return []
        if len(tasks) == 1 or self.max_parallel <= 1:
            return [self.run(task) for task in tasks]
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            return list(pool.map(self.run, tasks))
