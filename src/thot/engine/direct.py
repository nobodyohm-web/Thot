"""Run agent tasks straight against a provider.

The fallback engine: no kernel, no subagents, just the configured backend and
a thread pool. Works on a bare machine and in CI, which is exactly when the
fancier engines are unavailable.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from thot.engine.base import AgentResult, AgentTask, EngineCapabilities, extract_json
from thot.llm.base import Message, Provider

SYSTEM = (
    "Tu es un auditeur de code. Tu réponds de façon factuelle et vérifiable, "
    "sans hypothèse invérifiable. Si une information manque, tu le dis."
)


@dataclass
class DirectEngine:
    provider: Provider
    max_parallel: int = 4
    system: str = SYSTEM

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name=f"direct:{getattr(self.provider, 'name', '?')}",
            max_parallel=self.max_parallel,
            tiering=False,
            stateful=False,
        )

    def run(self, task: AgentTask) -> AgentResult:
        try:
            reply = self.provider.complete(
                system=self.system,
                messages=[Message(role="user", content=task.prompt())],
                tools=[],
            )
        except Exception as exc:  # a task failure is data, not a crash
            return AgentResult(task_id=task.id, error=str(exc))

        text = reply.message.content
        data = extract_json(text) if task.schema else None
        if task.schema and data is None:
            return AgentResult(
                task_id=task.id,
                text=text,
                error="réponse non conforme au schéma attendu",
                usage=reply.usage,
            )
        return AgentResult(task_id=task.id, text=text, data=data, usage=reply.usage)

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        if not tasks:
            return []
        if len(tasks) == 1 or self.max_parallel <= 1:
            return [self.run(task) for task in tasks]
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            return list(pool.map(self.run, tasks))
