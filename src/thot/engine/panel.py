"""The three agents on one audit: one argues a finding, another attacks it.

Thot, Hermes and Prime being available one at a time is not a fusion — it is
a choice of supplier. Three engines that do the same work interchangeably add
nothing to each other; you pick one and the other two idle.

This engine is the combination itself. It implements the same port as any
single backend, so `analyse` needs no knowledge of it, and it uses the two
phases that were already there:

- the probe is spread across every available agent, so a run costs the wall
  clock of the slowest one rather than the sum of all of them;
- the refutation of a finding is deliberately routed to a *different* agent
  than the one that argued it. An adversarial pass where the attacker is the
  same model that just committed to the scenario is a model marking its own
  homework. Here the attacker never is.

A member that fails a task does not cost the task: it is handed once to
another member. That is the "mutual reinforcement" made literal — Prime
covering for a Hermes that timed out, and the report saying so.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from thot.engine.base import AgentResult, AgentTask, Engine, EngineCapabilities

# `analyse` labels its tasks `probe:<finding id>` and `refute:<finding id>`.
# The panel reads that label rather than being told the phase, so it stays a
# plain Engine — nothing above it has to know a panel is running.
PROBE_PREFIX = "probe:"
REFUTE_PREFIX = "refute:"


def _subject(task_id: str) -> str:
    """The finding a task is about, whichever phase it belongs to."""
    return task_id.split(":", 1)[1] if ":" in task_id else task_id


@dataclass
class PanelEngine:
    """Several engines behaving as one, with a memory of who said what."""

    members: list[Engine]
    _who: dict[str, str] = field(default_factory=dict)
    _argued: dict[str, str] = field(default_factory=dict)
    _turn: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if not self.members:
            raise ValueError("Un panel a besoin d'au moins un moteur.")

    # -- identity --------------------------------------------------------

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(m.capabilities.name for m in self.members)

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="panel",
            max_parallel=sum(m.capabilities.max_parallel for m in self.members),
            tiering=any(m.capabilities.tiering for m in self.members),
            stateful=all(m.capabilities.stateful for m in self.members),
            # One member that cannot count tokens makes the panel's total a
            # guess, and a plausible-looking wrong figure is worse than none.
            reports_usage=all(
                m.capabilities.reports_usage for m in self.members
            ),
        )

    def who(self, task_id: str) -> str:
        """Which member actually answered — read back by the report.

        `capabilities.name` would say "panel" for every finding, which is
        exactly the information a panel exists to provide.
        """
        return self._who.get(task_id, "panel")

    # -- routing ---------------------------------------------------------

    def _assign(self, task: AgentTask) -> Engine:
        """Round-robin, except that a refutation avoids the arguer."""
        opposed = ""
        if task.id.startswith(REFUTE_PREFIX):
            opposed = self._argued.get(_subject(task.id), "")

        pool = [m for m in self.members if m.capabilities.name != opposed]
        if not pool:  # a panel of one: better a self-attack than no attack
            pool = list(self.members)

        member = pool[self._turn % len(pool)]
        self._turn += 1
        return member

    def _record(self, task: AgentTask, name: str) -> None:
        with self._lock:
            self._who[task.id] = name
            if task.id.startswith(PROBE_PREFIX):
                self._argued[_subject(task.id)] = name

    def _execute(self, member: Engine, task: AgentTask) -> AgentResult:
        result = member.run(task)
        name = member.capabilities.name
        if result.ok:
            self._record(task, name)
            return result

        # One stand-in, not a cascade: a task every agent refuses is a task
        # with a problem of its own, and trying all of them would triple the
        # cost of a systematic failure to learn nothing.
        stand_ins = [m for m in self.members if m.capabilities.name != name]
        if not stand_ins:
            self._record(task, name)
            return result

        index = self.members.index(member)
        stand_in = (self.members[index + 1:] + self.members[:index])[0]
        second = stand_in.run(task)
        if second.ok:
            self._record(task, stand_in.capabilities.name)
            return second

        self._record(task, name)
        return result

    # -- the port --------------------------------------------------------

    def run(self, task: AgentTask) -> AgentResult:
        return self._execute(self._assign(task), task)

    def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]:
        if not tasks:
            return []

        # Assigned up front, on this thread: routing reads a counter and the
        # record of who argued what, and neither wants a race.
        assignments = [(task, self._assign(task)) for task in tasks]

        workers = min(len(tasks), max(1, self.capabilities.max_parallel))
        if workers <= 1:
            return [self._execute(member, task) for task, member in assignments]

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(
                pool.map(lambda pair: self._execute(pair[1], pair[0]), assignments)
            )
