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

from thot.engine import process as process_group
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

# No tier flag: `hermes -z` has nowhere to put one. `--reasoning` is declared
# on the top-level parser, so argparse takes it and nothing complains, but the
# one-shot dispatch never forwards it — `_run_and_exit_oneshot` calls
# `run_oneshot(model=, provider=, toolsets=, skills=, usage_file=)`, and
# `_run_agent` then builds its `AIAgent` with no `reasoning_config` at all, so
# not even the user's own `agent.reasoning_effort` applies. Sending the flag
# priced a `deep` pass that never happened. `-m/--model` is the only lever
# `-z` honours, and naming a model would override what the user configured in
# their own agent — so Hermes declares no tiering instead. Prime keeps its
# `--thinking` map, which is wired end to end.

# execve fails with E2BIG well before this, and a truncated audit prompt
# would produce a confident answer about the wrong code. Refuse instead.
MAX_PROMPT = 100_000

# Hermes enables a dozen toolsets by default. An audit needs one.
TOOLSETS = "file"


@dataclass
class HermesEngine:
    root: Path
    max_parallel: int = DEFAULT_PARALLEL
    system: str = SYSTEM
    timeout: int = 600
    # Which of Hermes's dozen toolsets this engine is allowed. `file` for an
    # audit — see `_command`. A loop that has to run the test suite it is
    # judged by needs `terminal` too, and says so by asking for it here
    # rather than by widening the constant for everybody.
    toolsets: str = TOOLSETS


    @staticmethod
    def available() -> bool:
        from thot.fusion.locate import hermes_command

        return hermes_command() is not None

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="hermes",
            max_parallel=self.max_parallel,
            tiering=False,  # `-z` forwards no effort level; see above
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
        # File operations only. An audit has no business holding a terminal,
        # a browser, a code interpreter or an image generator, and every one
        # of those is enabled by default. `file` keeps the capability a
        # refutation needs: going to look at the code it rests on, which is
        # usually not in the excerpt.
        #
        # What this does NOT do is make the probe read-only. Measured, after
        # claiming otherwise: `file` is "File Operations", reads and writes
        # alike, and `--safe-mode` turns off customisations rather than
        # permissions. Hermes has no read-only mode. This narrows the blast
        # radius; it does not close it, and `thot doctor --agents` says so.
        return [*base, "-z", prompt, "--in", str(self.root),
                "-t", self.toolsets]

    def _anchor(self) -> str:
        """Where the work is — stated in the prompt, not left to a flag.

        `--in DIR` is read in `cmd_chat` and nowhere else. One-shot dispatch
        calls `_run_and_exit_oneshot` and exits before that code runs, so the
        flag parses, is accepted, and is never applied. Measured, not assumed:
        `hermes -z 'pwd' --in <repo> -t terminal` answers with the home
        directory. Nor does `Popen(cwd=...)` survive — Hermes moves itself.

        Prime honours `--cwd` (measured the same way), so the two engines
        disagree, and only one of them says so.

        The consequence is silent: an engine landing in the wrong tree does
        not fail, it answers confidently about other code. Callers happen to
        pass the root today — `context_brief` puts it on the first line of
        every brief — but a caller that forgets gets a fluent wrong answer,
        which is the worst failure an auditor can have. So the root travels
        in the prompt, where nothing downstream can drop it.

        The flag stays on the command line: it costs nothing, and it carries
        the intent the day the one-shot path honours it.
        """
        return (f"Dépôt de travail : {self.root}\n"
                "Les chemins relatifs partent de cette racine.")

    def run(self, task: AgentTask) -> AgentResult:
        # No system-prompt flag in one-shot mode, so the instruction rides at
        # the head of the prompt itself.
        prompt = f"{self.system}\n\n{self._anchor()}\n\n{task.prompt()}"
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
        return process_group.parallel_map(
            self.run, tasks, max_workers=self.max_parallel
        )
