"""The host side of the kernel: start it, feed it cells, answer its calls.

Two jobs. The first is plumbing — a subprocess, a pipe, a timeout. The
second is the one that matters: when a cell calls `rlm()`, this is what
decides whether that call happens, and pays for it.

Prime enforces recursion depth in the runtime the agent shares. Thot
enforces it here, in the parent, because a limit the child can edit is not
a limit — and the child is executing code from the repository under audit.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from thot.kernel.protocol import (
    EXEC,
    HOST,
    READY,
    REPLY,
    RESULT,
    SHUTDOWN,
    Outcome,
    decode,
    encode,
)

# A cell is not a conversation: a loop that calls rlm() a thousand times is
# a runaway, not an ambition.
MAX_CALLS_PER_CELL = 8
MAX_CALLS_PER_KERNEL = 40
DEFAULT_TIMEOUT = 120


class KernelError(RuntimeError):
    """The kernel could not be started, or died."""


@dataclass
class Kernel:
    """One persistent Python namespace, in a process of its own."""

    root: Path
    engine: object | None = None       # thot.engine.base.Engine
    harness: object | None = None      # thot.harness.Harness
    sandbox: object | None = None      # runs the worker inside a container
    max_calls: int = MAX_CALLS_PER_KERNEL
    calls_made: int = 0
    thot_available: bool = False
    _process: subprocess.Popen | None = field(default=None, init=False)
    _counter: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    # -- lifecycle -------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _command(self) -> list[str]:
        """Where the namespace lives. In the container when there is one."""
        if self.sandbox is not None and getattr(self.sandbox, "name", "") == "docker":
            # The worker is stdlib-only on purpose, so it can be inlined into
            # a container where Thot is not installed. What it loses there is
            # the repository map; `rlm()` still works, because that is a call
            # back to this process over the same pipe.
            source = Path(__file__).with_name("worker.py").read_text(encoding="utf-8")
            return self.sandbox.command_line(
                f"python3 -c {shlex.quote(source)}", interactive=True
            )
        return [sys.executable, "-m", "thot.kernel.worker"]

    def start(self) -> "Kernel":
        if self.running:
            return self

        import os

        environment = dict(os.environ, THOT_ROOT=str(self.root))
        try:
            self._process = subprocess.Popen(
                self._command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
                cwd=str(self.root), env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise KernelError(f"le noyau n'a pas démarré : {exc}") from exc

        first = self._readline(timeout=30)
        if first is None or first.get("op") != READY:
            self.stop()
            raise KernelError("le noyau n'a pas répondu au démarrage")
        self.thot_available = bool(first.get("thot"))
        return self

    def stop(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        try:
            if process.poll() is None and process.stdin:
                process.stdin.write(encode({"op": SHUTDOWN}))
                process.stdin.flush()
            process.wait(timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            process.kill()

    def describe(self) -> str:
        where = "conteneur" if (self.sandbox is not None
                                and getattr(self.sandbox, "name", "") == "docker") \
            else "processus séparé"
        api = "carte de Thot disponible" if self.thot_available else "Python seul"
        return f"{where} · {api} · {self.calls_made}/{self.max_calls} appels rlm"

    # -- talking to it ---------------------------------------------------

    def _readline(self, *, timeout: float) -> dict | None:
        """Read one message, giving up rather than hanging for ever."""
        assert self._process is not None and self._process.stdout is not None
        holder: list[str] = []

        def pump() -> None:
            line = self._process.stdout.readline()
            if line:
                holder.append(line)

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        thread.join(timeout)
        if not holder:
            return None
        return decode(holder[0])

    def _write(self, message: dict) -> None:
        if not self.running or self._process.stdin is None:
            raise KernelError("le noyau n'est pas en marche")
        self._process.stdin.write(encode(message))
        self._process.stdin.flush()

    def execute(self, code: str, *, timeout: int = DEFAULT_TIMEOUT) -> Outcome:
        """Run one cell, answering whatever it asks for along the way."""
        with self._lock:
            if not self.running:
                self.start()
            self._counter += 1
            cell_id = f"c{self._counter}"
            self._write({"op": EXEC, "id": cell_id, "code": code})

            calls_here = 0
            while True:
                message = self._readline(timeout=timeout)
                if message is None:
                    self.stop()
                    return Outcome(error=f"Cellule interrompue après {timeout} s "
                                         f"— le noyau a été redémarré.")

                if message.get("op") == RESULT:
                    return Outcome(
                        stdout=str(message.get("stdout") or ""),
                        value=str(message.get("value") or ""),
                        error=str(message.get("error") or ""),
                        calls=tuple(message.get("calls") or ()),
                    )

                if message.get("op") != HOST:
                    continue

                calls_here += 1
                reply = self._serve(message, calls_here)
                self._write(reply)

    # -- what a cell may ask for -----------------------------------------

    def _serve(self, message: dict, calls_here: int) -> dict:
        kind = str(message.get("kind") or "")
        payload = message.get("payload") or {}
        answer: dict = {"op": REPLY, "for": message.get("id")}

        if kind == "rlm":
            text, error = self._rlm(payload, calls_here)
            if error:
                answer["error"] = error
            else:
                answer["result"] = {"text": text}
            return answer

        if kind == "harness":
            answer["result"] = self._harness(payload)
            return answer

        answer["error"] = f"demande inconnue : {kind}"
        return answer

    def _rlm(self, payload: dict, calls_here: int) -> tuple[str, str]:
        """Delegate one question to a fresh model instance.

        Every refusal below is a limit the cell cannot lift, because the
        cell is running code from the repository under audit.
        """
        if calls_here > MAX_CALLS_PER_CELL:
            return "", (f"rlm() refusé : plus de {MAX_CALLS_PER_CELL} appels "
                        f"dans une seule cellule.")
        if self.calls_made >= self.max_calls:
            return "", (f"rlm() refusé : budget de {self.max_calls} appels "
                        f"épuisé pour ce noyau.")
        if self.engine is None:
            return "", "rlm() indisponible : aucun moteur connecté."

        prompt = str(payload.get("prompt") or "").strip()
        if not prompt:
            return "", "rlm() attend une question."

        from thot.engine import AgentTask

        self.calls_made += 1
        task = AgentTask(
            id=f"rlm:{self.calls_made}",
            instructions=prompt,
            context=str(payload.get("context") or ""),
            tier=str(payload.get("tier") or "standard"),
        )
        try:
            result = self.engine.run(task)
        except Exception as exc:
            return "", f"rlm() a échoué : {exc}"
        if not result.ok:
            return "", f"rlm() a échoué : {result.error}"
        return result.text, ""

    def _harness(self, payload: dict) -> dict:
        if self.harness is None:
            return {"id": ""}
        action = str(payload.get("action") or "")
        if action == "remember":
            entry = self.harness.remember(
                title=str(payload.get("title") or ""),
                content=str(payload.get("content") or ""),
                kind=str(payload.get("kind") or "memory"),
            )
            return {"id": entry.id}
        return {"id": ""}
