"""The child process: one Python namespace that survives between cells.

Prime Agent's central idea, ported — the agent writes Python and its
variables are still there next time. What changes here is where it runs.

Prime executes in an IPython kernel the agent effectively shares with the
host. Thot audits code it has every reason to distrust, so the namespace
lives in a **separate process**, always. An `exec()` inside Thot's own
process would hand audited code the credentials, the open databases and
the verdict store — strictly worse than `run_command`, which Thot already
took the trouble to put in a container.

Stdlib only, and no import of `thot` at module level: this same file is
executed inside the Docker sandbox, where Thot is not installed. What the
namespace offers degrades accordingly, and `available()` says so.
"""

from __future__ import annotations

import io
import json
import sys
import traceback
from contextlib import redirect_stderr, redirect_stdout

EXEC, PING, REPLY, SHUTDOWN = "exec", "ping", "reply", "shutdown"
RESULT, HOST, READY = "result", "host", "ready"

# How much a single cell may print back. The host truncates again for the
# model; this only stops a runaway loop from filling the pipe.
MAX_STDOUT = 200_000


def _send(message: dict) -> None:
    sys.__stdout__.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.__stdout__.flush()


def _read() -> dict | None:
    line = sys.__stdin__.readline()
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


class Host:
    """The way a cell asks Thot to do something it cannot do itself.

    Prime routes this over an ipykernel Comm; here it is the same pipe the
    cell's results travel on. The important half is identical: the child
    holds no credential, so a cell cannot spend the user's subscription
    except by asking, and the host decides.
    """

    def __init__(self) -> None:
        self._next = 0
        self.calls: list[str] = []

    def request(self, kind: str, payload: dict) -> dict:
        self._next += 1
        request_id = f"h{self._next}"
        self.calls.append(kind)
        _send({"op": HOST, "id": request_id, "kind": kind, "payload": payload})

        while True:
            message = _read()
            if message is None:
                raise RuntimeError("l'hôte a fermé la connexion")
            if message.get("op") == REPLY and message.get("for") == request_id:
                if message.get("error"):
                    raise RuntimeError(str(message["error"]))
                return message.get("result") or {}


def build_namespace(host: Host, root: str) -> dict:
    """What a cell starts with. Thot's map when it is reachable, else Python."""
    import pathlib

    namespace: dict = {
        "__name__": "__thot__",
        "ROOT": pathlib.Path(root),
        "host": host,
    }

    def rlm(prompt: str, *, tier: str = "standard", context: str = "") -> str:
        """Delegate a question to a fresh model instance and get its answer.

        The recursive half of Prime's RLM: a cell can decompose its own
        problem. Depth and budget are enforced by the host, not here — a
        limit the child could edit is not a limit.
        """
        answer = host.request("rlm", {"prompt": prompt, "tier": tier,
                                      "context": context})
        return str(answer.get("text") or "")

    namespace["rlm"] = rlm

    def remember(title: str, content: str, *, kind: str = "memory") -> str:
        """Persist something learned about this codebase, for later sessions."""
        answer = host.request("harness", {"action": "remember", "title": title,
                                          "content": content, "kind": kind})
        return str(answer.get("id") or "")

    namespace["remember"] = remember

    try:
        from thot.kernel.api import install
    except Exception:
        namespace["thot_available"] = False
    else:
        install(namespace, root)
        namespace["thot_available"] = True

    return namespace


def _value_of(code: str, namespace: dict):
    """Run the cell, and echo its last expression the way a REPL would.

    The statements always run. Only the trailing expression — when there is
    one — is evaluated separately so its value can be shown, which is what
    makes `x` on a line by itself print something.
    """
    import ast

    tree = ast.parse(code, mode="exec")  # a SyntaxError belongs to the caller
    trailing = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        trailing = tree.body.pop()

    if tree.body:
        exec(compile(tree, "<cellule>", "exec"), namespace)
    if trailing is None:
        return None, False

    value = eval(compile(ast.Expression(trailing.value), "<cellule>", "eval"),
                 namespace)
    return value, True


def _clean_traceback() -> str:
    """The cell's own frames, without the machinery that ran it."""
    kept: list[str] = []
    skip_next = False
    for line in traceback.format_exc().splitlines():
        if line.lstrip().startswith("File ") and __file__ in line:
            skip_next = True   # drop the source line that follows too
            continue
        if skip_next and (line.startswith("    ") or line.strip().startswith("^")):
            continue
        skip_next = False
        kept.append(line)
    return "\n".join(kept)


def run_cell(code: str, namespace: dict, host: Host) -> dict:
    out, err = io.StringIO(), io.StringIO()
    value_text = ""
    error = ""
    before = len(host.calls)

    try:
        with redirect_stdout(out), redirect_stderr(err):
            value, had_value = _value_of(code, namespace)
            if had_value and value is not None:
                value_text = repr(value)
                if len(value_text) > 4000:
                    value_text = value_text[:4000] + "…"
    except SyntaxError as exc:
        # A REPL reports the offending line, not the frames of the parser
        # that found it.
        marker = " " * (max(1, (exc.offset or 1)) - 1) + "^"
        error = (f"SyntaxError : {exc.msg}\n"
                 f"  {(exc.text or '').rstrip()}\n  {marker}")
    except SystemExit:
        error = "SystemExit ignoré : la cellule ne peut pas arrêter le noyau."
    except BaseException:
        # The traceback is the useful part, but the frames inside this file
        # are the runner and never help — they point at worker.py when the
        # mistake is in the cell.
        error = _clean_traceback()[-4000:]

    printed = (out.getvalue() + err.getvalue())[:MAX_STDOUT]
    return {"op": RESULT, "stdout": printed, "value": value_text,
            "error": error, "calls": host.calls[before:]}


def serve(root: str) -> int:
    host = Host()
    namespace = build_namespace(host, root)
    _send({"op": READY, "thot": bool(namespace.get("thot_available"))})

    while True:
        message = _read()
        if message is None:
            return 0
        operation = message.get("op")

        if operation == SHUTDOWN:
            return 0
        if operation == PING:
            _send({"op": RESULT, "id": message.get("id"), "stdout": "",
                   "value": "pong", "error": "", "calls": []})
            continue
        if operation != EXEC:
            continue

        answer = run_cell(str(message.get("code") or ""), namespace, host)
        answer["id"] = message.get("id")
        _send(answer)


if __name__ == "__main__":
    import os

    raise SystemExit(serve(os.environ.get("THOT_ROOT") or os.getcwd()))
