"""What a chat is allowed to ask Thot to do.

A closed set, and the closure is the point. Hermes's gateway hands a
message to a general agent that can run shell commands; that is right for
an assistant you live with and wrong for something reachable by anyone who
learns a bot token.

Three rules hold here:

* no shell, no file writes, no arbitrary paths — the verbs below are all
  there is, and none of them takes code;
* an audit can only target a repository already registered with
  `thot schedule add`, so the blast radius is what the user already chose;
* the sender must be on the channel's allowlist, checked before this module
  is reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from thot.contracts import Finding
from thot.gateway import render

HELP = """Thot — commandes disponibles

status            les audits programmés, et leur dernier passage
audit [nom]       relancer un audit programmé (défaut : le premier)
findings [n]      la liste, ou le détail du finding n
verdict n refute|accept|fixed <raison>
help              ceci

Aucune commande n'exécute de code ni n'écrit de fichier."""


@dataclass
class Board:
    """What the gateway remembers between two messages: the last report.

    `verdict 2` has to mean something, and nobody types a sixteen-character
    hash into a chat.
    """

    findings: list[Finding] = field(default_factory=list)
    root: str = ""

    def remember(self, findings: list[Finding], root: str) -> None:
        self.findings = list(findings)
        self.root = root


def _jobs():
    from thot.schedule import jobs

    return jobs.load()


def _status() -> str:
    from thot.memory import build_memory

    jobs = _jobs()
    if not jobs:
        return ("Aucun audit programmé.\n"
                "`thot schedule add <nom> <chemin> --every daily` sur la machine.")

    lines = ["Audits programmés :"]
    for job in jobs:
        lines.append(f"· {job.name} — {job.root} ({job.schedule}, seuil {job.threshold})")

    memory = build_memory(jobs[0].root if jobs else None)
    try:
        decided = len(memory.all_verdicts())
    finally:
        getattr(memory, "close", lambda: None)()
    lines.append(f"\n{decided} décision(s) mémorisée(s).")
    return "\n".join(lines)


def _audit(name: str, board: Board) -> str:
    """Run a registered job now. Unregistered paths are refused by design."""
    from thot.memory import build_memory
    from thot.paths import run_store
    from thot.pipeline import run_audit
    from thot.store.db import Store

    jobs = _jobs()
    if not jobs:
        return "Aucun audit programmé — rien à lancer depuis ici."

    chosen = next((j for j in jobs if j.name == name), None) if name else jobs[0]
    if chosen is None:
        known = ", ".join(j.name for j in jobs)
        return f"Aucun audit nommé « {name} ». Connus : {known}."

    store = Store.open(run_store())
    memory = build_memory(chosen.root)
    try:
        result = run_audit(
            Path(chosen.root), store,
            require_authorization=True, memory=memory,
        )
    except Exception as exc:  # a broken repo must not take the gateway down
        return f"L'audit de {chosen.name} a échoué : {exc}"
    finally:
        store.close()
        getattr(memory, "close", lambda: None)()

    board.remember(result.findings, chosen.root)
    return render.report(result.findings, root=chosen.root, title=chosen.name)


def _findings(argument: str, board: Board) -> str:
    if not board.findings:
        return "Rien en mémoire — lance `audit` d'abord."
    if argument.isdigit():
        index = int(argument)
        if not 1 <= index <= len(board.findings):
            return f"Il n'y a que {len(board.findings)} finding(s)."
        return render.detail(index, board.findings[index - 1])
    return render.report(board.findings, root=board.root, title="Findings",
                         shown=10)


def _verdict(argument: str, board: Board, author: str) -> str:
    from thot.memory import Decision, Verdict, build_memory
    from thot.plugins import notify_verdict

    parts = argument.split(maxsplit=2)
    if len(parts) < 3 or not parts[0].isdigit():
        return "Usage : verdict <n> refute|accept|fixed <raison>"
    if not board.findings:
        return "Rien en mémoire — lance `audit` d'abord."

    index = int(parts[0])
    if not 1 <= index <= len(board.findings):
        return f"Il n'y a que {len(board.findings)} finding(s)."

    decision = Decision.parse(parts[1])
    if decision is None:
        return "Décision inconnue : refute, accept ou fixed."

    finding = board.findings[index - 1]
    verdict = Verdict.of(finding, decision, parts[2], author or "gateway")
    memory = build_memory(board.root or None)
    try:
        memory.remember(verdict)
    finally:
        getattr(memory, "close", lambda: None)()
    notify_verdict(verdict)

    return (f"{finding.rule} à {finding.location.path}:{finding.location.line} "
            f"— {decision.value}\nRetenu tant que ce code ne change pas.")


def handle(verb: str, argument: str, *, board: Board, author: str = "") -> str:
    """Run one command. Unknown verbs get the help, never an interpretation."""
    if verb in {"help", "aide", "start", "?"}:
        return HELP
    if verb in {"status", "état", "etat"}:
        return _status()
    if verb in {"audit", "scan"}:
        return _audit(argument, board)
    if verb in {"findings", "finding", "liste"}:
        return _findings(argument, board)
    if verb in {"verdict", "verdicts"}:
        return _verdict(argument, board, author)
    return f"Commande inconnue : {verb}\n\n{HELP}"
