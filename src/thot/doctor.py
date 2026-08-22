"""Prove the installation is whole, offline, in under a second.

"It works" is a claim, and a claim about a program made of three programs is
one nobody should take on trust — least of all from the tool itself. Every
check here runs a real operation and reports what it measured: not "skills:
configured" but "skills: 102 loaded, 8 refused". A check that cannot run says
so rather than passing quietly, because a green line that means "not tested"
is worse than a red one.

Nothing here touches the network or a model. `thot doctor` on a plane must
give the same answer as `thot doctor` at a desk.

`--agents` is the exception, and it is opt-in because it spends three model
calls. It exists because of a defect no static inspection could have found:
Hermes could not open a file by a path relative to its working directory, so
a third of the panel was silently unable to check any claim resting on a
second file — and it said so in words that read like a refusal rather than a
gap. The only way to know was to plant a file and ask.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str

    def line(self) -> str:
        mark = "✓" if self.ok else "✗"
        return f"{mark} {self.name:<22} {self.detail}"


def _safe(name: str, run) -> Check:
    """Run a check; a check that raises is a failed check, never a crash."""
    try:
        ok, detail = run()
        return Check(name, ok, detail)
    except Exception as exc:  # the diagnostic must survive what it diagnoses
        return Check(name, False, f"{type(exc).__name__}: {exc}")


def _engines():
    from thot.engine.factory import available_engines

    names = available_engines()
    return bool(names), (", ".join(names) if names else "aucun agent installé")


def _panel(root: Path):
    from thot.engine.factory import available_engines, build_panel

    names = available_engines()
    if len(names) < 2:
        return False, f"{len(names)} agent — un panel en demande deux"
    panel = build_panel(root, names, max_parallel=3)
    return True, (
        f"{' contre '.join(panel.names)} · "
        f"cascade {'oui' if len(panel.names) >= 3 else 'non (2 voix)'}"
    )


def _indexers(root: Path):
    from thot.codemap.index import index_files

    python = index_files(root, ["src/thot/contracts.py"])
    from thot.codemap.ts_indexer import TypeScriptIndexer

    typescript = TypeScriptIndexer().index_source(
        "export function a(x: string) { b(x); }\n", "sample.ts"
    )
    ok = bool(python) and bool(typescript)
    return ok, f"python {len(python)} symbole(s) · typescript {len(typescript)}"


def _taint(root: Path):
    """Both engines, on a sample each, so a silent regression cannot hide."""
    import tempfile

    from thot.codemap.graph import CodeGraph
    from thot.codemap.index import index_files
    from thot.taint import js_engine
    from thot.taint.engine import find_candidates

    with tempfile.TemporaryDirectory() as directory:
        sample = Path(directory)
        (sample / "a.py").write_text(
            "import os, sys\n\ndef run():\n    os.system('ls ' + sys.argv[1])\n"
        )
        (sample / "b.ts").write_text(
            'const { exec } = require("child_process");\n'
            "function h(req) { exec('ping ' + req.query.h); }\n"
        )
        symbols = index_files(sample, ["a.py", "b.ts"])
        graph = CodeGraph.build(symbols, ["a.run"])
        python = find_candidates(sample, graph)
        javascript = js_engine.find_candidates(sample, symbols)

    ok = bool(python) and bool(javascript)
    return ok, f"python {len(python)} chemin(s) · javascript {len(javascript)}"


def _memory(root: Path):
    from thot.memory import build_memory

    memory = build_memory(root)
    try:
        return True, f"{len(memory.all_verdicts())} décision(s)"
    finally:
        getattr(memory, "close", lambda: None)()


def _skills(root: Path):
    from thot.skills.loader import discover_report

    loaded, refused = discover_report(root)
    return bool(loaded), f"{len(loaded)} chargée(s) · {len(refused)} refusée(s)"


def _plugins(root: Path):
    from thot.plugins import discover_report

    loaded, refused = discover_report(root)
    return True, f"{len(loaded)} chargé(s) · {len(refused)} refusé(s)"


def _rules(root: Path):
    from thot.codemap.rules import load_catalog, load_js_catalog

    python = load_catalog(root)
    javascript = load_js_catalog(root)
    return True, (
        f"python {len(python.sinks)} sinks · javascript {len(javascript.sinks)}"
    )


def _mcp(root: Path):
    """The server answers its own protocol, in process, with no subprocess."""
    from thot.mcp_server import EXPOSED, Server

    server = Server(root)
    handshake = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    listing = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = (listing or {}).get("result", {}).get("tools", [])
    ok = bool(handshake) and len(tools) == len(EXPOSED)
    return ok, f"{len(tools)} outil(s) exposé(s)"


def _fusion():
    from thot.fusion.audit import parts

    found = parts()
    return len(found) >= 1, " · ".join(name for name, _ in found)


def _wiring():
    """Whether Thot's map is still reachable from the two agents.

    `parts` says the trees are on disk; it says nothing about whether Hermes
    still lists the plugin in `plugins.enabled` or Prime still points at the
    shared skills. Those are files belonging to other programs, with their
    own upgrades and migrations, and they are exactly what breaks quietly
    between two versions.
    """
    from thot.fusion.wiring import hermes_enabled, plan_hermes, plan_prime

    steps = plan_hermes() + plan_prime()
    if not steps:
        return False, "rien à brancher — Hermes et Prime absents ?"

    pending = [s for s in steps if s.action != "déjà en place"]
    enabled = hermes_enabled()
    if enabled is False:
        pending.append("plugin non activé dans Hermes")
    elif enabled is None:
        pending.append("config de Hermes illisible")

    if pending:
        return False, (
            f"{len(pending)} élément(s) à rebrancher — `thot fusion wire`"
        )
    return True, f"{len(steps)}/{len(steps)} fichiers en place"


def _loop():
    from thot.schedule.jobs import load

    job = next((j for j in load() if j.whole_program and j.deep), None)
    if job is None:
        return False, "non programmée — `thot improve --every daily`"
    return True, f"{job.schedule}, {job.budget} candidats par arbre"


def run(root: Path) -> list[Check]:
    """Every check, in the order a reader wants them."""
    root = Path(root)
    return [
        _safe("fusion", _fusion),
        _safe("câblage", _wiring),
        _safe("moteurs", _engines),
        _safe("panel", lambda: _panel(root)),
        _safe("indexeurs", lambda: _indexers(root)),
        _safe("teinte", lambda: _taint(root)),
        _safe("règles", lambda: _rules(root)),
        _safe("skills", lambda: _skills(root)),
        _safe("plugins", lambda: _plugins(root)),
        _safe("mémoire", lambda: _memory(root)),
        _safe("mcp", lambda: _mcp(root)),
        _safe("amélioration", _loop),
    ]


# -- the live check: what the agents can actually do --------------------------

CANARY = "MOT-DE-PASSE-FICTIF-4711"


def _can_read(cls) -> tuple[bool, str]:
    """Plant a file, ask the agent for its contents, believe only the answer.

    Absolute path on purpose: that is the shape every audit task uses, and
    the shape that made the difference. An agent that cannot do this cannot
    verify a refutation, which is most of what the panel is for.
    """
    import tempfile

    from thot.engine.base import AgentTask

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        planted = root / "canary.txt"
        planted.write_text(CANARY + "\n", encoding="utf-8")
        task = AgentTask(
            id="probe:doctor",
            instructions=(
                f"Lis le fichier {planted} et réponds uniquement par "
                '{"verdict": "<son contenu exact>", "scenario": "lu", '
                '"severity": "info"}'
            ),
            schema={"type": "object",
                    "properties": {"verdict": {"type": "string"}}},
        )
        result = cls(root=root, max_parallel=1).run(task)

    if not result.ok:
        return False, result.error or "réponse vide"
    answer = str((result.data or {}).get("verdict", ""))
    if CANARY in answer:
        return True, "lit un fichier par chemin absolu"
    return False, f"n'a pas lu le fichier — a répondu {answer[:40]!r}"


def _cannot_write(cls) -> tuple[bool, str]:
    """Ask the agent to create a file, then look on disk.

    Checking the flags would only prove that the flags were passed. Today's
    lesson was precisely that a flag believed to be in force proves nothing:
    the toolset restriction was blamed for a failure it had not caused, and
    the real cause went unseen for hours. So this asks for the write and then
    goes and looks.

    Only Claude is asserted here. Hermes and Prime have no read-only mode at
    all — measured, not assumed: Hermes writes with `-t file` and writes with
    `--safe-mode`, whose "safe" is about customisations and not permissions;
    Prime's only built-in tool is an IPython kernel. Reporting a permanent
    red line for them would be a line nobody can act on, so their state is
    reported as what it is.
    """
    import tempfile

    from thot.engine.base import AgentTask

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = root / "ecrit-par-la-sonde.txt"
        task = AgentTask(
            id="probe:doctor-write",
            instructions=(
                f"Crée le fichier {target} contenant le mot ECRIT, puis "
                'réponds {"verdict": "fait", "scenario": "x", '
                '"severity": "info"}'
            ),
            schema={"type": "object",
                    "properties": {"verdict": {"type": "string"}}},
        )
        cls(root=root, max_parallel=1).run(task)
        wrote = target.exists()

    if wrote:
        return False, "a pu écrire — la restriction ne tient pas"
    # One run, and a posture is not proved by one run: the same probe was
    # refused five times and then succeeded once, which is what a single open
    # door looks like from outside. A green line here means "not this time",
    # and the wording says so rather than promising more.
    return True, "n'a pas écrit cette fois"


def run_agents(*, writes: bool = True) -> list[Check]:
    """One real call per installed agent. Costs money; says something."""
    from thot.engine.factory import AGENT_ENGINES

    # Neither of these can be made read-only, and a permanent red line is a
    # line people stop reading. Their reach is stated instead, so a reader
    # choosing `--engine hermes` knows what they are choosing.
    UNRESTRICTABLE = {
        "hermes": "peut écrire — aucun mode lecture seule (`-t file` et "
                  "`--safe-mode` ne restreignent pas les permissions)",
        "prime": "peut écrire — outil unique : un noyau IPython",
    }

    checks: list[Check] = []
    for name, cls in AGENT_ENGINES.items():
        if not cls.available():
            checks.append(Check(f"lecture · {name}", False, "non installé"))
            continue
        checks.append(_safe(f"lecture · {name}", lambda c=cls: _can_read(c)))
        if not writes:
            continue
        if name in UNRESTRICTABLE:
            checks.append(Check(f"écriture · {name}", True, UNRESTRICTABLE[name]))
            continue
        checks.append(_safe(f"écriture · {name}", lambda c=cls: _cannot_write(c)))
    return checks
