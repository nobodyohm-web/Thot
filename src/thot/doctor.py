"""Prove the installation is whole, offline, in under a second.

"It works" is a claim, and a claim about a program made of three programs is
one nobody should take on trust — least of all from the tool itself. Every
check here runs a real operation and reports what it measured: not "skills:
configured" but "skills: 102 loaded, 8 refused". A check that cannot run says
so rather than passing quietly, because a green line that means "not tested"
is worse than a red one.

Nothing here touches the network or a model. `thot doctor` on a plane must
give the same answer as `thot doctor` at a desk.
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
