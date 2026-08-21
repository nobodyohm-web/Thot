"""What a cell can reach when Thot itself is importable.

The reason the kernel is worth having at all. Thot's map — the AST index,
the call graph, the taint findings — is already computed and sitting in
memory as Python objects. A tool call renders it to text so a model can
read it; a cell can just *use* it:

    for f in audit(severity="high"):
        print(f.location, [c for c in callers(f.location.symbol)])

That loop is one model turn. The same work through tool calls is a dozen,
and each one pays to re-read what the map already knew.

Read-only by construction: nothing here writes a file, runs a command, or
touches the verdict store. A cell that wants to change something asks the
host, and the host is where the permission prompt lives.
"""

from __future__ import annotations

from pathlib import Path


def install(namespace: dict, root: str) -> None:
    """Put Thot's map into a kernel namespace, computed on first use."""
    from thot.contracts import Severity

    state: dict = {}

    def recon():
        if "recon" not in state:
            from thot.recon import sweep

            state["recon"] = sweep(Path(root))
        return state["recon"]

    def files(pattern: str = "") -> list[str]:
        """Every source file the audit scope selected."""
        from thot.agent_tools import _matches_pattern

        found = list(recon().manifest.files)
        return [f for f in found if not pattern or _matches_pattern(f, pattern)]

    def symbols(name: str = "") -> list:
        needle = name.lower()
        return [s for s in recon().symbols if not needle or needle in s.name.lower()]

    def find(name: str):
        """The first symbol whose name matches, or None."""
        found = symbols(name)
        return found[0] if found else None

    def callers(symbol: str) -> list[str]:
        graph = recon().graph
        if graph is None:
            return []
        from thot.agent_tools import _resolve_symbol

        resolved = _resolve_symbol(graph, symbol)
        return sorted(graph.callers(resolved)) if resolved else []

    def callees(symbol: str) -> list[str]:
        graph = recon().graph
        if graph is None:
            return []
        from thot.agent_tools import _resolve_symbol

        resolved = _resolve_symbol(graph, symbol)
        return sorted(graph.callees(resolved)) if resolved else []

    def audit(severity: str = "", rule: str = "") -> list:
        """The findings, filtered. Same objects the report prints."""
        found = list(recon().findings)
        if severity:
            wanted = Severity(severity.lower())
            found = [f for f in found if f.severity is wanted]
        if rule:
            found = [f for f in found if rule in f.rule]
        return found

    def read(path: str, start: int = 1, end: int = 0) -> str:
        """A file, as text. Refuses anything outside the repository."""
        target = (Path(root) / path).resolve()
        try:
            target.relative_to(Path(root).resolve())
        except ValueError:
            raise PermissionError(f"hors du dépôt : {path}") from None
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        last = end if end and end >= start else len(lines)
        return "\n".join(lines[max(0, start - 1):last])

    def brief() -> str:
        from thot.recon import context_brief

        return context_brief(recon())

    namespace.update({
        "files": files, "symbols": symbols, "find": find,
        "callers": callers, "callees": callees, "audit": audit,
        "read": read, "brief": brief, "recon": recon,
    })


HELP = """Disponible dans le noyau :

  files(motif="")        les fichiers du dépôt
  symbols(nom="")        les symboles indexés
  find(nom)              le premier symbole qui correspond
  callers(symbole)       qui appelle
  callees(symbole)       ce qui est appelé
  audit(severity=, rule=) les findings, filtrés
  read(chemin, start, end) lire un fichier du dépôt
  rlm(question)          déléguer une question à un modèle
  remember(titre, texte) retenir quelque chose sur ce dépôt
  ROOT                   le dépôt, en Path

Les variables survivent d'une cellule à l'autre."""
