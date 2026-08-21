"""The tools the model can call.

Two families. The ordinary ones — read, write, edit, run — are what any coding
agent needs. The other four (`map`, `find_symbol`, `callers`, `audit`) answer
from the precomputed graph: no file is opened, no token is spent, and the
answer is complete rather than whatever a search happened to surface.

Anything that writes or executes asks the user first. That confirmation is not
configurable.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any

from thot.llm.base import ToolSpec

MAX_READ_BYTES = 200_000
MAX_OUTPUT_CHARS = 20_000
COMMAND_TIMEOUT = 120


@dataclass
class ToolContext:
    """What the tools act on, and how they ask permission."""

    root: Path
    recon: Any  # thot.recon.Recon — kept loose to avoid a circular import
    confirm: Callable[[str, str], bool]
    refresh: Callable[[], None]


class ToolError(Exception):
    """Recoverable: the message goes back to the model, which can retry."""


def _resolve(context: ToolContext, path: str) -> Path:
    """Resolve a path and refuse anything outside the working directory."""
    candidate = (context.root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    try:
        candidate.relative_to(context.root)
    except ValueError:
        raise ToolError(
            f"Chemin hors du répertoire de travail : {path}. "
            f"Thot ne travaille que dans {context.root}."
        ) from None
    return candidate


def _relative(context: ToolContext, path: Path) -> str:
    try:
        return str(path.relative_to(context.root))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------
# File tools
# --------------------------------------------------------------------------


def read_file(context: ToolContext, *, path: str, start: int = 1, end: int = 0) -> str:
    target = _resolve(context, path)
    if not target.is_file():
        raise ToolError(f"Fichier introuvable : {path}")
    if target.stat().st_size > MAX_READ_BYTES:
        raise ToolError(
            f"{path} fait plus de {MAX_READ_BYTES // 1000} ko. "
            f"Lis une plage avec start/end."
        )
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    first = max(1, start)
    last = end if end and end >= first else len(lines)
    selected = lines[first - 1 : last]
    numbered = [f"{first + i:>5}  {line}" for i, line in enumerate(selected)]
    return "\n".join(numbered) or "(fichier vide)"


def write_file(context: ToolContext, *, path: str, content: str) -> str:
    target = _resolve(context, path)
    exists = target.exists()
    action = "Écraser" if exists else "Créer"
    preview = content if len(content) < 800 else content[:800] + "\n…"
    if not context.confirm(f"{action} {_relative(context, target)}", preview):
        raise ToolError("L'utilisateur a refusé l'écriture.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    context.refresh()
    verb = "écrasé" if exists else "créé"
    return f"{_relative(context, target)} {verb} ({len(content.splitlines())} lignes)"


def edit_file(context: ToolContext, *, path: str, old: str, new: str) -> str:
    target = _resolve(context, path)
    if not target.is_file():
        raise ToolError(f"Fichier introuvable : {path}")
    source = target.read_text(encoding="utf-8", errors="replace")
    occurrences = source.count(old)
    if occurrences == 0:
        raise ToolError("Texte à remplacer introuvable — relis le fichier d'abord.")
    if occurrences > 1:
        raise ToolError(
            f"Texte présent {occurrences} fois. Donne un extrait plus large "
            f"pour qu'il soit unique."
        )
    diff = f"- {old.strip()[:300]}\n+ {new.strip()[:300]}"
    if not context.confirm(f"Modifier {_relative(context, target)}", diff):
        raise ToolError("L'utilisateur a refusé la modification.")
    target.write_text(source.replace(old, new, 1), encoding="utf-8")
    context.refresh()
    return f"{_relative(context, target)} modifié"


def list_dir(context: ToolContext, *, path: str = ".") -> str:
    target = _resolve(context, path)
    if not target.is_dir():
        raise ToolError(f"Répertoire introuvable : {path}")
    entries = sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name))
    rendered = [
        f"{'DIR ' if entry.is_dir() else '    '}{entry.name}"
        for entry in entries
        if not entry.name.startswith(".")
    ]
    return "\n".join(rendered) or "(vide)"


def run_command(context: ToolContext, *, command: str) -> str:
    if not context.confirm("Exécuter une commande", command):
        raise ToolError("L'utilisateur a refusé l'exécution.")
    try:
        done = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=COMMAND_TIMEOUT, cwd=str(context.root), check=False,
        )
    except subprocess.TimeoutExpired:
        raise ToolError(f"Commande interrompue après {COMMAND_TIMEOUT} s.") from None
    output = (done.stdout + done.stderr).strip()
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n… (sortie tronquée)"
    context.refresh()
    return f"code de sortie {done.returncode}\n{output or '(aucune sortie)'}"


# --------------------------------------------------------------------------
# Graph tools — free, complete, instant
# --------------------------------------------------------------------------


def _matches_pattern(path: str, pattern: str) -> bool:
    """Glob when the pattern looks like one, substring otherwise.

    A model reaching for this tool writes `*.py` as readily as `app`. Treating
    the glob as a literal substring answers "0 fichiers", which reads as an
    empty project and sends it grepping — the exact waste the map exists to
    prevent.
    """
    lowered = path.lower()
    needle = pattern.lower()
    if any(char in pattern for char in "*?["):
        return fnmatch(lowered, needle) or fnmatch(PurePosixPath(lowered).name, needle)
    return needle in lowered


def code_map(context: ToolContext, *, pattern: str = "") -> str:
    recon = context.recon
    if recon.is_empty:
        return "Aucun code source dans ce répertoire."
    files = recon.manifest.files
    if pattern:
        files = [f for f in files if _matches_pattern(f, pattern)]
        if not files:
            return (
                f"Aucun fichier ne correspond à « {pattern} » "
                f"(sur {len(recon.manifest.files)} indexés). "
                "Rappelle `code_map` sans motif pour tout voir."
            )
    listing = "\n".join(files[:200])
    suffix = f"\n… {len(files) - 200} de plus" if len(files) > 200 else ""
    return f"{len(files)} fichiers\n{listing}{suffix}"


_SKILL_CACHE: dict[str, list] = {}


def _skills_for(root) -> list:
    """Discovered once per directory: a session opens dozens of tool calls."""
    key = str(root)
    if key not in _SKILL_CACHE:
        from thot.skills import discover

        _SKILL_CACHE[key] = discover(root)
    return _SKILL_CACHE[key]


def skills(context: ToolContext, *, query: str = "") -> str:
    """The catalogue: one line each, cheap enough to read before choosing."""
    available = _skills_for(context.root)
    if query:
        needle = query.lower()
        available = [
            s for s in available
            if needle in s.name.lower()
            or needle in s.description.lower()
            or needle in s.category.lower()
        ]
    if not available:
        return f"Aucun skill ne correspond à « {query} »." if query else "Aucun skill."
    lines = [s.summary() for s in available]
    return f"{len(available)} skill(s)\n" + "\n".join(lines)


def skill(context: ToolContext, *, name: str) -> str:
    """The full method. Read it before applying it, not after."""
    available = _skills_for(context.root)
    exact = [s for s in available if s.name == name]
    chosen = exact or [s for s in available if name.lower() in s.name.lower()]
    if not chosen:
        near = ", ".join(s.name for s in available[:8])
        return f"Skill « {name} » inconnu. Disponibles : {near}…"
    found = chosen[0]
    header = f"# {found.name}\n\n{found.description}\n"
    return f"{header}\n---\n\n{found.body}"


def find_symbol(context: ToolContext, *, name: str) -> str:
    recon = context.recon
    needle = name.lower()
    matches = [
        symbol for symbol in recon.symbols
        if needle in symbol.name.lower()
    ]
    if not matches:
        return f"Aucun symbole ne correspond à « {name} »."
    lines = [
        f"{symbol.name}  {symbol.path}:{symbol.lineno}-{symbol.end_lineno}  "
        f"({symbol.kind}, params: {', '.join(symbol.params) or 'aucun'})"
        for symbol in matches[:40]
    ]
    suffix = f"\n… {len(matches) - 40} de plus" if len(matches) > 40 else ""
    return "\n".join(lines) + suffix


def callers(context: ToolContext, *, symbol: str) -> str:
    graph = context.recon.graph
    if graph is None:
        return "Aucun graphe d'appels disponible."
    resolved = _resolve_symbol(graph, symbol)
    if resolved is None:
        return f"Symbole inconnu : {symbol}"
    incoming = sorted(graph.callers(resolved))
    outgoing = sorted(graph.callees(resolved))
    distance = graph.distance_from_entrypoints(resolved)
    reach = (
        "inatteignable depuis un point d'entrée"
        if distance is None
        else f"à {distance} saut(s) d'un point d'entrée"
    )
    return (
        f"{resolved} — {reach}\n"
        f"appelé par : {', '.join(incoming) or 'personne'}\n"
        f"appelle    : {', '.join(outgoing) or 'rien'}"
    )


def _resolve_symbol(graph, name: str) -> str | None:
    if name in graph.symbols:
        return name
    matches = [key for key in graph.symbols if key.rsplit(".", 1)[-1] == name]
    if len(matches) == 1:
        return matches[0]
    matches = [key for key in graph.symbols if name.lower() in key.lower()]
    return matches[0] if len(matches) == 1 else None


def audit(context: ToolContext) -> str:
    findings = context.recon.findings
    if not findings:
        return (
            "Aucun chemin de teinte détecté. Analyse déterministe uniquement : "
            "ce n'est pas une preuve d'absence de défaut."
        )
    lines = []
    for finding in findings:
        path = " → ".join(str(step) for step in finding.taint_path)
        lines.append(
            f"[{finding.severity.value.upper()}] {finding.rule} — {finding.location} "
            f"({finding.location.symbol})\n    {finding.failure_scenario}\n"
            f"    chemin : {path}"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_STRING = {"type": "string"}

SPECS: list[ToolSpec] = [
    ToolSpec(
        name="read_file",
        description="Lire un fichier du projet, avec numéros de ligne. "
                    "Utilise start/end pour une plage.",
        parameters={
            "type": "object",
            "properties": {
                "path": _STRING,
                "start": {"type": "integer"},
                "end": {"type": "integer"},
            },
            "required": ["path"],
        },
    ),
    ToolSpec(
        name="write_file",
        description="Créer ou écraser un fichier. Demande confirmation.",
        parameters={
            "type": "object",
            "properties": {"path": _STRING, "content": _STRING},
            "required": ["path", "content"],
        },
    ),
    ToolSpec(
        name="edit_file",
        description="Remplacer un extrait exact et unique dans un fichier. "
                    "Demande confirmation.",
        parameters={
            "type": "object",
            "properties": {"path": _STRING, "old": _STRING, "new": _STRING},
            "required": ["path", "old", "new"],
        },
    ),
    ToolSpec(
        name="list_dir",
        description="Lister le contenu d'un répertoire.",
        parameters={
            "type": "object",
            "properties": {"path": _STRING},
        },
    ),
    ToolSpec(
        name="run_command",
        description="Exécuter une commande shell dans le projet. "
                    "Demande confirmation.",
        parameters={
            "type": "object",
            "properties": {"command": _STRING},
            "required": ["command"],
        },
    ),
    ToolSpec(
        name="skills",
        description="Lister les méthodes disponibles (audit, débogage, TDD, "
                    "revue, planification). Gratuit. À consulter avant de "
                    "commencer une tâche non triviale.",
        parameters={
            "type": "object",
            "properties": {"query": _STRING},
        },
    ),
    ToolSpec(
        name="skill",
        description="Lire une méthode en entier, par son nom. À faire avant de "
                    "l'appliquer.",
        parameters={
            "type": "object",
            "properties": {"name": _STRING},
            "required": ["name"],
        },
    ),
    ToolSpec(
        name="code_map",
        description="Lister les fichiers du projet. Sans motif : tout. Avec motif : glob (`*.py`, `src/**`) ou fragment de chemin (`auth`). Gratuit : réponse issue de l'index, aucun fichier ouvert.",
        parameters={
            "type": "object",
            "properties": {"pattern": _STRING},
        },
    ),
    ToolSpec(
        name="find_symbol",
        description="Localiser une fonction ou une classe : fichier, lignes, "
                    "paramètres. Gratuit, issu de l'index AST.",
        parameters={
            "type": "object",
            "properties": {"name": _STRING},
            "required": ["name"],
        },
    ),
    ToolSpec(
        name="callers",
        description="Qui appelle un symbole, qui il appelle, et sa distance à un "
                    "point d'entrée. Réponse complète issue du graphe d'appels.",
        parameters={
            "type": "object",
            "properties": {"symbol": _STRING},
            "required": ["symbol"],
        },
    ),
    ToolSpec(
        name="audit",
        description="Les chemins de teinte source → sink détectés dans le projet, "
                    "avec sévérité calculée.",
        parameters={"type": "object", "properties": {}},
    ),
]

HANDLERS: dict[str, Callable[..., str]] = {
    "read_file": read_file,
    "write_file": write_file,
    "edit_file": edit_file,
    "list_dir": list_dir,
    "run_command": run_command,
    "skills": skills,
    "skill": skill,
    "code_map": code_map,
    "find_symbol": find_symbol,
    "callers": callers,
    "audit": audit,
}

# Tools that change the world; the session shows them differently.
MUTATING = frozenset({"write_file", "edit_file", "run_command"})


def dispatch(context: ToolContext, name: str, arguments: dict) -> str:
    handler = HANDLERS.get(name)
    if handler is None:
        return f"Outil inconnu : {name}"
    try:
        return handler(context, **arguments)
    except ToolError as exc:
        return f"Erreur : {exc}"
    except TypeError as exc:
        return f"Arguments invalides pour {name} : {exc}"
    except Exception as exc:  # a tool must never kill the session
        return f"Échec de {name} : {exc}"
