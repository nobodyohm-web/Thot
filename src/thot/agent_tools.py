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

from thot.contracts import Severity
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
    # Where `run_command` executes. None means the host, which is what Thot
    # has always done; a session started with --sandbox puts a container here.
    sandbox: Any = None
    # A live Python namespace, when the session opened one.
    kernel: Any = None


class ToolError(Exception):
    """Recoverable: the message goes back to the model, which can retry."""


def _resolve(context: ToolContext, path: str) -> Path:
    """Resolve a path and refuse anything outside the working directory.

    Both sides are resolved, and that symmetry is the whole point. Resolving
    only the candidate refused every legitimate file whenever the root was
    reached through a symlink — on macOS `/tmp` is `/private/tmp` and
    `tempfile.mkdtemp()` hands back `/var/folders/…` for
    `/private/var/folders/…`, so an agent working there was told "outside the
    working directory" about files sitting in it, and concluded it could not
    read the code at all.

    It does not widen the guard: an escape still resolves outside the root and
    is still refused, and so is a symlink *inside* the root that points out of
    it — resolving the candidate is what catches that one.
    """
    root = context.root.resolve()
    candidate = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ToolError(
            f"Chemin hors du répertoire de travail : {path}. "
            f"Thot ne travaille que dans {context.root}."
        ) from None
    return candidate


def _relative(context: ToolContext, path: Path) -> str:
    """The short name a human reads in a confirmation prompt.

    Resolved on both sides for the same reason `_resolve` is: against an
    unresolved root this fell through to the absolute path on any symlinked
    working directory, so the prompt asking permission to write said
    `/private/var/folders/b1/…/src/app.py` where it meant `src/app.py`.
    """
    try:
        return str(path.resolve().relative_to(context.root.resolve()))
    except (ValueError, OSError):
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
    if not numbered:
        return "(fichier vide)"

    # A file is read from the top, so this one keeps the head — the opposite
    # end from a command's output, and for the opposite reason.
    from thot.output import truncate_head

    return truncate_head("\n".join(numbered)).rendered()


_PLUGIN_CACHE: dict[str, list] = {}


def _plugins_for(root) -> list:
    key = str(root)
    if key not in _PLUGIN_CACHE:
        from thot.plugins import discover

        _PLUGIN_CACHE[key] = discover(root)
    return _PLUGIN_CACHE[key]


def _write_warnings(context: ToolContext, path: str, content: str) -> str:
    """What the plugins want the model to know about this write.

    Advisory by design: the file is written and the warning rides back in the
    tool result, so the model self-corrects on the next turn. Blocking would
    mean a false positive can deadlock a session, and a model that cannot
    write cannot fix anything.
    """
    from thot.plugins import invoke_hook

    notes = invoke_hook(
        _plugins_for(context.root), "pre_write", path=path, content=content
    )
    warnings = [str(note).strip() for note in notes if note]
    return ("\n\n" + "\n".join(warnings)) if warnings else ""


def python(context: ToolContext, *, code: str) -> str:
    """One cell in the session's kernel. Never in Thot's own process."""
    if context.kernel is None:
        raise ToolError(
            "Aucun noyau Python dans cette session — `/py` pour l'ouvrir."
        )
    # The kernel's posture, on every cell. Its full warning is printed once,
    # when `/py` opens it, and a session runs for hours after that — leaving
    # every later confirmation to show the code alone. Arbitrary Python
    # reaches the same credentials an arbitrary command does, so it says the
    # same thing `run_command` does.
    # Posture first: `Session._confirm` truncates the detail at 1500 characters,
    # and a Python cell reaches that without being unusual. Placed last, the
    # warning vanished exactly when the code was too long to take in at a
    # glance — which is when it mattered most.
    detail = f"[{context.kernel.describe()}]\n\n{code}"
    if not context.confirm("Exécuter du Python", detail):
        raise ToolError("L'utilisateur a refusé l'exécution.")

    outcome = context.kernel.execute(code)
    context.refresh()
    return outcome.render()


def _notify_write(context: ToolContext, path: str, content: str) -> None:
    """Tell the plugins the file is on disk. Never blocks, never raises."""
    from thot.plugins import notify_write

    notify_write(path, content, context.root)


def write_file(context: ToolContext, *, path: str, content: str) -> str:
    target = _resolve(context, path)
    exists = target.exists()
    action = "Écraser" if exists else "Créer"
    preview = content if len(content) < 800 else content[:800] + "\n…"
    if not context.confirm(f"{action} {_relative(context, target)}", preview):
        raise ToolError("L'utilisateur a refusé l'écriture.")
    warnings = _write_warnings(context, path, content)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _notify_write(context, path, content)
    context.refresh()
    verb = "écrasé" if exists else "créé"
    return (
        f"{_relative(context, target)} {verb} "
        f"({len(content.splitlines())} lignes){warnings}"
    )


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
    updated = source.replace(old, new, 1)
    warnings = _write_warnings(context, path, updated)
    target.write_text(updated, encoding="utf-8")
    _notify_write(context, path, updated)
    context.refresh()
    return f"{_relative(context, target)} modifié{warnings}"


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


def _sandbox_for(context: ToolContext):
    from thot.sandbox.local import LocalSandbox

    return context.sandbox or LocalSandbox(root=context.root)


def run_command(context: ToolContext, *, command: str) -> str:
    sandbox = _sandbox_for(context)
    # The posture always, and `local` above all: it means "no isolation, the
    # command runs under your account". Showing it only for the other
    # sandboxes reassured when it could and went quiet when it mattered, in
    # the one text a human reads before allowing an arbitrary command.
    detail = f"[{sandbox.describe()}]\n\n{command}"
    if not context.confirm("Exécuter une commande", detail):
        raise ToolError("L'utilisateur a refusé l'exécution.")

    result = sandbox.run(command, timeout=COMMAND_TIMEOUT)
    if result.timed_out:
        raise ToolError(result.output)

    context.refresh()
    where = "" if result.sandbox == "local" else f" (dans {result.sandbox})"
    return (f"code de sortie {result.exit_code}{where}\n"
            f"{result.output or '(aucune sortie)'}")


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


# A catalogue of two hundred lines is a catalogue nobody reads. Without a
# query the answer is shaped like a table of contents; with one it is a
# short list of candidates.
SKILL_MATCH_LIMIT = 15


def skills(context: ToolContext, *, query: str = "") -> str:
    """The catalogue: an index without a query, candidates with one."""
    available = _skills_for(context.root)
    if not available:
        return "Aucun skill."

    if not query:
        return _skill_index(available)

    matched = [s for s in available if s.matches(query)]
    if not matched:
        return _no_skill_matched(query, available)

    lines = [s.summary() for s in matched[:SKILL_MATCH_LIMIT]]
    extra = len(matched) - len(lines)
    tail = f"\n… {extra} autre(s) — précise ta recherche." if extra else ""
    return f"{len(matched)} skill(s) pour « {query} »\n" + "\n".join(lines) + tail


def _skill_index(available: list) -> str:
    """Names grouped by category — enough to choose, cheap enough to send."""
    grouped: dict[str, list[str]] = {}
    for item in available:
        grouped.setdefault(item.category or "général", []).append(item.name)

    lines = [
        f"{category}: " + ", ".join(sorted(names))
        for category, names in sorted(grouped.items())
    ]
    return (
        f"{len(available)} méthodes disponibles.\n"
        "`skills(\"mot\")` pour filtrer, `skill(\"nom\")` pour en lire une.\n\n"
        + "\n".join(lines)
    )


def _no_skill_matched(query: str, available: list) -> str:
    """Say where else it could be, rather than only that it is not here."""
    from thot.skills.loader import optional

    try:
        elsewhere = [s.name for s in optional() if s.matches(query)]
    except OSError:
        elsewhere = []
    if elsewhere:
        names = ", ".join(elsewhere[:8])
        return (
            f"Aucun skill chargé pour « {query} », mais {len(elsewhere)} dans la "
            f"bibliothèque optionnelle : {names}.\n"
            f"L'utilisateur peut les activer avec `thot skills install <nom>`."
        )
    return f"Aucun skill ne correspond à « {query} »."


# Tools the library's own home agents provide and Thot does not. A method
# that tells the model to call one of these is still worth reading — the
# reasoning transfers, the tool call does not — so the mismatch is named
# instead of the skill being rewritten or dropped.
FOREIGN_TOOLS = (
    "delegate_task", "agent_run", "run_agent", "web_search", "browser_navigate",
    "browser_click", "browser_vision", "browser_snapshot", "browser_type",
    "browser_console", "browser_scroll", "browser_press", "browser_back",
    "image_gen", "video_gen", "speak", "memory_search", "ipython",
)


def _foreign_tools(body: str) -> list[str]:
    return [name for name in FOREIGN_TOOLS if name in body]


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
    text = f"{header}\n---\n\n{found.body}"

    missing = _foreign_tools(found.body)
    if missing:
        text += (
            "\n\n---\n\nNote Thot : cette méthode vient de la bibliothèque "
            "Hermes/Prime et cite des outils absents ici — "
            f"{', '.join(missing)}. La démarche reste valable ; fais le travail "
            "avec les outils de Thot (`run_command`, `read_file`, `write_file`, "
            "`edit_file`, `code_map`, `find_symbol`, `callers`, `audit`)."
        )
    return text


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


# One tool call must not cost half a context window. Measured on Hermes
# before this: 372 findings, 375 000 characters, some 94 000 tokens handed
# back in a single answer — and this tool is exposed over MCP to the user's
# own sessions, where a model with a smaller window would simply fail.
MAX_LISTED = 40
MAX_SCENARIO = 400

_SEVERITY_RANK = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


def audit(context: ToolContext) -> str:
    findings = context.recon.findings
    if not findings:
        return (
            "Aucun chemin de teinte détecté. Analyse déterministe uniquement : "
            "ce n'est pas une preuve d'absence de défaut."
        )

    ranked = sorted(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 9))
    shown, rest = ranked[:MAX_LISTED], ranked[MAX_LISTED:]

    lines = []
    for finding in shown:
        path = " → ".join(str(step) for step in finding.taint_path)
        scenario = (finding.failure_scenario or "").strip()
        if len(scenario) > MAX_SCENARIO:
            scenario = scenario[:MAX_SCENARIO].rsplit(" ", 1)[0] + " […]"
        lines.append(
            f"[{finding.severity.value.upper()}] {finding.rule} — {finding.location} "
            f"({finding.location.symbol})\n    {scenario}\n"
            f"    chemin : {path}"
        )

    if rest:
        # Counted by severity rather than dropped in silence: "40 findings"
        # where there are 372 is a lie a reader cannot detect.
        tally: dict[str, int] = {}
        for finding in rest:
            tally[finding.severity.value] = tally.get(finding.severity.value, 0) + 1
        breakdown = " · ".join(
            f"{count} {name}" for name, count in sorted(
                tally.items(), key=lambda pair: _SEVERITY_RANK.get(
                    Severity(pair[0]), 9
                )
            )
        )
        lines.append(
            f"\n… et {len(rest)} autre(s) finding(s) non listés ici — "
            f"{breakdown}. Les plus graves sont ci-dessus ; "
            f"`thot audit --all` pour la liste entière."
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
        name="python",
        description="Exécuter du Python dans un noyau persistant : les variables "
                    "survivent d'un appel à l'autre. La carte du dépôt y est "
                    "disponible comme objets — files(), symbols(), callers(), "
                    "audit(), read() — et `rlm(question)` délègue une question à "
                    "un autre modèle. À préférer aux appels d'outils répétés dès "
                    "qu'il faut boucler ou croiser des résultats.",
        parameters={
            "type": "object",
            "properties": {"code": _STRING},
            "required": ["code"],
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
    "python": python,
    "skills": skills,
    "skill": skill,
    "code_map": code_map,
    "find_symbol": find_symbol,
    "callers": callers,
    "audit": audit,
}

# Tools that change the world; the session shows them differently.
NAMES = frozenset(spec.name for spec in SPECS)

MUTATING = frozenset({"write_file", "edit_file", "run_command", "python"})


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
