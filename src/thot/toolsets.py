"""Which tools the model gets, as a named posture rather than a list.

Ported from Hermes Agent's `toolsets.py`, reduced from a composable alias
system to three postures, because Thot has eleven tools and a user picking
between them one by one is a user making a mistake.

The one that earns the file: **lecture**. Reviewing a repository you do
not own means reading code you have every reason to distrust, and the
model editing it is rarely what you wanted. The sandbox stops that code
from running as you; this stops Thot from writing to it at all.
"""

from __future__ import annotations

# Free, and answered from the precomputed map: never a reason to withhold.
GRAPH = ("code_map", "find_symbol", "callers", "audit", "skills", "skill")
READS = ("read_file", "list_dir")
WRITES = ("write_file", "edit_file")
RUNS = ("run_command",)

TOOLSETS: dict[str, tuple[str, ...]] = {
    # Everything. What `thot` has always done.
    "complet": GRAPH + READS + WRITES + RUNS,
    # Read and reason, never modify. For a repository under audit.
    "lecture": GRAPH + READS,
    # The map alone: no file is opened, so nothing on disk is even read.
    "carte": GRAPH,
}

DEFAULT = "complet"

DESCRIPTIONS = {
    "complet": "lire, écrire, exécuter — le mode normal",
    "lecture": "lire et raisonner, jamais modifier",
    "carte": "la carte seule — aucun fichier ouvert",
}


def resolve(name: str) -> tuple[str, ...]:
    """The tool names for a posture. An unknown name raises rather than
    silently handing over everything."""
    key = (name or DEFAULT).strip().lower()
    if key not in TOOLSETS:
        raise KeyError(
            f"Jeu d'outils inconnu : {name}. Connus : {', '.join(TOOLSETS)}."
        )
    return TOOLSETS[key]


def select(specs, name: str):
    """Filter tool specifications down to one posture, order preserved."""
    allowed = set(resolve(name))
    return tuple(spec for spec in specs if spec.name in allowed)


def denied_cli_tools(name: str) -> tuple[str, ...]:
    """What the official CLI must be told not to do, for the same posture.

    In account mode the CLI owns its own Read/Write/Bash. A posture that
    only filtered Thot's tools would be a lie there — the model could still
    edit the repository through the client's own tools.
    """
    from thot.llm.claude_cli import READING_TOOLS, WRITING_TOOLS

    key = (name or DEFAULT).strip().lower()
    if key == "lecture":
        return WRITING_TOOLS
    if key == "carte":
        return WRITING_TOOLS + READING_TOOLS
    return ()


def describe(name: str) -> str:
    key = (name or DEFAULT).strip().lower()
    return DESCRIPTIONS.get(key, "")
