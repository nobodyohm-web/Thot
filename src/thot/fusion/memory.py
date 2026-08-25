"""One memory across the three programs.

Each keeps durable notes, in its own place and its own shape:

    thot    `~/.thot/harness.json`          structuré : titre + contenu
    hermes  `~/.hermes/memories/MEMORY.md`  entrées séparées par des `§`
    prime   `~/.prime/agent/AGENTS.md`      markdown, chargé globalement

They are read into one view, always — reading cannot break anything, and a
fact Hermes learned last week is a fact Thot should know today.

Writing is the opposite: these are live files that the agents themselves
edit mid-session. So the projection is an explicit act, it only ever touches
entries Thot itself wrote — tagged, never guessed at — and it backs the file
up before the first change.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from thot.fusion.wiring import hermes_home, prime_home

# Hermes's own delimiter, from tools/memory_tool.py. Splitting on a bare "§"
# would cut an entry that merely mentions one.
ENTRY_DELIMITER = "\n§\n"

# Every entry Thot writes into another program's memory starts with this.
# It is how a re-sync knows what is its to replace, and how a human reading
# the file knows who put it there.
TAG = "[thot]"

# Enough for the facts to be useful, small enough not to crowd out the
# briefing they are injected into.
MAX_ENTRIES = 40
MAX_CHARS = 4000


@dataclass(frozen=True)
class Note:
    """One remembered fact, and which program remembered it."""

    source: str
    text: str

    def line(self) -> str:
        # `source · text`, not `[source] text`: the bracket form is what
        # `TAG` uses inside another program's file, and two things that look
        # identical on screen but mean different things is how a reader ends
        # up trusting the wrong one.
        return f"{self.source} · {self.text}"

    @property
    def from_thot(self) -> bool:
        return self.text.lstrip().startswith(TAG)


def hermes_memory_path() -> Path:
    return hermes_home() / "memories" / "MEMORY.md"


def hermes_user_path() -> Path:
    return hermes_home() / "memories" / "USER.md"


def prime_context_path() -> Path:
    # Prime loads a context file from its agent directory before walking up
    # from the working directory: this is its global memory.
    return prime_home() / "AGENTS.md"


def _entries(path: Path) -> list[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [entry.strip() for entry in raw.split(ENTRY_DELIMITER) if entry.strip()]


def read_hermes() -> tuple[list[Note], int]:
    """Hermes's two stores, and how many entries were skipped as scaffolding.

    A freshly created `USER.md` is a form: `**Name:**` with nothing after it,
    italic instructions, a horizontal rule, and one closing line of plain
    prose that looks like nothing at all. Passing those into a briefing would
    state "Context: ---" as a fact about the user. The count comes back
    with the notes rather than being dropped in silence — Thot cannot tell a
    template from a terse note with certainty, so the number is shown.
    """
    raw = [Note("hermes", entry) for entry in _entries(hermes_memory_path())]
    raw += [Note("hermes/user", entry) for entry in _entries(hermes_user_path())]
    kept = [note for note in raw if _is_fact(note.text)]
    return kept, len(raw) - len(kept)


# `**Label:**` followed by nothing but optional italic guidance.
_EMPTY_FIELD = re.compile(r"^\*\*[^*]+:\*\*\s*(_[^_]*_)?$")

# The one entry of the `USER.md` Hermes creates that no rule below catches:
# ordinary prose, addressed to the agent, with no marker of any kind. It went
# into the briefing as a fact about the user. Matched on its text because
# that is what it is — a shipped line, not a shape — and because every shape
# broad enough to cover it (second person, ends in an instruction) would also
# throw away real notes somebody wrote about themselves.
_SHIPPED_SCAFFOLDING = frozenset({
    "the more you know, the better you can help. but remember — you're "
    "learning about a person, not building a dossier. respect the difference.",
})


def _is_fact(text: str) -> bool:
    body = text.strip()
    # The template prefixes some of its own scaffolding with "Context: ".
    if body.startswith("Context:"):
        body = body[len("Context:"):].strip()
    if not body or body in {"---", "***", "___"}:
        return False
    if body.startswith("_") and body.endswith("_"):
        return False  # wholly italic: an instruction to the agent, not a fact
    if " ".join(body.split()).casefold() in _SHIPPED_SCAFFOLDING:
        return False
    return _EMPTY_FIELD.match(body) is None


def _without_block(text: str) -> str:
    start = text.find(PRIME_HEADER)
    if start == -1:
        return text
    end = text.find(PRIME_FOOTER, start)
    if end == -1:
        # Header without footer: someone truncated the file. Removing to the
        # end would delete whatever they wrote after it, so leave it alone
        # and let the sync append rather than destroy.
        return text
    return text[:start] + text[end + len(PRIME_FOOTER):]


def read_prime() -> list[Note]:
    """Prime's global context file, minus the block Thot itself wrote.

    Excluded by its delimiters rather than by a marker on every line: the
    block is prose a person also reads, so it carries no per-line tag — and
    reading it back as Prime's own knowledge made every synced fact appear
    twice, then survive a `forget` as a copy nobody could delete.
    """
    try:
        raw = prime_context_path().read_text(encoding="utf-8")
    except OSError:
        return []
    blocks = [block.strip() for block in _without_block(raw).split("\n\n")]
    return [Note("prime", block) for block in blocks if block]


def read_thot(root: Path | str | None = None) -> list[Note]:
    from thot.harness import Harness

    harness = Harness.open(root or Path.cwd())
    return [Note("thot", entry.line().lstrip("- ")) for entry in harness.all()]


def merged(root: Path | str | None = None) -> list[Note]:
    """Everything the three know, minus what Thot itself put there.

    Without that subtraction a synced fact would come back as a second copy
    every time it is read, and grow a third on the next sync.
    """
    from_hermes, _ = read_hermes()
    notes = read_thot(root) + from_hermes + read_prime()
    return [note for note in notes if not note.from_thot]


def skipped() -> int:
    """How many entries were set aside as unfilled scaffolding."""
    return read_hermes()[1]


def brief(root: Path | str | None = None) -> str:
    """The shared memory, sized for a system prompt. Empty when there is none."""
    notes = merged(root)[:MAX_ENTRIES]
    if not notes:
        return ""

    lines: list[str] = []
    budget = MAX_CHARS
    for note in notes:
        line = f"- {note.line()}"
        if len(line) > budget:
            break
        lines.append(line)
        budget -= len(line)
    if not lines:
        return ""
    return "Mémoire partagée (thot · hermes · prime) :\n" + "\n".join(lines)


# -- projection --------------------------------------------------------------


@dataclass(frozen=True)
class Written:
    target: Path
    count: int
    action: str

    def line(self) -> str:
        return f"{self.action:<12} {self.target} — {self.count} entrée(s)"


def _thot_entries(root: Path | str | None) -> list[str]:
    from thot.harness import Harness

    harness = Harness.open(root or Path.cwd())
    return [f"{TAG} {entry.title} : {entry.content}" for entry in harness.all()]


def _backup(path: Path) -> None:
    """One backup, before the first change only.

    These files hold notes a person or an agent wrote over months. A tool
    that rewrites them owes a copy that predates its first mistake.
    """
    if not path.is_file():
        return
    backup = path.with_suffix(path.suffix + ".thot-backup")
    if not backup.exists():
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


try:  # Unix only; a machine without it simply writes unlocked.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None


@contextmanager
def _locked(path: Path):
    """Hold the lock Hermes holds, on the file Hermes locks.

    Its memory tool takes an exclusive `flock` on a sibling `<file>.lock`
    for the whole read-modify-write, then replaces the file atomically.
    Writing without taking that lock means a `--sync` landing during a live
    Hermes session silently drops whichever write finished second.

    This is not reaching into Hermes: it is speaking the file protocol two
    programs sharing a file have to agree on, and it is documented in
    `hermes/tools/memory_tool.py`.
    """
    if fcntl is None:
        yield
        return

    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = None
    try:
        handle = lock_path.open("a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    except OSError:
        # A lock we cannot take must not cost the sync. Losing a race is
        # recoverable; refusing to write at all is not what was asked.
        yield
    finally:
        if handle is not None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".thot-tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def project_hermes(root: Path | str | None = None) -> Written:
    """Add Thot's facts to Hermes's memory, in Hermes's own format."""
    path = hermes_memory_path()
    mine = _thot_entries(root)

    # Read and write inside one lock: reading first and locking second is
    # the race this exists to close.
    with _locked(path):
        theirs = [e for e in _entries(path) if not e.lstrip().startswith(TAG)]
        if not mine and not path.is_file():
            return Written(path, 0, "rien à faire")
        _backup(path)
        _atomic_write(path, ENTRY_DELIMITER.join([*theirs, *mine]) + "\n")
    return Written(path, len(mine), "écrit")


PRIME_HEADER = "## Mémoire de Thot"
PRIME_FOOTER = "<!-- fin de la mémoire de Thot -->"


def project_prime(root: Path | str | None = None) -> Written:
    """Add Thot's facts to Prime's global context file.

    Delimited rather than tagged line by line: `AGENTS.md` is prose a person
    edits, and a block with a visible beginning and end is what lets a
    re-sync replace exactly what it wrote and nothing else.
    """
    path = prime_context_path()
    mine = _thot_entries(root)

    try:
        existing = path.read_text(encoding="utf-8")
    except OSError:
        existing = ""

    kept = _without_block(existing)
    if not mine:
        if kept.strip() == existing.strip():
            return Written(path, 0, "rien à faire")
        _backup(path)
        _atomic_write(path, kept)
        return Written(path, 0, "retiré")

    block = "\n".join([PRIME_HEADER, "", *(f"- {entry[len(TAG):].strip()}"
                                           for entry in mine), "", PRIME_FOOTER])
    body = f"{kept.rstrip()}\n\n{block}\n" if kept.strip() else block + "\n"

    _backup(path)
    _atomic_write(path, body)
    return Written(path, len(mine), "écrit")


def project(root: Path | str | None = None) -> list[Written]:
    return [project_hermes(root), project_prime(root)]
