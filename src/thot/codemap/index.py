"""Pick the indexer for a file, and index a whole scope with it.

One place decides which language gets a map, so `run_audit` and the
interactive reconnaissance can never drift apart on the answer — they did
before, only by accident of both hard-coding `.py`.
"""

from __future__ import annotations

from pathlib import Path

from thot.contracts import Symbol

PYTHON_SUFFIXES = (".py",)


def _indexer_for(relative: str):
    from thot.codemap.ts_indexer import EXTENSIONS as TS_SUFFIXES

    lowered = relative.lower()
    if lowered.endswith(PYTHON_SUFFIXES):
        from thot.codemap.python_indexer import PythonIndexer

        return PythonIndexer()
    if lowered.endswith(TS_SUFFIXES):
        from thot.codemap.ts_indexer import TypeScriptIndexer

        return TypeScriptIndexer()
    return None


# Symbols computed once per version of a file. Parsing is the expensive half
# of every map Thot builds, and it was paid in full every single time: the MCP
# server built one map at startup, the session rebuilt the whole tree after
# each tool write, and `thot audit` started from nothing on every run. Measured
# on `hermes/`: 6 924 files, 26 s of indexing — repeated for a tree where one
# file had changed.
#
# The key is `(path, size, mtime_ns)`, the one `ts_indexer.read_masked`
# already uses. A file nobody has written is the same file; a file somebody
# has is a different key, and the entry expires by construction rather than
# by anyone remembering to invalidate it.
#
# Bounded, because an audit of twelve thousand files must not hold every
# symbol of every version it has ever seen.
_SYMBOL_CACHE: dict[tuple[str, int, int], tuple[Symbol, ...]] = {}
SYMBOL_CACHE_LIMIT = 20_000


def _version(path: Path) -> tuple[str, int, int] | None:
    """Which version of a file this is, or nothing if it is not readable."""
    try:
        found = path.stat()
    except OSError:
        return None
    return (str(path), found.st_size, found.st_mtime_ns)


def forget_symbols() -> None:
    """Drop the cache — for tests, and for a process that has moved on."""
    _SYMBOL_CACHE.clear()


def _language_known(relative: str) -> bool:
    """Whether any indexer would read this file — asked without building one."""
    from thot.codemap.ts_indexer import EXTENSIONS as TS_SUFFIXES

    lowered = relative.lower()
    return lowered.endswith(PYTHON_SUFFIXES) or lowered.endswith(TS_SUFFIXES)


def _remember(version: tuple[str, int, int], found: tuple[Symbol, ...]) -> None:
    if len(_SYMBOL_CACHE) >= SYMBOL_CACHE_LIMIT:
        _SYMBOL_CACHE.clear()
    _SYMBOL_CACHE[version] = found


def _index_chunk(root: str, relatives: list[str]) -> list[tuple]:
    """Parse a slice of the tree, returning `(version, symbols)` per file.

    At module level and taking only picklable arguments, because on macOS a
    worker is spawned rather than forked: it re-imports this module and calls
    this function by name. A closure would not survive the trip.

    The version is read *before* the file is parsed, never after. A file
    rewritten mid-parse then lands under the version it had, so the next
    sweep sees a mismatch and reads it again — where stamping it with the
    version it acquired afterwards would cache the old symbols under the new
    file, and serve them for as long as nobody touched it again.
    """
    base = Path(root)
    indexers: dict[str, object] = {}
    produced: list[tuple] = []
    for relative in relatives:
        suffix = Path(relative).suffix.lower()
        if suffix not in indexers:
            indexers[suffix] = _indexer_for(relative)
        indexer = indexers[suffix]
        version = _version(base / relative)
        if indexer is None:
            produced.append((version, ()))
            continue
        try:
            found = tuple(indexer.index_file(base, relative))
        except Exception:
            # One unparseable file must not cost the map. A scanner that dies
            # on a single minified bundle would take the whole reconnaissance
            # with it. Remembered as empty, too: a file that cannot be read
            # costs one attempt, not one per sweep.
            found = ()
        produced.append((version, found))
    return produced


def index_files(root: Path, files, *, jobs: int | None = None) -> list[Symbol]:
    """Every symbol in scope, from whichever indexer knows the language.

    One indexer instance per language, not per file: constructing a scanner
    nine hundred times is pure waste on a repository this size. One parse per
    version of a file, not per sweep, for the same reason at a larger scale.
    And, above a few hundred files still to read, one parse per core.

    The cache is consulted *before* anything is handed out, and only the
    misses are. That ordering is not an optimisation, it is what keeps the
    cache working at all: workers are separate processes, so what they parse
    is remembered nowhere until the parent writes it down here — and
    `gateway/commands.py` and `schedule/runner.py` both call `run_audit` in a
    loop inside one process. A pool that skipped this step would turn a warm
    0.06 s audit back into 5.4 s, every round.
    """
    root = Path(root)
    wanted = [relative for relative in files if _language_known(relative)]

    versions: dict[str, tuple | None] = {}
    misses: list[str] = []
    for relative in wanted:
        version = _version(root / relative)
        versions[relative] = version
        if version is None or version not in _SYMBOL_CACHE:
            misses.append(relative)

    produced: dict[str, tuple[Symbol, ...]] = {}
    if misses:
        from thot.parallel import over_files

        for relative, (version, found) in zip(
            misses, over_files(_index_chunk, root, misses, jobs=jobs)
        ):
            produced[relative] = found
            if version is not None:
                _remember(version, found)

    symbols: list[Symbol] = []
    for relative in wanted:
        if relative in produced:
            symbols.extend(produced[relative])
        else:
            symbols.extend(_SYMBOL_CACHE.get(versions[relative], ()))
    return symbols
