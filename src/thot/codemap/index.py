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


def index_files(root: Path, files) -> list[Symbol]:
    """Every symbol in scope, from whichever indexer knows the language.

    One indexer instance per language, not per file: constructing a scanner
    nine hundred times is pure waste on a repository this size.
    """
    cache: dict[str, object] = {}
    symbols: list[Symbol] = []
    for relative in files:
        suffix = Path(relative).suffix.lower()
        if suffix not in cache:
            cache[suffix] = _indexer_for(relative)
        indexer = cache[suffix]
        if indexer is None:
            continue
        try:
            symbols.extend(indexer.index_file(root, relative))
        except Exception:
            # One unparseable file must not cost the map. A scanner that
            # dies on a single minified bundle would take the whole
            # reconnaissance with it.
            continue
    return symbols
