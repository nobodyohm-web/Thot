"""Spread a per-file pass across cores, or decline to.

Measured on `hermes/`, 6 924 files, ten cores: `thot audit` took 138.5 s of
wall clock and spent 135.6 s of it on one core — 99 % of a single CPU while
seven others slept. The heavy phases are all the same shape, a
`for relative in files:` loop that reads a file, parses or tokenises it, and
appends to a local list. Nothing between two files is shared.

The result, on the same tree and the same machine: 106.1 s serial against
53.6 s spread, for 104.0 s and 113.4 s of CPU respectively — the extra nine
seconds are the spawn and the pickling, and they buy back fifty-two. Both
runs report the same findings in the same order.

Two things make this worth its own module rather than a `ProcessPoolExecutor`
at each call site.

The first is that parallelism is not free and not always right. Spawning
eight interpreters costs about a second on macOS, pickling the answers costs
more, and on the repository Thot audits most often — itself, 199 files — the
whole serial pass is under three seconds. So there is a threshold, and below
it nothing is spawned at all.

The second is that it has to be switchable off. `THOT_JOBS=1` restores the
serial path exactly, which is what a test needs, what a debugger needs, and
what a machine that forbids subprocesses needs. A parallel audit that cannot
be turned back into a serial one is not debuggable.

Chunks are contiguous and `map` preserves their order, so the findings come
out in the same sequence as a serial run — verified positionally, not merely
as a set. An audit that reordered its own output between runs would break
the run-to-run comparison the memory of verdicts depends on.
"""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

JOBS_ENV = "THOT_JOBS"

# Below this many files the serial pass wins outright: on a 199-file tree it
# finishes in less time than eight interpreters take to start.
PARALLEL_THRESHOLD = 400

# More chunks than workers, so one slow file — a minified bundle, a generated
# module ten thousand lines long — does not leave seven cores waiting on the
# eighth.
CHUNKS_PER_WORKER = 4


def jobs_wanted(explicit: int | None = None) -> int:
    """How many processes to use: the argument, the environment, or the cores."""
    if explicit is not None:
        return max(1, explicit)
    raw = os.environ.get(JOBS_ENV, "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass  # a typo in an env var must not stop an audit
    return os.cpu_count() or 1


def chunked(items: list, pieces: int) -> list[list]:
    """Contiguous slices, as even as they divide, never empty."""
    if pieces <= 1 or len(items) <= 1:
        return [items]
    size = max(1, (len(items) + pieces - 1) // pieces)
    return [items[start:start + size] for start in range(0, len(items), size)]


def over_files(function, root: Path, files, *, jobs: int | None = None,
               threshold: int | None = None) -> list:
    """`function(root, files)` run in pieces, concatenated in order.

    `function` is called with `(str(root), chunk)` and must be importable by
    name — a module-level function, not a closure or a lambda — because the
    workers are spawned rather than forked on macOS and Windows, and a spawned
    interpreter re-imports what it is asked to run.

    Any failure to start the pool falls back to running the whole list here.
    A machine that forbids subprocesses must still be able to audit; it should
    just be slower.

    One consequence for anyone embedding Thot rather than running the CLI: a
    spawned worker re-imports `__main__`, so a script that calls `run_audit`
    at module level, outside `if __name__ == "__main__":`, will re-run itself
    in every worker. That is Python's own contract for `multiprocessing` and
    not something a library can undo — `THOT_JOBS=1` is the way out for a
    script that cannot be restructured.
    """
    listed = list(files)
    workers = jobs_wanted(jobs)
    # Read at call time, not bound as a default: a default argument freezes
    # the value at import, and a test that lowered the threshold would then
    # exercise the serial path while believing it had proved the parallel one.
    limit = PARALLEL_THRESHOLD if threshold is None else threshold
    if workers <= 1 or len(listed) < limit:
        return function(str(root), listed)

    pieces = chunked(listed, workers * CHUNKS_PER_WORKER)
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            produced = list(pool.map(function, [str(root)] * len(pieces), pieces))
    except Exception:
        return function(str(root), listed)

    out: list = []
    for part in produced:
        out.extend(part)
    return out
