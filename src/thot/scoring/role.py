"""What a file is *for*, which decides who can reach what is in it.

The call graph answers "can an entry point reach this symbol". It cannot
answer "is this file an attack surface at all". A `child_process.exec` in
`packages/ai/test/stream.test.ts` fires the same rule as one in
`src/core/clipboard.ts`, and the graph says the same thing about both —
because in neither case does a Python call graph reach TypeScript.

Measured on the two programs Thot ships with: 12 of Hermes's 25 HIGH
findings and 6 of Prime's 11 are in test or example code. Half of the top of
the report is about code nobody outside the repository runs, which is how a
report stops being read.

The discount is deliberate, not a suppression. Test code runs on developer
machines and in CI — a compromised dependency there is the exact shape of a
supply-chain attack — so a finding is demoted, kept in the report, and told
apart by name.
"""

from __future__ import annotations

from enum import Enum
from pathlib import PurePosixPath


class Role(str, Enum):
    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "exemple"


# Matched as whole path segments, never as substrings: `latest/` is not a
# test directory and `contest.py` is not a test file.
TEST_DIRS = frozenset({
    "test", "tests", "spec", "specs", "__tests__", "testdata", "test_data",
    "fixtures", "__fixtures__", "benchmarks", "bench", "e2e", "integration_tests",
})

EXAMPLE_DIRS = frozenset({
    "example", "examples", "demo", "demos", "samples", "sample", "cookbook",
})

TEST_PREFIXES = ("test_",)
TEST_SUFFIXES = (
    "_test.py", "_test.ts", "_test.js", "_test.go",
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
)
TEST_NAMES = frozenset({"conftest.py"})


def role_of(path: str) -> Role:
    """What this repo-relative path is for.

    Conservative on purpose: anything unrecognised is production. Calling
    production code a test hides a real defect; calling a test production
    only costs a finding one rung, and the rung is recoverable.
    """
    parts = PurePosixPath(str(path)).parts
    if not parts:
        return Role.PRODUCTION

    directories, name = parts[:-1], parts[-1]

    # A directory wins over a filename: `examples/foo/test_helper.py` is an
    # example whose helper happens to be named like a test.
    for segment in directories:
        lowered = segment.lower()
        if lowered in EXAMPLE_DIRS:
            return Role.EXAMPLE
        if lowered in TEST_DIRS:
            return Role.TEST

    lowered = name.lower()
    if lowered in TEST_NAMES:
        return Role.TEST
    if lowered.startswith(TEST_PREFIXES) or lowered.endswith(TEST_SUFFIXES):
        return Role.TEST
    return Role.PRODUCTION


# One factor for both non-production roles. In *this* program neither is
# reachable from an entry point, which is the question severity answers.
#
# An example carries a second risk this number does not model: it exists to
# be copied, so a dangerous pattern in one propagates into code that is
# reachable. That is a judgement about propagation, not about reach, and
# folding it in here would hide two different things behind one number. The
# role is recorded on the finding instead, so a reader sees `exemple` and
# decides.
ROLE_WEIGHT = {
    Role.PRODUCTION: 1.0,
    Role.TEST: 0.6,
    Role.EXAMPLE: 0.6,
}


def role_weight(role: Role) -> float:
    return ROLE_WEIGHT.get(role, 1.0)
