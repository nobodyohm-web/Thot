"""A labelled corpus: code whose answers are known before Thot looks at it.

Everything else in this program measures Thot against Thot. `improve.py`
asks a model whether a finding is real; `evolve.py` guarded `provenance`,
a ratio the engine computes about its own output. Both are circular, and
the circle is not academic — the deep pass spent 638 model judgments and
confirmed 9, while a rule that scored **−100 %** (`xml_unsafe_parse`, which
flagged `defusedxml` — the very remedy its own message recommended) sat
untouched, because nothing in the program could tell right from wrong.

A corpus breaks the circle. Each file is labelled *vulnerable* or *safe* by
its author, in equal numbers, with the weakness class named. Thot's answer
is then simply right or wrong, and no model's confidence enters into it.

The shape read here is BenchProctor's, because that is what exists: a
`testcode/` directory of single-purpose files and an `expectedresults-*.csv`
naming each one. The corpus itself is **not vendored** — eighteen thousand
third-party files do not belong in this repository — so a path is always
given, and `verified()` says whether the file on disk is still the one the
manifest was written for.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

# `benchmark_test_01126.py` and `BenchmarkTest01126.py` name the same case;
# the corpus generator picks per language and the CSV always uses the second.
# Only the digits are identity.
CASE_NUMBER = re.compile(r"(?:benchmark_test_|BenchmarkTest)(\d{4,})", re.I)


def case_key(name: str) -> str | None:
    """The CSV key for a file name, or None if it is not a case at all."""
    found = CASE_NUMBER.search(name)
    return f"BenchmarkTest{found.group(1)}" if found else None


@dataclass(frozen=True)
class Case:
    """One labelled file. `cwe` is the class it is labelled *for*.

    A case counts as detected only when Thot names that class. Flagging
    `BenchmarkTest00004` — a real XSS — for a hardcoded password is not a
    true positive by any reading; it is a right answer to another question.
    """

    key: str
    category: str
    vulnerable: bool
    cwe: int


@dataclass(frozen=True)
class Suite:
    """One framework's worth of cases, and the tree they live in."""

    label: str
    root: Path
    code: Path
    cases: dict[str, Case]

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({case.category for case in self.cases.values()}))

    def counts(self) -> tuple[int, int]:
        vulnerable = sum(1 for case in self.cases.values() if case.vulnerable)
        return vulnerable, len(self.cases) - vulnerable

    def case_of(self, path: str) -> Case | None:
        """The case a finding's path belongs to, or None if it is elsewhere."""
        key = case_key(Path(path).name)
        return self.cases.get(key) if key else None


class NotACorpus(Exception):
    """The path given holds no suite this can read."""


def read_labels(csv: Path) -> dict[str, Case]:
    """The CSV, as cases. Comment lines and short rows are skipped.

    Deliberately not `csv.reader`: the file is `name,category,bool,cwe` with
    no quoting anywhere, and a row whose CWE is not an integer is a corrupt
    row rather than something to guess at.
    """
    cases: dict[str, Case] = {}
    for line in csv.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue
        try:
            cwe = int(parts[3].strip())
        except ValueError:
            continue
        key = parts[0].strip()
        cases[key] = Case(
            key=key,
            category=parts[1].strip(),
            vulnerable=parts[2].strip().lower() == "true",
            cwe=cwe,
        )
    return cases


def load(path: Path | str) -> Suite:
    """One suite, from the directory that holds its CSV and its `testcode/`."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotACorpus(f"{root} n'est pas un dossier")

    found = sorted(root.glob("expectedresults*.csv"))
    if not found:
        raise NotACorpus(f"aucun expectedresults*.csv dans {root}")
    code = root / "testcode"
    if not code.is_dir():
        raise NotACorpus(f"aucun testcode/ dans {root}")

    cases = read_labels(found[0])
    if not cases:
        raise NotACorpus(f"{found[0].name} ne contient aucun cas")
    return Suite(label=root.name, root=root, code=code, cases=cases)


def load_all(path: Path | str) -> list[Suite]:
    """Every suite under `path` — the directory itself if it is one.

    A corpus of three frameworks is three suites, not one: `django`,
    `fastapi` and `flask` label the same weakness in code that looks
    nothing alike, and a rule that only works on one of them is a fact
    worth being able to see.
    """
    root = Path(path).expanduser().resolve()
    try:
        return [load(root)]
    except NotACorpus:
        pass
    suites = []
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        try:
            suites.append(load(child))
        except NotACorpus:
            continue
    if not suites:
        raise NotACorpus(f"aucune suite lisible sous {root}")
    return suites


def verified(suite: Suite, manifest: Path | None = None) -> tuple[bool, str]:
    """Whether the labels still hash to what the manifest recorded.

    A benchmark whose ground truth moved under a measurement is worse than
    no benchmark: every number since is wrong and nothing says so. This is
    cheap, and it is the only claim `thot bench` makes about provenance.
    """
    import json

    manifest = manifest or (suite.root.parent / "benchproctor-manifest.json")
    if not manifest.is_file():
        return False, "aucun manifeste — les étiquettes ne sont pas vérifiées"
    try:
        declared = json.loads(manifest.read_text(encoding="utf-8"))
        expected = declared["suites"][suite.label]["csv_sha256"]
    except (ValueError, KeyError, OSError):
        return False, f"le manifeste ne décrit pas {suite.label}"

    csv = sorted(suite.root.glob("expectedresults*.csv"))[0]
    digest = hashlib.sha256(csv.read_bytes()).hexdigest()
    if digest == expected:
        return True, f"étiquettes vérifiées ({digest[:12]})"
    return False, f"étiquettes modifiées : {digest[:12]} ≠ {expected[:12]}"
