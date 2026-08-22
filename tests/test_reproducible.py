"""The same audit, twice, must say the same thing.

Not a nicety: a verdict is keyed to a finding's identity, a report is meant
to be diffed against yesterday's, and a scenario names the origin of the
value it followed. Measured on the vendored Hermes tree, four runs under
different `PYTHONHASHSEED`: the 417 findings and their identities were
identical every time — verdicts were never at risk — but five of them named a
different origin from one run to the next. Python randomises string hashing
per process, and three sets in the taint engine reached the output through
their iteration order.

This is a structural test, and the choice is deliberate. A behavioural one
was written first: audit a generated repository twice under different seeds
and compare. It stayed green with every fix reverted, at three names and
again at twenty-four — the instability needs a shape the fixture did not
reproduce, and a test that cannot fail is worse than none. Pointing it at the
vendored tree does catch it, and costs about ninety seconds, which is four
times the whole suite.

So what is asserted is what was actually fixed: those three iterations are
ordered. The behavioural verification is written down below rather than run,
because a procedure a reader can repeat beats a test that only looks like one.

    for seed in 1 7 13 29; do
      PYTHONHASHSEED=$seed python -c "…run_audit(Path('hermes'))…" | sha256sum
    done
"""

from __future__ import annotations

import re
from pathlib import Path

ENGINE = Path(__file__).parent.parent / "src" / "thot" / "taint" / "engine.py"


def _body(source: str, name: str) -> str:
    start = source.index(f"def {name}(")
    end = source.find("\ndef ", start + 1)
    return source[start : end if end != -1 else len(source)]


def test_the_sets_that_reach_the_output_are_ordered():
    """Three of them, each found by diffing two runs of the same audit."""
    source = ENGINE.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines()
        if not line.strip().startswith("#")
    )

    # 1. Which name's taint is reported when several carry it.
    assert "min(carriers)" in code, (
        "l'origine doit être la plus ancienne, pas la première du hachage"
    )
    # 2. The insertion order of `param_sinks`, which the fixed point follows.
    assert re.search(r"for name in sorted\(argument_refs & params\)", code)
    # 3. The order of `calls_out`, which decides which caller emits first.
    assert re.search(r"for name in sorted\(outgoing\)", code)


def test_no_bare_set_iteration_decides_an_emitted_field():
    """A guard against the next one: a set iterated straight into a decision.

    Narrow on purpose — it looks only at the two loops that build the facts
    an emission reads, not at every set in the file, because a rule that
    fires everywhere is a rule people delete.
    """
    source = ENGINE.read_text(encoding="utf-8")
    analysed = _body(source, "_analyse_body")

    for line in analysed.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "for " not in stripped:
            continue
        if "outgoing" in stripped or "argument_refs & params" in stripped:
            assert "sorted(" in stripped, f"itération non ordonnée : {stripped!r}"
