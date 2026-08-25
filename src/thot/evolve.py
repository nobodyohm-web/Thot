"""The loop that changes the code, and can be trusted to.

`improve.py` says it plainly in its own docstring: *what it never does is
edit code*. It sharpens the program's judgement of itself and leaves every
real defect exactly where it was. That line is defensible — a loop that
argues is cheap to be wrong about — but it is not self-improvement, which is
what the program claims to do.

This crosses the line, and everything here is about the one question that
makes crossing it safe: **what happens when the change is wrong.**

The answer is three rules, and none of them is advice.

- The test suite decides. Not the agent's report of what it did, not a
  model's confidence, not a diff that reads well. A change is kept when the
  suite is green after it and reverted when it is not.
- The revert is byte for byte. Every file inside the scope is read before
  the agent is let near it; a failed attempt puts back what was there,
  removes what was created, and restores what was deleted.
- Nothing here touches git. A loop that can edit code *and* commit is a loop
  that can rewrite the history it broke — so this module never runs git at
  all, and a test asserts that about its source.

What it is not: an oracle. A patch can be green and still wrong, and the
literature on automated program repair calls that overfitting. The suite is
a floor, not a proof, and this module reports what it changed so a human can
disagree.

---

Two things were added after the loop had run and the result was measured,
and both come from the same finding: **the loop worked and changed nothing
worth having.**

*What it was scored on was wrong.* The guarded number was `provenance` — a
ratio Thot computes over its own findings. Nothing outside the program was
consulted, so "better" meant "better by its own account", and a rule that
scored −100 % against real labelled code sat untouched through every round.
`thot.bench` is the answer: code labelled vulnerable or safe by someone
else, in equal numbers. `bench_metrics` makes that the gate, and Youden's J
has no cheap cheat — raising a threshold until the report empties, which
moved `provenance` the right way, drops true positives and lowers J.

*And only one agent was ever writing.* `agent_apply` takes an engine,
singular. So did the session: `Cascade.turn` picks one member and calls it,
falling back to the other only on an error. A program whose premise is the
fusion of two agents was, everywhere it mattered, a switch between them —
and a switch is capped at the better of the two by construction. It can
lose less. It cannot win more.

`fused_apply` is the fusion actually happening: Hermes specifies, Prime
builds, and the corpus decides. Neither half is a verdict. See its docstring
for why the order is not arbitrary.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

# What an attempt is allowed to touch, and therefore what is snapshotted.
# A snapshot of a 7 000-file tree before every attempt is a snapshot nobody
# takes; scope is what makes the safety affordable.
DEFAULT_SCOPE = ("src", "tests")

# Directories never read, whatever the scope says.
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules"}

# `sys.executable`, never the bare name. `python` is not on the PATH of a
# machine that installs its interpreters through uv or pyenv — measured
# here, on the first real run: the gate raised FileNotFoundError, the loop
# read that as "the change did not pass", and reverted a change that had
# never been judged. A judge that cannot start must not look like a verdict.
DEFAULT_GATE = [sys.executable, "-m", "pytest", "tests/", "-q", "-x"]


# Which way a measurement is allowed to move. Nothing here ever rewards
# *finding less*: an agent told to reduce noise gets there by hardening the
# threshold until the report is empty, and a guard that calls that a win is
# how a loop optimises itself into uselessness.
DEFAULT_GUARDS = {"provenance": "ne_baisse_pas"}


@dataclass(frozen=True)
class Gate:
    """What decides whether a change survives: a command, and measurements.

    The command alone was not enough, and the failure is quiet. No test in
    this repository asserts that named provenance stays at 31 %, so a patch
    that took it to 12 % passed green — the suite is a floor on *breakage*,
    never a floor on *quality*. `metrics` is read before and after, and a
    guarded measurement that moved the wrong way reverts the change even
    though every test passed.

    A measurement that cannot be taken is not evidence that nothing got
    worse. It rejects, because the alternative is a loop that learns to
    break its own instruments.
    """

    command: Sequence[str]
    root: Path | None = None
    timeout: int = 1800
    metrics: Callable[[Path], dict[str, float]] | None = None
    guards: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_GUARDS))
    tolerance: float = 0.0

    def measure(self, root: Path) -> tuple[dict[str, float] | None, str]:
        if self.metrics is None:
            return {}, ""
        try:
            return dict(self.metrics(root)), ""
        except Exception as exc:
            return None, f"mesure impossible : {type(exc).__name__}: {exc}"

    def compare(self, before: dict[str, float] | None,
                after: dict[str, float] | None) -> tuple[bool, str]:
        """Whether the guarded measurements survived the change."""
        if before is None or after is None:
            return False, "mesure impossible — un changement non mesuré n'est pas un changement sûr"
        moved: list[str] = []
        for name, direction in self.guards.items():
            if name not in before or name not in after:
                continue
            was, now = before[name], after[name]
            margin = abs(was) * self.tolerance
            if direction == "ne_baisse_pas" and now < was - margin:
                moved.append(f"{name} {was:.3g} → {now:.3g}")
            if direction == "ne_monte_pas" and now > was + margin:
                moved.append(f"{name} {was:.3g} → {now:.3g}")
        if moved:
            return False, "régression : " + " · ".join(moved)
        kept = " · ".join(f"{k} {after[k]:.3g}" for k in sorted(self.guards)
                          if k in after)
        return True, ("suite verte" + (f" · {kept}" if kept else ""))

    def passes(self, root: Path) -> tuple[bool, str]:
        try:
            done = subprocess.run(
                list(self.command), cwd=str(self.root or root),
                capture_output=True, text=True, timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"la vérification n'a pas pu tourner : {exc}"
        if done.returncode == 0:
            return True, "suite verte"
        tail = (done.stdout or done.stderr or "").strip().splitlines()[-6:]
        return False, "tests en échec — " + " / ".join(tail)


@dataclass
class Attempt:
    """One goal, handed to one agent, and what became of it."""

    goal: str
    before: dict[str, bytes] = field(default_factory=dict)
    summary: str = ""
    touched: tuple[str, ...] = ()
    kept: bool = False
    reason: str = ""
    error: str | None = None


def thot_metrics(root: Path) -> dict[str, float]:
    """What an audit of `root` looks like, as numbers a guard can compare.

    A subprocess, and not a call. Thot measuring Thot has the module under
    change already imported: an in-process measurement reads the version
    loaded at startup, reports that nothing moved, and lets every regression
    through. The one thing this function must not be is fast and wrong.

    `provenance` is the guarded number — the share of taint findings whose
    source rule the engine could name. It is the one that moves when the
    engine gets better or worse at following a value, and the one no
    threshold change can fake: hardening the floor removes findings from
    both halves of the ratio.

    `candidats` is reported and deliberately *not* guarded. Fewer candidates
    is what an agent produces when it is told to reduce noise and reaches
    for the threshold instead of the analysis.
    """
    import json
    import sys

    done = subprocess.run(
        [sys.executable, "-m", "thot", "audit", str(root), "--json", "--all"],
        capture_output=True, text=True, timeout=1800,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    if done.returncode not in (0, 1):
        raise RuntimeError((done.stderr or "audit en échec").strip()[:200])
    findings = json.loads(done.stdout)["findings"]
    taint = [f for f in findings
             if not f["rule"].startswith(("pattern.", "suppression."))]
    named = sum(1 for f in taint if f.get("source_rule"))
    return {
        "provenance": (named / len(taint)) if taint else 0.0,
        "candidats": float(len(taint)),
    }


# What a corpus-scored run guards, and why these two and not the others.
#
# `youden` is the whole measurement: caught minus invented. Guarding it
# alone would already close the hole `provenance` left open, because on a
# balanced corpus both ways of faking progress lose. Finding less drops true
# positives. Flagging everything scores TPR 100 %, FPR 100 %, J zero.
#
# `youden_holdout` covers the one cheat the number itself cannot see. A rule
# keyed on what a particular benchmark file happens to look like raises the
# score and helps nobody, and from the outside that is indistinguishable
# from having got better. It is distinguishable from *the other two
# frameworks*, which express the same weakness in code that reads nothing
# alike. A change that moves the suites it was optimised against and not the
# one it never saw has said what it is.
#
# `fpr` is deliberately *not* guarded. J already prices it, and a separate
# floor under it forbids the honest trade — twenty more true positives for
# one more false one raises J and would be refused. One number, one guard.
BENCH_GUARDS = {"youden": "ne_baisse_pas", "youden_holdout": "ne_baisse_pas"}


def bench_metrics(corpus: Path | str, *, hold_out: str = "",
                  floor: str = "medium",
                  root: Path | None = None) -> Callable[[Path], dict[str, float]]:
    """A `Gate.metrics` that asks a labelled corpus instead of asking Thot.

    A subprocess, for the reason `thot_metrics` gives above and which is
    worth repeating because getting it wrong is silent: the module under
    change is already imported here, so an in-process reading measures the
    version loaded at startup, reports that nothing moved, and keeps every
    regression. The correct measurement costs one interpreter start.
    """
    from thot.bench.run import measure_out_of_process

    def measure(_: Path) -> dict[str, float]:
        return measure_out_of_process(corpus, hold_out=hold_out, floor=floor,
                                      root=root)

    return measure


def bench_gate(corpus: Path | str, *, hold_out: str = "",
               floor: str = "medium", command: Sequence[str] = DEFAULT_GATE,
               root: Path | None = None) -> Gate:
    """The tests as a floor, the corpus as the verdict.

    Both, and in that order. The suite alone cannot see a change that makes
    Thot worse at its job — no test in this repository asserts a detection
    rate, so a rule that stops firing passes green. The corpus alone cannot
    see a change that breaks everything *around* the rule. Neither is
    redundant, and `evolve` already only measures a tree whose tests pass,
    so the expensive half never runs on a broken one.
    """
    return Gate(command=command, metrics=bench_metrics(corpus, hold_out=hold_out,
                                                       floor=floor, root=root),
                guards=dict(BENCH_GUARDS))


# How many of the worst categories one run works through, and how many
# example files each goal carries. Both small on purpose: an agent handed
# forty goals writes forty shallow changes, and the loop is judged on
# whether the number moved, not on how much was attempted.
DEFAULT_TARGETS = 5
GOAL_SAMPLES = 4


def goals_from_bench(score, *, limit: int = DEFAULT_TARGETS,
                     corpus: Path | str = "") -> list[str]:
    """The measurement, turned into work — worst first.

    This is what closes the loop. Until now a goal was a sentence the user
    typed, which means the loop could only ever chase what a human already
    suspected. A goal built from the score is the program saying where it is
    weakest in numbers it did not choose, and the same numbers then decide
    whether the answer helped.

    Order matters. `Score.worst` ranks by J and breaks ties on how many cases
    are at stake, so an inverted rule outranks a missing one — a category at
    −100 % is actively costing points, and a category at 0 % is only failing
    to earn them.
    """
    from thot.bench.score import already_claimed, misnamed

    claims = already_claimed(score)
    seen = misnamed(score)
    base = Path(corpus).expanduser() if corpus else None
    goals: list[str] = []

    # Ranked last, never first: a category Thot already fires on cannot be
    # won by any honest change, and the cheapest way to appear to win it is
    # to widen the CWE mapping until it covers the label. That is the loop
    # learning to score instead of to detect, and the corpus would applaud.
    for name, tally in score.worst(limit,
                                   prefer=lambda n: claims(n) and not seen(n)):
        cwe = score.cwe.get(name, 0)
        missed = score.missed.get(name, ())[:GOAL_SAMPLES]
        invented = score.invented.get(name, ())[:GOAL_SAMPLES]

        lines = [
            f"Catégorie « {name} » (CWE-{cwe}) : J = {tally.youden:+.0%} "
            f"— {tally.tp} vrais positifs sur {tally.positives} cas "
            f"vulnérables, {tally.fp} faux positifs sur {tally.negatives} "
            f"cas sains.",
        ]
        if tally.youden < 0:
            lines.append(
                "La règle est *inversée* : elle signale le code sain et rate "
                "le code vulnérable. La corriger vaut plus que d'en ajouter une."
            )
        elif tally.tp == 0 and tally.fp == 0 and seen(name):
            # Say plainly that this one is not a missing rule, and forbid the
            # shortcut by name. Told only "a rule already claims this class",
            # an agent adds the label to the mapping, the score rises, and
            # the report starts naming a weakness the code does not have.
            lines.append(
                f"Thot signale déjà {score.seen.get(name, 0)} de ces cas "
                f"vulnérables, sous une *autre* classe que CWE-{cwe} : la "
                f"règle marche, c'est la classe annoncée qui diffère. "
                f"N'ajoute PAS CWE-{cwe} au mapping d'une règle existante "
                f"pour faire monter le chiffre — la relation taxonomique a "
                f"été instruite et rejetée. Seule une règle qui distingue "
                f"vraiment cette faiblesse de celle déjà détectée compte, "
                f"et il se peut qu'il n'y en ait pas."
            )
        elif tally.tp == 0 and tally.fp == 0 and claims(name):
            # The cheaper half of the silence, and it must not be described as
            # the other one. Told "there is no rule", an agent writes a second
            # rule beside the one that already exists and neither fires.
            lines.append(
                f"Thot ne produit rien du tout sur cette classe, et pourtant "
                f"une règle revendique déjà CWE-{cwe} : elle existe et ne "
                f"matche jamais ce code. Cherche pourquoi elle ne se "
                f"déclenche pas avant d'en écrire une autre."
            )
        elif tally.tp == 0 and tally.fp == 0:
            lines.append(
                "Thot ne produit rien du tout sur cette classe, et aucune "
                "règle ne revendique CWE-%d — il manque une règle, pas un "
                "réglage." % cwe
            )
        if missed:
            lines.append("Cas vulnérables non détectés : "
                         + ", ".join(_case_path(base, k) for k in missed))
        if invented:
            lines.append("Cas sains signalés à tort : "
                         + ", ".join(_case_path(base, k) for k in invented))
        goals.append("\n".join(lines))

    return goals


def _case_path(base: Path | None, key: str) -> str:
    """A case key as something an agent can open.

    `combine` qualifies keys as `suite/BenchmarkTest01126`; the file on disk
    is `<corpus>/<suite>/testcode/benchmark_test_01126.py`. Handing over the
    key alone would make every goal start with the agent hunting for the
    file it was told about.
    """
    suite, _, name = key.rpartition("/")
    digits = "".join(ch for ch in name if ch.isdigit())
    leaf = f"benchmark_test_{digits}.py" if digits else name
    if base is None:
        return f"{suite}/testcode/{leaf}" if suite else leaf
    if suite and base.name == suite:
        # `load_all` accepts being pointed straight at one suite, and
        # `combine` stamps the suite name onto every key regardless — so
        # `--corpus …/bp/flask` named `…/bp/flask/flask/testcode/x.py` in
        # every goal it wrote, a path the agent cannot open.
        return str(base / "testcode" / leaf)
    return str(base / suite / "testcode" / leaf) if suite else str(base / leaf)


# What a run remembers about the last one, and why it has to.
#
# Goals come from the measurement, and the measurement barely moves in one
# round. So the next run reads the same worst categories, hands Hermes the
# same failing files, and gets back — reasonably — the same specification
# that was already built, measured, and reverted. Without a record, `--rounds
# 5` is one attempt tried five times at five times the cost, and the loop
# looks busy while standing still.
#
# JSONL and append-only: a run that dies halfway leaves every completed
# attempt readable, which a rewritten JSON object would not.
LEDGER = "evolve-log.jsonl"

# Only the category is kept, not the whole goal line — the counts inside it
# change between runs by construction, so a goal is never byte-identical to
# the one before even when it is the same work.
_CATEGORY = re.compile(r"«\s*([^»]+?)\s*»")


def goal_key(goal: str) -> str:
    """What two runs would call the same piece of work."""
    found = _CATEGORY.search(goal)
    return found.group(1) if found else goal.strip().splitlines()[0][:80]


def remember(attempts: Sequence["Attempt"], path: Path) -> None:
    """Append what this run tried, kept and reverted."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with path.open("a", encoding="utf-8") as out:
        for attempt in attempts:
            out.write(json.dumps({
                "when": stamp,
                "key": goal_key(attempt.goal),
                "kept": attempt.kept,
                "reason": attempt.reason,
                "summary": attempt.summary,
                "touched": list(attempt.touched[:12]),
            }, ensure_ascii=False) + "\n")


def recall(path: Path, *, keys: Sequence[str] = (), limit: int = 12) -> str:
    """The relevant history, as a paragraph for an agent's brief.

    Reverted attempts are what matters and are listed first: an agent that
    knows a change was built and lost points can propose a different one,
    while an agent that does not will propose that same change again. Kept
    attempts are listed too but shorter — they are already in the code the
    agent is about to read.
    """
    path = Path(path)
    if not path.is_file():
        return ""
    wanted = set(keys)
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue  # a half-written line from a run that was killed
        if not wanted or row.get("key") in wanted:
            rows.append(row)
    if not rows:
        return ""

    reverted = [r for r in rows if not r.get("kept")][-limit:]
    kept = [r for r in rows if r.get("kept")][-limit:]
    parts: list[str] = []
    if reverted:
        parts.append("Déjà tenté et annulé — ne repropose pas la même chose :")
        parts += [f"  · {r['key']} : {r.get('summary') or 'sans résumé'}"
                  f" — {r.get('reason', '')}" for r in reverted]
    if kept:
        parts.append("Déjà appliqué et gardé :")
        parts += [f"  · {r['key']} : {r.get('summary') or 'sans résumé'}"
                  for r in kept]
    return "\n".join(parts)


DESIGNER = """Tu conçois une correction pour Thot. Tu n'écris pas le code.

Ce que la mesure dit, sur du code étiqueté par quelqu'un d'autre :
{goal}

Lis les fichiers d'exemple cités, et lis comment Thot les traite
aujourd'hui : `src/thot/codemap/catalog.py` pour les règles de teinte,
`src/thot/guard/patterns.py` pour les motifs, `src/thot/report/cwe.py` pour
la classe de faiblesse associée à chaque règle.

Rends une spécification, dans cet ordre :
1. Pourquoi Thot rate (ou invente) ces cas. Une cause, pas une hypothèse :
   nomme la règle, le fichier, la ligne.
2. Le changement exact — quelle règle, quel fichier, quelle forme.
3. Ce qui pourrait casser ailleurs, et ce que ça ferait aux autres
   catégories.
4. Le test qui exprimerait le changement.

Si les cas cités ne se ressemblent pas assez pour qu'une seule règle les
couvre, dis-le et propose la plus petite chose qui marche. Une spécification
honnête et étroite vaut mieux qu'une large et inventée : ce qui sera écrit
d'après toi sera mesuré, pas cru."""


FUSED_BUILDER = """Tu appliques une spécification au code de Thot.

La spécification, écrite par l'autre agent d'après la mesure :
{design}

Objectif mesuré dont elle vient :
{goal}

Règles, dans l'ordre :
1. Écris la modification dans les fichiers. Ne propose pas un patch : fais-le.
2. Écris le test qui exprime le changement.
3. Ne touche pas à git. Ni commit, ni checkout, ni reset, ni stash.
4. Reste dans {scope}. Un fichier hors de là ne sera pas gardé.
5. Si la spécification est fausse — tu lis le code et la cause n'est pas
   celle qu'elle nomme — ne l'applique pas. Dis en quoi elle se trompe et ne
   modifie rien. Un tour vide est une réponse ; appliquer une spécification
   que tu sais fausse n'en est pas une.

Ni ta confiance ni la sienne ne décide. La suite de tests puis le corpus
étiqueté décident, et ce qui baisse le score est annulé fichier par fichier.
Termine par UNE ligne résumant ce que tu as changé."""


def fused_apply(cascade, *, brief: str = "", scope=DEFAULT_SCOPE,
                history: Callable[[str], str] | None = None,
                on_design: Callable[[str, str], None] | None = None):
    """Hermes specifies, Prime builds, the corpus decides.

    `agent_apply` above takes one engine and is honest about it. This takes
    the cascade and uses **both members on every goal**, which is the thing
    the program claims to do and did nowhere: `Cascade.turn` picks one member
    and calls it, reaching for the second only when the first returns an
    error. A turn like that is capped at the better of the two agents by
    construction — it can lose less than either, never win more.

    Two agents are worth more than one only if they do different work. So:

    - **Hermes reads the measurement and writes a specification.** It never
      touches a file. Its output is a claim about cause — which rule, which
      line, why these cases and not others.
    - **Prime reads the specification and writes the code.** It is told
      explicitly to refuse a specification the code contradicts, because an
      implementer that cannot say no is a relay, and a relay adds nothing.
    - **Neither one decides.** The tests are a floor and the labelled corpus
      is the verdict. That is what makes the pairing safe to run unattended:
      a wrong specification confidently built produces a lower score and is
      reverted byte for byte, and no amount of agreement between the two
      changes that.

    The order is not arbitrary either. Design-then-build can be checked at
    the seam — Prime sees Hermes' reasoning before committing to it, and
    says so when it is wrong. Build-then-review cannot: by the time the
    second agent looks, the first has already decided.

    `history` is handed the goal and returns what past runs tried against it;
    `recall` is the implementation. It goes to Hermes and not to Prime,
    because it is a constraint on what to *design*, and Prime is meant to
    judge the specification it gets on the code in front of it rather than
    on who failed before.
    """
    from thot.engine.base import AgentTask

    try:
        hermes = cascade.members["hermes"]
        prime = cascade.members["prime"]
    except (AttributeError, KeyError, TypeError):
        raise NoFusion(
            "la boucle fusionnée demande les deux agents ; "
            "`thot fusion status` dit lequel manque"
        ) from None

    count = {"n": 0}

    def apply(goal: str, attempt: "Attempt") -> str:
        count["n"] += 1
        turn = count["n"]

        past = (history(goal) if history is not None else "") or ""
        spec = hermes.run(AgentTask(
            id=f"evolve-design-{turn}",
            instructions=DESIGNER.format(goal=goal),
            context=f"{brief}\n\n{past}".strip() if past else brief,
            tier="deep",
        ))
        if spec.error:
            raise RuntimeError(f"conception : {spec.error}")
        design = (spec.text or "").strip()
        if not design:
            # Not an error, and not something to paper over with a default.
            # Prime handed an empty specification writes whatever it likes,
            # which is the single-agent loop again wearing two names.
            return ""
        if on_design is not None:
            on_design(goal, design)

        built = prime.run(AgentTask(
            id=f"evolve-build-{turn}",
            instructions=FUSED_BUILDER.format(
                design=design, goal=goal, scope=", ".join(scope)),
            context=brief,
            tier="deep",
        ))
        if built.error:
            raise RuntimeError(f"application : {built.error}")
        lines = [line for line in (built.text or "").strip().splitlines()
                 if line.strip()]
        return lines[-1][:200] if lines else ""

    return apply


class NoFusion(Exception):
    """The fused loop was asked for and both agents are not there."""


def snapshot_of(root: Path, scope: Sequence[str] = DEFAULT_SCOPE) -> dict[str, bytes]:
    """Every file the run may touch, read before it is let near them."""
    root = Path(root)
    taken: dict[str, bytes] = {}
    for name in scope:
        base = root / name
        if not base.is_dir():
            if base.is_file():
                taken[base.relative_to(root).as_posix()] = base.read_bytes()
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if SKIP & set(path.relative_to(root).parts):
                continue
            taken[path.relative_to(root).as_posix()] = path.read_bytes()
    return taken


def _changed(root: Path, before: dict[str, bytes],
             scope: Sequence[str]) -> tuple[str, ...]:
    after = snapshot_of(root, scope)
    names = set(before) | set(after)
    return tuple(sorted(
        name for name in names if before.get(name) != after.get(name)
    ))


def restore(root: Path, before: dict[str, bytes],
            scope: Sequence[str] = DEFAULT_SCOPE) -> tuple[str, ...]:
    """Put the tree back exactly as it was. Returns what had to be undone."""
    root = Path(root)
    after = snapshot_of(root, scope)
    undone: list[str] = []

    for name, content in before.items():
        target = root / name
        if after.get(name) != content:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            undone.append(name)

    # A revert that only rewrites what it knew about leaves the new file
    # behind, and a stray module is exactly how a green suite goes red on
    # the next run.
    for name in after:
        if name not in before:
            (root / name).unlink(missing_ok=True)
            undone.append(name)
    return tuple(sorted(undone))


def _under(root: Path, name: str) -> Path | None:
    """A scope entry resolved inside `root`, or None if it escapes it.

    `--scope` is a comma-separated string a user types, and everything below
    treats its entries as directories to read, copy and — here — delete.
    `..` resolves to the parent of the repository and an absolute entry
    discards `root` entirely, so this is checked before anything destructive
    rather than left to `relative_to` to raise halfway through.
    """
    root = Path(root).resolve()
    candidate = (root / name).resolve()
    if candidate == root:
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def keep_a_copy(root: Path, into: Path,
                scope: Sequence[str] = DEFAULT_SCOPE) -> Path:
    """A whole-tree copy outside the repository, before the first attempt.

    The per-attempt revert is precise and in-process; this is the answer to
    the failure it cannot cover — the process dying between the edit and the
    restore. It costs one copy per run.

    Each scope directory is *replaced*, never merged into. `thot evolve`
    hands the same `~/.thot/evolve-backup` to every run, and `copytree` with
    `dirs_exist_ok=True` writes the new tree over whatever the last run left:
    a file deleted since then survives in the copy, and what comes back is a
    tree that never existed at any moment. A safety net has to be a snapshot
    of one instant or it is worse than none.
    """
    into = Path(into)
    into.mkdir(parents=True, exist_ok=True)
    for name in scope:
        source = _under(Path(root), name)
        if source is None or not source.is_dir():
            continue
        target = into / source.relative_to(Path(root).resolve())
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*SKIP))
    return into


BUILDER = """Tu modifies le code de Thot, directement dans les fichiers.

Objectif de ce tour :
{goal}

Règles, dans l'ordre :
1. Écris la modification dans les fichiers. Ne propose pas un patch, ne
   décris pas ce qu'il faudrait faire : fais-le.
2. Si le comportement change, écris ou adapte le test qui l'exprime, avant.
3. Ne touche pas à git. Ni commit, ni checkout, ni reset, ni stash.
4. Reste dans {scope}. Un fichier hors de là ne sera pas gardé.
5. Si l'objectif est déjà atteint, ou si tu ne vois pas quoi faire sans
   deviner, ne modifie rien et dis-le. Un tour vide est une réponse
   acceptable ; une modification au hasard n'en est pas une.

La suite de tests décide : ce qui la casse est annulé, fichier par fichier.
Termine par UNE ligne résumant ce que tu as changé."""


def agent_apply(engine, *, brief: str = "", scope=DEFAULT_SCOPE, tier: str = "deep"):
    """An `apply` that hands the goal to a real agent, with its own tools.

    The agent edits the working tree itself — Thot does not relay a patch.
    That is the point of driving an agent rather than a model: Hermes and
    Prime each hold file and shell tools, their own memory and their own
    credentials, and Thot never sees a token of theirs.
    """
    from thot.engine.base import AgentTask

    count = {"n": 0}

    def apply(goal: str, attempt: "Attempt") -> str:
        count["n"] += 1
        result = engine.run(AgentTask(
            id=f"evolve-{count['n']}",
            instructions=BUILDER.format(goal=goal, scope=", ".join(scope)),
            context=brief,
            tier=tier,
        ))
        if result.error:
            raise RuntimeError(result.error)
        lines = [line for line in (result.text or "").strip().splitlines() if line.strip()]
        return lines[-1][:200] if lines else ""

    return apply


def evolve(
    root: Path,
    *,
    goals: Sequence[str],
    apply: Callable[[str, Attempt], str],
    gate: Gate | None = None,
    scope: Sequence[str] = DEFAULT_SCOPE,
    stop_after_idle: int = 3,
    backup: Path | None = None,
    on_attempt: Callable[[Attempt], None] | None = None,
) -> list[Attempt]:
    """Work a list of goals, keeping only what the gate accepts.

    `apply` is what actually edits — an agent in production, a function in a
    test. It is handed the goal and the attempt, whose `before` already holds
    the snapshot, and returns a one-line summary of what it did.

    `stop_after_idle` ends the run when that many attempts in a row change
    nothing. An agent that has run out of ideas says so by doing nothing, and
    the next identical round buys the same nothing.
    """
    root = Path(root)
    gate = gate or Gate(command=DEFAULT_GATE)
    if backup is not None:
        keep_a_copy(root, backup, scope)

    # The measurement the run is judged against, taken once on the tree as
    # it stands. Re-measuring before every attempt would let a change that
    # lost ground become the new normal for the next one.
    baseline, why_not = gate.measure(root)
    if why_not:
        baseline = None

    done: list[Attempt] = []
    idle = 0

    for goal in goals:
        attempt = Attempt(goal=goal, before=snapshot_of(root, scope))
        try:
            attempt.summary = apply(goal, attempt) or ""
        except Exception as exc:                      # an agent, not our code
            attempt.error = f"{type(exc).__name__}: {exc}"
            attempt.reason = "l'agent n'a pas rendu de changement"
            restore(root, attempt.before, scope)
            done.append(attempt)
            if on_attempt is not None:
                on_attempt(attempt)
            idle += 1
            if idle >= stop_after_idle:
                break
            continue

        attempt.touched = _changed(root, attempt.before, scope)
        if not attempt.touched:
            attempt.reason = "aucun fichier modifié"
            done.append(attempt)
            if on_attempt is not None:
                on_attempt(attempt)
            idle += 1
            if idle >= stop_after_idle:
                break
            continue

        idle = 0
        green, why = gate.passes(root)
        if green:
            # Only now: measuring a tree whose tests do not pass measures
            # nothing, and costs a full pass to say so.
            after, failed = gate.measure(root)
            green, why = gate.compare(baseline, after)
            if failed:
                why = failed
        attempt.kept = green
        attempt.reason = why
        if not green:
            restore(root, attempt.before, scope)
        done.append(attempt)
        if on_attempt is not None:
            on_attempt(attempt)

    return done
