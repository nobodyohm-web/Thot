"""Audit the whole fused program in one pass.

Three trees live here, and `.thotignore` keeps each out of the others' scope
— otherwise every launch of Thot would sweep 12 000 files and drown its own
four findings under Hermes's 365. The cost of that separation is that
auditing the program required three commands and a mental merge of three
reports.

Each part is audited on its own terms and reported on its own line. A part
that cannot be audited — not authorised, not present — costs its own row and
never the run: a missing Prime must not hide what Hermes said.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from thot.contracts import Severity


@dataclass
class Part:
    """One tree, and what came back from it."""

    name: str
    root: Path
    result: object | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.result is not None

    def counts(self) -> dict[Severity, int]:
        if self.result is None:
            return {}
        found: dict[Severity, int] = {}
        for finding in self.result.findings:
            found[finding.severity] = found.get(finding.severity, 0) + 1
        return found

    def line(self) -> str:
        if not self.ok:
            return f"{self.name:<8} —      {self.error}"
        counts = self.counts()
        total = sum(counts.values())
        breakdown = " · ".join(
            f"{counts[s]} {s.value}" for s in Severity if counts.get(s)
        )
        files = len(self.result.manifest.files)
        return (f"{self.name:<8} {files:>5} fichiers  {total:>4} finding(s)"
                + (f" — {breakdown}" if breakdown else ""))


def parts() -> list[tuple[str, Path]]:
    """The three trees, when they are here."""
    from thot.fusion.locate import hermes_root, prime_root, repo_root

    found = [("thot", repo_root())]
    hermes = hermes_root()
    if hermes is not None:
        found.append(("hermes", hermes))
    prime = prime_root()
    if prime is not None:
        found.append(("prime", prime))
    return found


def audit_all(*, deep: bool = False, engine_name: str = "",
              budget: int = 20, parallel: int = 4,
              require_authorization: bool = True,
              skip: set[str] | None = None,
              on_decided=None) -> list[Part]:
    """Audit every part. One failure never costs the others.

    `on_decided` is called as `(part_name, finding)` the moment a finding is
    settled, so a long run can be reported and persisted as it goes.

    `require_authorization` mirrors `run_audit`'s own knob rather than
    hiding it: auditing a tree is a mandated act, and the one caller that
    skips the mandate — the interactive session, where launching Thot inside
    a directory *is* the mandate — has to be able to say so out loud.
    """
    from thot.pipeline import run_audit
    from thot.errors import AuthorizationError

    done: list[Part] = []
    for name, root in parts():
        engine = None
        if deep:
            try:
                engine = _engine(root, engine_name, parallel)
            except Exception as exc:
                done.append(Part(name, root, error=str(exc).splitlines()[0]))
                continue

        memory = _memory(root)
        # The callback is told which tree the decision came from. Without it
        # a caller counting per part has no boundary to count against — the
        # first tree would be credited with every decision of the run.
        per_part = (
            (lambda finding, part=name: on_decided(part, finding))
            if on_decided is not None else None
        )
        try:
            result = run_audit(root, engine=engine, memory=memory, budget=budget,
                               require_authorization=require_authorization,
                               skip=skip, on_decided=per_part)
            done.append(Part(name, root, result=result))
        except AuthorizationError:
            done.append(
                Part(name, root, error=f"non autorisé — `thot init {root.name}`")
            )
        except Exception as exc:
            done.append(Part(name, root, error=str(exc).splitlines()[0]))
        finally:
            if memory is not None:
                getattr(memory, "close", lambda: None)()
    return done


def _engine(root: Path, name: str, parallel: int):
    from thot.engine.factory import build_engine

    return build_engine(root, max_parallel=parallel, prefer=name)


def _memory(root: Path):
    try:
        from thot.memory import build_memory

        return build_memory(root)
    except Exception:
        return None


def summary(done: list[Part]) -> str:
    """One line for the whole program."""
    total = sum(len(part.result.findings) for part in done if part.ok)
    worst: dict[Severity, int] = {}
    for part in done:
        for severity, count in part.counts().items():
            worst[severity] = worst.get(severity, 0) + count
    breakdown = " · ".join(
        f"{worst[s]} {s.value}" for s in Severity if worst.get(s)
    )
    failed = [part.name for part in done if not part.ok]
    tail = f" · {len(failed)} partie(s) non auditée(s) : {', '.join(failed)}" if failed else ""
    return f"{total} finding(s) sur l'ensemble" + (f" — {breakdown}" if breakdown else "") + tail
