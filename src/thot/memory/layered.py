"""Several verdict stores, read in order, written to one.

The arrangement an audited team actually needs: the repository's committed
verdicts, reviewed in pull requests, plus whatever you have decided locally
and not published yet.

Two rules, and both are deliberate:

* **reads fall through, first hit wins**, repository before local. A
  decision that survived review outranks a note you made to yourself.
* **writes go to one designated layer, local by default.** A tool that
  silently edited a committed file every time you typed `/verdict` would
  produce pull-request diffs nobody asked for. You decide locally, then
  publish on purpose with `thot verdicts --share`.

Hermes orders its memory providers bundled-first for the mirror-image
reason: so a directory dropped into a working tree cannot silently
redirect the agent's memory. Same instinct, opposite direction, because
here the working tree is the reviewed artefact and the local store is the
scratch pad.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from thot.memory.base import Memory, Verdict


@dataclass
class LayeredMemory:
    """A chain of verdict stores."""

    layers: list[Memory] = field(default_factory=list)
    write_index: int = -1  # -1 means "the last layer", the local one
    name: str = field(default="layered", init=False)

    def __post_init__(self) -> None:
        self.layers = [layer for layer in self.layers if layer is not None]

    @property
    def sink(self) -> Memory | None:
        """Where a new verdict is written."""
        if not self.layers:
            return None
        return self.layers[self.write_index]

    def describe(self) -> str:
        names = [layer.name for layer in self.layers]
        sink = self.sink.name if self.sink else "aucun"
        return f"{' → '.join(names)} (écriture : {sink})"

    def is_available(self) -> bool:
        return any(self._safe(layer.is_available, default=False)
                   for layer in self.layers)

    @staticmethod
    def _safe(call, *args, default=None):
        """One broken layer must not cost the others."""
        try:
            return call(*args)
        except Exception:
            return default

    def remember(self, verdict: Verdict) -> None:
        if self.sink is not None:
            self._safe(self.sink.remember, verdict)

    def recall(self, finding_id: str) -> Verdict | None:
        for layer in self.layers:
            found = self._safe(layer.recall, finding_id)
            if found is not None:
                return found
        return None

    def all_verdicts(self) -> list[Verdict]:
        merged: dict[str, Verdict] = {}
        for layer in reversed(self.layers):  # earlier layers overwrite later
            for verdict in self._safe(layer.all_verdicts, default=[]) or []:
                merged[verdict.finding_id] = verdict
        return [merged[key] for key in sorted(merged)]

    def forget(self, finding_id: str) -> bool:
        """Forget everywhere. A decision half-forgotten is worse than kept."""
        results = [self._safe(layer.forget, finding_id, default=False)
                   for layer in self.layers]
        return any(results)

    def close(self) -> None:
        for layer in self.layers:
            self._safe(getattr(layer, "close", lambda: None))
