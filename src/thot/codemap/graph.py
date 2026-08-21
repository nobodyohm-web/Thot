"""Call graph with best-effort name resolution and reachability distances."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from thot.contracts import Symbol


@dataclass
class CodeGraph:
    """Symbols plus resolved call edges.

    Resolution is deliberately best-effort: a bare call name is matched
    first inside the caller's own module, then globally by short name.
    Dynamic dispatch is not resolved — see the spec's documented limits.
    """

    symbols: dict[str, Symbol] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)
    entrypoints: tuple[str, ...] = ()

    @classmethod
    def build(
        cls, symbols: list[Symbol], entrypoints: tuple[str, ...] = ()
    ) -> CodeGraph:
        by_name = {s.name: s for s in symbols}

        by_short: dict[str, list[str]] = {}
        for name in by_name:
            by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

        graph = cls(symbols=by_name, entrypoints=tuple(entrypoints))

        for symbol in symbols:
            resolved: set[str] = set()
            module = symbol.name.rsplit(".", 1)[0]
            for call in symbol.calls:
                short = call.rsplit(".", 1)[-1]
                candidate = f"{module}.{short}"
                if candidate in by_name and candidate != symbol.name:
                    resolved.add(candidate)
                    continue
                matches = by_short.get(short, [])
                if len(matches) == 1 and matches[0] != symbol.name:
                    resolved.add(matches[0])
            graph.edges[symbol.name] = resolved
            for target in resolved:
                graph.reverse_edges.setdefault(target, set()).add(symbol.name)

        return graph

    def callees(self, name: str) -> set[str]:
        return self.edges.get(name, set())

    def callers(self, name: str) -> set[str]:
        return self.reverse_edges.get(name, set())

    def distance_from_entrypoints(self, name: str) -> int | None:
        """Shortest hop count from any entry point, or None if unreachable."""
        if name in self.entrypoints:
            return 0
        seen = set(self.entrypoints)
        queue = deque((entry, 0) for entry in self.entrypoints)
        while queue:
            current, depth = queue.popleft()
            for callee in self.callees(current):
                if callee in seen:
                    continue
                if callee == name:
                    return depth + 1
                seen.add(callee)
                queue.append((callee, depth + 1))
        return None
