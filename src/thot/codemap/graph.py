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
    # Short names reached by a route this graph cannot follow. Two sources,
    # and they are the same mistake wearing different clothes: a name handed
    # around as a value (a dispatch table, a decorator, a callback), and a
    # name called on a variable whose type is unknown, where several symbols
    # answer to it. Neither is evidence of unreachability.
    escaped_names: frozenset[str] = frozenset()
    ambiguous_names: frozenset[str] = frozenset()

    @classmethod
    def build(
        cls, symbols: list[Symbol], entrypoints: tuple[str, ...] = ()
    ) -> CodeGraph:
        by_name = {s.name: s for s in symbols}

        by_short: dict[str, list[str]] = {}
        for name in by_name:
            by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

        mentioned: set[str] = set()
        for symbol in symbols:
            mentioned.update(symbol.references)

        graph = cls(symbols=by_name, entrypoints=tuple(entrypoints))
        ambiguous: set[str] = set()

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
                elif len(matches) > 1:
                    # `sandbox.run(...)` with several `run` in the tree. The
                    # call happens; which one is what is unknown. Recording
                    # no edge is right; concluding "unreachable" is not.
                    ambiguous.add(short)
            graph.edges[symbol.name] = resolved
            for target in resolved:
                graph.reverse_edges.setdefault(target, set()).add(symbol.name)

        graph.escaped_names = frozenset(mentioned)
        graph.ambiguous_names = frozenset(ambiguous)
        return graph

    def reach_unknown(self, name: str) -> bool:
        """Whether a route to this symbol exists that the graph cannot follow.

        The distinction the severity score needs. A symbol nobody calls and
        nobody mentions is dead, and discounting it is the whole point of
        reachability. A symbol that is stored in a table, decorated, or
        called through a variable of unknown type is reached by a route this
        analysis does not resolve — and burying it hides the ordinary case
        in every framework there is.
        """
        if not name:
            return False
        short = name.rsplit(".", 1)[-1]
        return short in self.escaped_names or short in self.ambiguous_names

    # The old spelling, kept because it reads well at the call site.
    escapes = reach_unknown

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
