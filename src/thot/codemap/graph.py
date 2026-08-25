"""Call graph with best-effort name resolution and reachability distances."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from thot.contracts import Symbol

# The only language whose entry points are detected at all.
PYTHON_SUFFIXES = (".py", ".pyi")


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
    # Qualified names an escaped symbol calls, transitively. Whatever route
    # reaches the escaped caller reaches these too, by the graph's own edges.
    inherits_unknown: frozenset[str] = frozenset()

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
        graph.inherits_unknown = graph._inherited_unknown_reach()
        return graph

    def _escaped_by_name(self, name: str) -> bool:
        short = name.rsplit(".", 1)[-1]
        return short in self.escaped_names or short in self.ambiguous_names

    def _inherited_unknown_reach(self) -> frozenset[str]:
        """Spread unknown reach one call at a time, from escaped symbols out.

        Only the escaped symbol itself carried the signal, and a decorated
        Flask view is the one shape where that is never enough: the view is
        marked, the helper it calls is not — being called is exactly why it
        appears in nobody's `references`. So a proven `request.args` ->
        `conn.execute` path scored 0.2 instead of 0.8 as soon as any
        unrelated `main()` existed elsewhere in the tree, which put the
        *proven* finding below the *unproven* pattern one, and below the
        default threshold entirely.

        Seeded on the escape signal alone, never on the language gate below:
        a call resolved from TypeScript into a Python symbol of the same
        short name is a guess, and inheriting reach through it would spread
        one weak resolution across the other language.

        Cost, measured on this repository (3277 symbols): the set answering
        reach_unknown goes from 802 to 1477, but only symbols the graph
        already calls unreachable ever consult it — `accessibility_weight`
        reads `escapes` in the `distance is None` branch and nowhere else —
        and of the twelve taint findings exactly one moves: `sink.eval` in
        `kernel/worker.py`, which the cell loop does reach and which was
        buried at LOW. On prime/, exactly one moves too — `sink.js.spawn` in
        `cli/daemon-update-restart.ts`, low to medium.
        """
        reached: set[str] = set()
        queue = deque(name for name in self.symbols if self._escaped_by_name(name))
        while queue:
            for callee in self.callees(queue.popleft()):
                if callee not in reached:
                    reached.add(callee)
                    queue.append(callee)
        return frozenset(reached)

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
        symbol = self.symbols.get(name)
        if symbol is not None and not symbol.path.lower().endswith(PYTHON_SUFFIXES):
            # Entry points are found by `scope.detect._python_entrypoints` and
            # by nothing else, so `entrypoints` describes the Python half of a
            # tree and no other. No TypeScript, Go or Ruby symbol is reachable
            # from a Python `main()` by construction; answering "unreachable"
            # for one is a verdict from a graph that never covered it, and it
            # buried every `sink.js.exec` in a mixed repository — CRITICAL
            # impact at 1.0 x 0.2 x 0.6 = 0.12, two thresholds down.
            return True
        if name in self.inherits_unknown:
            return True
        return self._escaped_by_name(name)

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
