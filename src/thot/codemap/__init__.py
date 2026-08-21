"""Phase 1 — build the map: symbols, call graph, sinks and sources."""

# Which languages get an AST index, a call graph and taint analysis. Every
# other file in scope is read by the pattern rules alone — which is a real
# analysis, but not the same one, and a report that did not say so let a
# reader assume 912 TypeScript files had been indexed when none had.
INDEXED_LANGUAGES = ("python",)
