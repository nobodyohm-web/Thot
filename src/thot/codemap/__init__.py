"""Phase 1 — build the map: symbols, call graph, sinks and sources."""

# Which languages get a symbol index and a call graph. Everything else in
# scope is read by the pattern rules alone — a real analysis, but not the
# same one, and a report that did not say so let a reader assume 912
# TypeScript files had been indexed when none had.
INDEXED_LANGUAGES = ("python", "typescript", "javascript")

# Which of those also get taint analysis: a proven path from an untrusted
# source to a dangerous sink. Kept separate from the line above on purpose.
# TypeScript now has a map and a graph; it does not have a taint engine, and
# folding the two lists into one would trade a small honest gap for a large
# silent claim.
TAINTED_LANGUAGES = ("python",)
