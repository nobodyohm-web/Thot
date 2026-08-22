"""Phase 1 — build the map: symbols, call graph, sinks and sources.

Three tiers, kept apart on purpose. Folding them into one flag would trade a
small honest gap for a large silent claim — and the reverse happened here
once already: the JavaScript taint engine was written and this list was not
updated, so for an afternoon the report told every reader that TypeScript had
no taint engine while it had one.
"""

# A symbol index and a call graph. Everything else in scope is read by the
# pattern rules alone — a real analysis, but not the same one, and a report
# that did not say so let a reader assume 912 TypeScript files had been
# indexed when none had.
INDEXED_LANGUAGES = ("python", "typescript", "javascript")

# A proven path from an untrusted source to a dangerous sink.
TAINTED_LANGUAGES = ("python", "typescript", "javascript")

# Taint that crosses file boundaries, following return values and parameters
# through a resolved call graph. JavaScript's imports do not answer that
# question without a tsconfig and a type checker, so its taint stops at the
# file: within one, it follows a call into a helper; beyond one, it does not
# pretend to.
DEEP_TAINT_LANGUAGES = ("python",)
