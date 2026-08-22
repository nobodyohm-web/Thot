"""Source-to-sink propagation for JavaScript and TypeScript.

The Python engine proves three levels: inside a body, across return values,
and across parameters. This one proves the first, and says so. Everything it
reports is a path that exists in one function body, from a named untrusted
source to a named dangerous call, with no sanitizer in between.

Why stop there. The other two levels rest on a resolved call graph — knowing
that `read_input` in this file is the `read_input` that was defined over
there. Python's import system makes that answerable; JavaScript's does not,
not without a module resolver, a `tsconfig` and the type checker's view of
`this`. A second level built on guesses would turn a tool that reports proven
paths into one that reports plausible ones, which is the exact line Thot does
not cross. So: incomplete on purpose, never fabricated.

One assumption is worth stating rather than burying: a call that consumes a
tainted value is treated as returning one. `const launch = build(userInput)`
taints `launch`, because refusing to would silence most real chains — the
value almost always passes through a helper on its way to the sink. Python's
engine answers this properly by following the callee; here it is an
assumption, and it errs towards reporting. A sanitizer breaks it, which is
what the sanitizer list is for.

Works on the masked source — comments and string bodies blanked, offsets
preserved — for the same reason the indexer does: a brace inside a template
literal is not a brace, and a `//` inside a URL is not a comment.
"""

from __future__ import annotations

import re
from pathlib import Path

from thot.codemap.ts_indexer import EXTENSIONS, _line_of, _mask
from thot.contracts import CodeRef, Symbol
from thot.taint.js_catalog import (
    ASSIGNMENT_SINKS,
    SANITIZERS,
    SINKS,
    SOURCES,
    imports,
)

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_DOTTED = re.compile(rf"{_IDENT}(?:\.{_IDENT})*")

# `const x = …`, `let x = …`, `x = …` — but never `==`, `===`, `=>`, `<=`.
_ASSIGN = re.compile(
    rf"^\s*(?:const|let|var)?\s*({_IDENT})\s*(?::[^=;]+)?=(?![=>])\s*(.+)",
    re.DOTALL,
)
_DESTRUCTURE = re.compile(
    rf"^\s*(?:const|let|var)\s*\{{([^}}]*)\}}\s*=(?![=>])\s*(.+)",
    re.DOTALL,
)
_PROPERTY_ASSIGN = re.compile(
    rf"\.({_IDENT})\s*=(?![=>])\s*(.+)", re.DOTALL
)

OPENERS, CLOSERS = "([", ")]"

# What sits just before a brace that opens a *block* rather than a value.
# `if (x) {`, `=> {`, `else {`, `try {`, `do {` — against `= {`, `( {`, `, {`,
# `return {`, which are objects and must stay part of their statement.
BLOCK_AFTER = (")", ">", "else", "try", "do", "finally")


def _opens_block(body: str, index: int) -> bool:
    """Whether the brace at `index` starts a block and not an object literal.

    The distinction is the whole difference between splitting a body into
    statements and shredding `const { host } = req.query` into three pieces.
    """
    head = body[:index].rstrip()
    if not head:
        return True  # a bare block, or the very start of a body
    if head[-1] in ")>":
        return True
    for word in ("else", "try", "do", "finally"):
        if head.endswith(word):
            return True
    return False


def _statements(body: str, offset: int) -> list[tuple[int, str]]:
    """Split a body into logical statements, with each one's absolute offset.

    Depth counts parentheses, brackets, and object braces — but not block
    braces, which are separators. Counting every brace would leave the
    function's own opening brace holding the whole body at depth one, and
    nothing would ever split; counting none would cut destructuring in half.

    A call spread over five lines survives: it is inside parentheses.
    """
    out: list[tuple[int, str]] = []
    depth = 0
    start = 0
    block_depth: list[bool] = []
    for index, char in enumerate(body):
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth = max(0, depth - 1)
        elif char == "{":
            if depth == 0 and _opens_block(body, index):
                block_depth.append(True)
                piece = body[start:index]
                if piece.strip():
                    out.append((offset + start, piece))
                start = index + 1
            else:
                block_depth.append(False)
                depth += 1
        elif char == "}":
            was_block = block_depth.pop() if block_depth else True
            if was_block:
                piece = body[start:index]
                if piece.strip():
                    out.append((offset + start, piece))
                start = index + 1
            else:
                depth = max(0, depth - 1)
        elif char in ";\n" and depth == 0:
            piece = body[start:index]
            if piece.strip():
                out.append((offset + start, piece))
            start = index + 1
    if body[start:].strip():
        out.append((offset + start, body[start:]))
    return out


def _names(text: str) -> list[str]:
    return _DOTTED.findall(text)


def _source_in(text: str) -> str | None:
    """The first untrusted source a fragment reads, as its dotted name."""
    for name in _names(text):
        for rule in SOURCES:
            for pattern in rule.patterns:
                if name == pattern or name.startswith(pattern + "."):
                    return pattern
    return None


def _sanitised(text: str) -> bool:
    """Whether the value is wrapped in something that neutralises it."""
    head = text.strip()
    match = re.match(rf"({_IDENT}(?:\.{_IDENT})*)\s*\(", head)
    if not match:
        return False
    return match.group(1).split(".")[-1] in SANITIZERS


def _arguments(text: str, start: int) -> str:
    """The text between the parentheses opening at or after `start`."""
    opening = text.find("(", start)
    if opening == -1:
        return ""
    depth = 0
    for index in range(opening, len(text)):
        char = text[index]
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index]
    return text[opening + 1 :]


def _split_arguments(text: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for char in text:
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    parts.append(current)
    return parts


def _reads_tainted(text: str, tainted: dict[str, str]) -> str | None:
    """The tainted name this fragment reads, if any and if not neutralised."""
    if _sanitised(text):
        return None
    for name in _names(text):
        root = name.split(".")[0]
        if root in tainted:
            return root
    return None


def _applicable(source: str) -> tuple[list, list]:
    """The rules this file can trigger, given what it imports."""
    calls = [
        rule for rule in SINKS
        if not rule.needs or any(imports(source, m) for m in rule.needs)
    ]
    return calls, list(ASSIGNMENT_SINKS)


def _scan_body(
    *,
    relative: str,
    symbol: Symbol,
    body: str,
    offset: int,
    starts: list[int],
    call_sinks: list,
    assign_sinks: list,
) -> list:
    """Every proven path inside one function body."""
    from thot.taint.engine import TaintCandidate

    tainted: dict[str, str] = {}   # variable -> the source that tainted it
    origin: dict[str, int] = {}    # variable -> line where it became tainted
    found = []
    seen_sites: dict[str, int] = {}

    def ref(line: int, site: str | None = None) -> CodeRef:
        return CodeRef(
            path=relative, line=line, symbol=symbol.name,
            ast_hash=symbol.ast_hash, site=site,
        )

    for position, statement in _statements(body, offset):
        # The line of the *statement*. A sink several lines into a multi-line
        # statement gets its own line below — pointing a reader at
        # `const x = JSON.parse(` when the sink is the `execSync` four lines
        # down is how a true finding gets read as a false one.
        line = _line_of(starts, position)

        # -- sinks first: a statement can both consume and produce taint ----
        for rule in call_sinks:
            for name in rule.names:
                for match in re.finditer(rf"\b{re.escape(name)}\s*\(", statement):
                    call_line = _line_of(starts, position + match.start())
                    arguments = _arguments(statement, match.start())
                    parts = _split_arguments(arguments)
                    watched = (
                        [parts[i] for i in rule.dangerous_args if i < len(parts)]
                        if rule.dangerous_args else parts
                    )
                    fragment = ",".join(watched)
                    culprit = _reads_tainted(fragment, tainted)
                    direct = None if culprit else _source_in(fragment)
                    if not culprit and not direct:
                        continue
                    if not culprit and _sanitised(fragment):
                        continue
                    seen_before = seen_sites.get(name, 0)
                    seen_sites[name] = seen_before + 1
                    sink_ref = ref(call_line, f"{name}#{seen_before}")
                    source_line = (
                        origin.get(culprit, call_line) if culprit else call_line
                    )
                    source_ref = ref(source_line)
                    found.append(
                        TaintCandidate(
                            rule=rule.id,
                            source=source_ref,
                            sink=sink_ref,
                            path=(source_ref, sink_ref),
                            impact=rule.impact,
                            description=rule.description,
                        )
                    )

        for rule in assign_sinks:
            for match in _PROPERTY_ASSIGN.finditer(statement):
                if match.group(1) not in rule.names:
                    continue
                sink_line = _line_of(starts, position + match.start())
                value = match.group(2)
                culprit = _reads_tainted(value, tainted)
                if not culprit and not _source_in(value):
                    continue
                if not culprit and _sanitised(value):
                    continue
                seen_before = seen_sites.get(match.group(1), 0)
                seen_sites[match.group(1)] = seen_before + 1
                sink_ref = ref(sink_line, f"{match.group(1)}#{seen_before}")
                source_ref = ref(
                    origin.get(culprit, sink_line) if culprit else sink_line
                )
                found.append(
                    TaintCandidate(
                        rule=rule.id, source=source_ref, sink=sink_ref,
                        path=(source_ref, sink_ref), impact=rule.impact,
                        description=rule.description,
                    )
                )

        # -- then propagation ------------------------------------------------
        destructured = _DESTRUCTURE.search(statement)
        if destructured:
            value = destructured.group(2)
            mark = _source_in(value) or (
                tainted.get(_reads_tainted(value, tainted) or "")
            )
            for name in _names(destructured.group(1)):
                bare = name.split(".")[-1]
                if mark and not _sanitised(value):
                    tainted[bare] = mark
                    origin[bare] = line
                else:
                    tainted.pop(bare, None)
            continue

        assigned = _ASSIGN.search(statement)
        if assigned:
            name, value = assigned.group(1), assigned.group(2)
            if _sanitised(value):
                tainted.pop(name, None)
                continue
            mark = _source_in(value)
            if mark is None:
                culprit = _reads_tainted(value, tainted)
                mark = tainted.get(culprit) if culprit else None
                if culprit and mark:
                    origin[name] = origin.get(culprit, line)
            else:
                origin[name] = line
            if mark:
                tainted[name] = mark
            else:
                # Reassignment clears: `x = req.query.a; x = "safe"` is safe.
                tainted.pop(name, None)

    return found


def find_candidates(root: Path, symbols: list[Symbol]) -> list:
    """Proven intra-procedural paths in every JavaScript or TypeScript file."""
    root = Path(root)
    by_file: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        if symbol.path.lower().endswith(EXTENSIONS):
            by_file.setdefault(symbol.path, []).append(symbol)

    found: list = []
    for relative, members in by_file.items():
        try:
            source = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        call_sinks, assign_sinks = _applicable(source)
        if not call_sinks and not assign_sinks:
            continue

        masked = _mask(source)
        starts = [0] + [i + 1 for i, c in enumerate(masked) if c == "\n"]
        for symbol in members:
            if symbol.kind == "class":
                continue  # its methods are indexed separately
            begin = starts[min(symbol.lineno - 1, len(starts) - 1)]
            end = (
                starts[symbol.end_lineno] if symbol.end_lineno < len(starts)
                else len(masked)
            )
            found.extend(
                _scan_body(
                    relative=relative, symbol=symbol,
                    body=masked[begin:end], offset=begin, starts=starts,
                    call_sinks=call_sinks, assign_sinks=assign_sinks,
                )
            )
    return found
