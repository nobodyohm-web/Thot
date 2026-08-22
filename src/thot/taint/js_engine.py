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

import os
import re
from pathlib import Path, PurePosixPath

from thot.codemap.ts_indexer import EXTENSIONS, _line_of, read_masked
from thot.contracts import CodeRef, Symbol
from thot.taint.js_catalog import active, bindings, imports, using

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
        for rule in active().sources:
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
    return match.group(1).split(".")[-1] in active().sanitizers


# Past this, it is not an argument list. Profiled on Prime: `_split_arguments`
# took 130 of the pass's 144 seconds over 61 122 calls, and the distribution
# says why — median 16 characters, p90 77, maximum 1 859 942. `_arguments`
# used to return the rest of the file when the closing parenthesis was missing
# or impossibly far, which happens in generated and minified code, and a
# handful of those cost more than every other call together.
#
# The bound is generous by three orders of magnitude over p90. What it drops
# is not analysed rather than analysed wrongly: splitting two megabytes on
# commas yields thousands of "arguments" and an arbitrary answer, which is the
# line this engine does not cross.
ARGUMENT_LIMIT = 20_000


def _arguments(text: str, start: int) -> str:
    """The text between the parentheses opening at or after `start`.

    Empty when the call does not close within `ARGUMENT_LIMIT`: that is not a
    call whose arguments can be read.
    """
    opening = text.find("(", start)
    if opening == -1:
        return ""
    depth = 0
    stop = min(len(text), opening + ARGUMENT_LIMIT + 2)
    for index in range(opening, stop):
        char = text[index]
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index]
    return ""


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


def _has_any_source(masked: str) -> bool:
    """Whether any untrusted source appears anywhere in the file."""
    for rule in active().sources:
        for pattern in rule.patterns:
            if pattern in masked:
                return True
    return False


def _applicable(source: str) -> tuple[list, list]:
    """The rules this file can trigger, given what it imports."""
    catalog = active()
    calls = [
        rule for rule in catalog.sinks
        if not rule.needs or any(imports(source, m) for m in rule.needs)
    ]
    return calls, list(catalog.assignment_sinks)


def _scan_body(
    *,
    relative: str,
    symbols: list[Symbol],
    body: str,
    offset: int,
    starts: list[int],
    call_sinks: list,
    assign_sinks: list,
    seeded: dict[str, str] | None = None,
    entered: CodeRef | None = None,
    locals_by_name: dict[str, Symbol] | None = None,
    handed: list | None = None,
) -> list:
    """Every proven path in one file, attributed to the function it sits in.

    `seeded` pre-taints names — a parameter that a caller handed a tainted
    value. `handed` collects the reverse: local functions this pass called
    with tainted arguments, so a second pass can follow the value in.
    """
    from thot.taint.engine import TaintCandidate

    tainted: dict[str, str] = dict(seeded or {})
    origin: dict[str, int] = {}    # variable -> line where it became tainted
    found = []
    seen_sites: dict[str, int] = {}
    module = relative.rsplit(".", 1)[0].replace("/", ".")

    def ref(line: int, site: str | None = None) -> CodeRef:
        # The innermost function containing this line. Top-level code has
        # none, and is named after its module rather than left anonymous.
        for candidate in symbols:
            if candidate.lineno <= line <= candidate.end_lineno:
                return CodeRef(
                    path=relative, line=line, symbol=candidate.name,
                    ast_hash=candidate.ast_hash, site=site,
                )
        return CodeRef(path=relative, line=line, symbol=module, site=site)

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
                    # A crossing reported only inside the callee is unreadable:
                    # the file that touches the request never appears, and the
                    # reader sees a helper handling a value from nowhere.
                    steps = ((entered,) if entered else ()) + (source_ref, sink_ref)
                    found.append(
                        TaintCandidate(
                            rule=rule.id,
                            source=entered or source_ref,
                            sink=sink_ref,
                            path=steps,
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

        # -- a tainted value handed to a function defined in this file -------
        if locals_by_name is not None and handed is not None:
            for match in re.finditer(rf"\b({_IDENT})\s*\(", statement):
                entry = locals_by_name.get(match.group(1))
                if entry is None:
                    continue
                where, callee = entry
                if not callee.params:
                    continue
                arguments = _split_arguments(
                    _arguments(statement, match.start())
                )
                for index, fragment in enumerate(arguments):
                    if index >= len(callee.params):
                        break
                    culprit = _reads_tainted(fragment, tainted)
                    mark = (
                        tainted.get(culprit) if culprit
                        else _source_in(fragment)
                    )
                    # An unnamed slot holds a position and binds nothing:
                    # a destructured parameter cannot be seeded by name.
                    if mark and callee.params[index] and not _sanitised(fragment):
                        handed.append((where, callee, callee.params[index],
                                       mark, ref(_line_of(starts, position
                                                          + match.start()))))

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


def _enclosing(symbols: list[Symbol]) -> list[Symbol]:
    """Innermost first, so a line inside a method resolves to the method."""
    return sorted(symbols, key=lambda s: (s.end_lineno - s.lineno, s.lineno))


def find_candidates(root: Path, symbols: list[Symbol]) -> list:
    """Proven intra-procedural paths in every JavaScript or TypeScript file.

    Scans whole files rather than the bodies of named symbols. The ordinary
    shape of a web handler is an anonymous arrow passed to a route —
    `app.get("/x", (req, res) => { … })` — which no indexer names and which
    an engine walking named bodies never sees. Measured on the two trees:
    24 454 such functions, every one of them invisible.

    The taint map is flat within a file rather than per-scope. That is not a
    shortcut: a closure genuinely does see the variables around it, so
    nesting has to inherit. Two sibling functions reusing a variable name is
    the case it over-approximates, and reassignment clears taint, so the
    common shape of that collision heals itself.
    """
    from thot.codemap.rules import load_js_catalog

    root = Path(root)
    with using(load_js_catalog(root)):
        return _find_candidates(root, symbols)


# `import { ping } from "./helpers"` and `const { ping } = require("./x")`.
# Named bindings only: a default import does not say which function it is
# without reading the target's export table, and a namespace import
# (`import * as h`) needs member resolution. Both are refused rather than
# guessed, which is the same rule the rest of this engine follows.
_NAMED_IMPORT = re.compile(
    r"""import\s*\{(?P<clause>[^}]*)\}\s*from\s*['"](?P<spec>\.[^'"]*)['"]"""
    r"""|(?:const|let|var)\s*\{(?P<clause2>[^}]*)\}\s*=\s*require\s*\(\s*"""
    r"""['"](?P<spec2>\.[^'"]*)['"]\s*\)"""
)


def _resolve(source_file: str, specifier: str, known: dict) -> str | None:
    """A relative specifier to a file this index already holds.

    A rule about files, not an inference: `./helpers` from `src/app.ts` names
    one path, and either it is in the index or the crossing does not happen.
    Bare specifiers and tsconfig aliases stay refused — those genuinely need
    a resolver.
    """
    base = PurePosixPath(source_file).parent / specifier
    flat = PurePosixPath(os.path.normpath(str(base)))
    for candidate in (
        *(f"{flat}{extension}" for extension in EXTENSIONS),
        str(flat),
        *(f"{flat}/index{extension}" for extension in EXTENSIONS),
    ):
        if candidate in known:
            return candidate
    return None


def _exported_functions(target: str, by_file: dict, cache: dict) -> dict:
    """The callable functions of one file, by bare name — built once.

    A popular module is imported by dozens of files. Measured: this is *not*
    where the crossing spends its time — caching it left the pass at +21% on a
    1 686-file tree, unchanged. Kept because it is correct and free, not
    because it bought anything.
    """
    known = cache.get(target)
    if known is None:
        known = {
            symbol.name.rsplit(".", 1)[-1]: symbol
            for symbol in by_file[target]
            if symbol.kind in ("function", "method") and symbol.params
        }
        cache[target] = known
    return known


def _imported_callables(source: str, relative: str, by_file: dict,
                        cache: dict | None = None) -> dict:
    """Local name -> (file, symbol) for functions pulled in relatively."""
    cache = {} if cache is None else cache
    found: dict = {}
    for match in _NAMED_IMPORT.finditer(source):
        clause = match.group("clause") or match.group("clause2") or ""
        specifier = match.group("spec") or match.group("spec2") or ""
        target = _resolve(relative, specifier, by_file)
        if target is None:
            continue
        defined = _exported_functions(target, by_file, cache)
        for exported, local in bindings(clause):
            symbol = defined.get(exported)
            if symbol is not None:
                found[local] = (target, symbol)
    return found


def _find_candidates(root: Path, symbols: list[Symbol]) -> list:
    by_file: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        if symbol.path.lower().endswith(EXTENSIONS):
            by_file.setdefault(symbol.path, []).append(symbol)

    found: list = []
    exported_cache: dict = {}
    for relative in sorted(by_file):
        # Read and masked once per version of the file: the indexer has
        # already paid for this, and paying twice showed up as nine seconds
        # before the prompt on a TypeScript repository.
        source, masked = read_masked(root / relative)
        if not source:
            continue
        # A file with no untrusted source in it cannot contain a path, so
        # there is nothing to walk. A plain substring test over the whole
        # file costs microseconds and skips the great majority of them —
        # measured on Prime: 938 files down to the few dozen that can
        # possibly matter.
        if not _has_any_source(masked):
            continue
        call_sinks, assign_sinks = _applicable(source)
        if not call_sinks and not assign_sinks:
            continue
        starts = [0] + [i + 1 for i, c in enumerate(masked) if c == "\n"]
        ordered = _enclosing(by_file[relative])
        # Functions this file defines, by the bare name a caller would use.
        # Same file only: following a call across files needs a resolved
        # module graph, and JavaScript does not offer one without a tsconfig
        # and a type checker. Within a file the question has an answer.
        locals_by_name = {
            symbol.name.rsplit(".", 1)[-1]: (relative, symbol)
            for symbol in ordered
            if symbol.kind in ("function", "method") and symbol.params
        }
        # A relative import resolves to one file by a rule about files. Local
        # definitions win: a name defined here is that one, whatever a module
        # of the same name exports.
        for name, target in _imported_callables(
                source, relative, by_file, exported_cache).items():
            locals_by_name.setdefault(name, target)

        handed: list = []
        found.extend(
            _scan_body(
                relative=relative,
                symbols=ordered,
                body=masked,
                offset=0,
                starts=starts,
                call_sinks=call_sinks,
                assign_sinks=assign_sinks,
                locals_by_name=locals_by_name,
                handed=handed,
            )
        )

        # One more level, and one only. A helper that takes an untrusted
        # value and reaches a sink is the ordinary shape of a handler that
        # delegates; chasing further would need the call graph this engine
        # deliberately does not claim to have.
        seen: set[tuple[str, str, str]] = set()
        for where, callee, parameter, mark, entered in handed:
            key = (where, callee.name, parameter)
            if key in seen:
                continue
            seen.add(key)

            if where == relative:
                body_source, body_masked, body_starts = source, masked, starts
                body_symbols = ordered
                body_call, body_assign = call_sinks, assign_sinks
            else:
                # The callee lives in the resolved module: its own text, its
                # own line table, and its own module gate — `exec` is only a
                # sink in a file that imports `child_process`, and that file
                # is this one, not the caller.
                body_source, body_masked = read_masked(root / where)
                if not body_source:
                    continue
                body_starts = [0] + [
                    i + 1 for i, c in enumerate(body_masked) if c == "\n"
                ]
                body_symbols = _enclosing(by_file[where])
                body_call, body_assign = _applicable(body_source)
                if not body_call and not body_assign:
                    continue

            begin = body_starts[min(callee.lineno - 1, len(body_starts) - 1)]
            end = (
                body_starts[callee.end_lineno]
                if callee.end_lineno < len(body_starts) else len(body_masked)
            )
            found.extend(
                _scan_body(
                    relative=where,
                    symbols=body_symbols,
                    body=body_masked[begin:end],
                    offset=begin,
                    starts=body_starts,
                    call_sinks=body_call,
                    assign_sinks=body_assign,
                    seeded={parameter: mark},
                    entered=entered if where != relative else None,
                )
            )
    return found
