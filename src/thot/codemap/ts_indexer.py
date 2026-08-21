"""TypeScript and JavaScript, indexed without a JavaScript runtime.

Prime is 912 TypeScript files. Until now Thot read none of them: `code_map`,
`find_symbol` and `callers` answered nothing about a third of the fused
program, and the agent working on it was blind in exactly the place it was
most often asked to look.

The obvious answer — shell out to `tsc` — was rejected. It makes the map
depend on a node toolchain being installed, resolvable and matching the
project's own TypeScript version; a code map that works on some machines is
worse than one whose limits are stated. This is a scanner: it masks comments
and string literals, then reads declarations by brace matching.

What it gets right: function, method, class and arrow-function declarations,
their spans, their parameters, and the names they call. What it does not do
is type resolution, overload merging, or telling `foo.bar()` on two
different objects apart — the same limits the Python indexer has, for the
same reason: a call graph is a map, not a proof. The taint engine still runs
on Python only, and nothing here pretends otherwise.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from thot.contracts import Symbol
from thot.scope.detect import module_name

EXTENSIONS = (
    ".ts", ".tsx", ".mts", ".cts",
    ".js", ".jsx", ".mjs", ".cjs",
)

# Words that look like a call and are not one. `if (x)` is not an edge, and
# a graph full of `if` edges is a graph nobody can read.
NOT_CALLS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "typeof", "instanceof",
    "await", "yield", "function", "super", "this", "void", "delete", "in",
    "of", "as", "case", "do", "else", "throw", "with", "constructor",
})

# Reserved words that can appear where a declaration name would be.
NOT_NAMES = frozenset({
    "if", "for", "while", "switch", "catch", "return", "function", "class",
    "const", "let", "var", "new", "typeof", "await", "else", "do", "try",
    "finally", "case", "default", "import", "export", "from", "as", "in",
    "of", "get", "set", "static", "public", "private", "protected",
    "readonly", "abstract", "declare", "type", "interface", "enum",
})

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"

# `function foo(`, `export async function foo(`, `export default function foo(`
_FUNCTION = re.compile(
    rf"\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*({_IDENT})\s*(?=[(<])"
)
# `const foo = (…) =>`, `let foo = async function(`, `export const foo = (`
_ASSIGNED = re.compile(
    rf"\b(?:export\s+)?(?:const|let|var)\s+({_IDENT})\s*(?::[^=;]+)?=\s*"
    rf"(?:async\s+)?(?:function\s*\*?\s*{_IDENT}?\s*)?(?=[(<]|{_IDENT}\s*=>)"
)
_CLASS = re.compile(rf"\b(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+({_IDENT})")
# A method inside a class body: `name(`, `async name(`, `get name(`, `#name(`
_METHOD = re.compile(
    rf"(?:^|[\n;{{}}])\s*(?:(?:public|private|protected|static|readonly|abstract|override|async|get|set)\s+)*"
    rf"(#?{_IDENT})\s*(?:<[^>(]*>)?\s*\("
)
_CALL = re.compile(rf"\b({_IDENT}(?:\.{_IDENT})*)\s*\(")


def _mask(source: str) -> str:
    """Blank out comments and string bodies, keeping every offset and newline.

    Everything downstream works on offsets: braces inside a template literal
    would otherwise close a function three lines early, and a `//` inside a
    URL string would swallow the rest of the line.
    """
    out = list(source)
    index, length = 0, len(source)
    while index < length:
        char = source[index]
        nxt = source[index + 1] if index + 1 < length else ""

        if char == "/" and nxt == "/":
            while index < length and source[index] != "\n":
                out[index] = " "
                index += 1
            continue

        if char == "/" and nxt == "*":
            out[index] = out[index + 1] = " "
            index += 2
            while index < length and not (
                source[index] == "*" and index + 1 < length
                and source[index + 1] == "/"
            ):
                if source[index] != "\n":
                    out[index] = " "
                index += 1
            for _ in range(2):
                if index < length:
                    out[index] = " "
                    index += 1
            continue

        if char in "\"'`":
            quote = char
            index += 1
            depth = 0
            while index < length:
                current = source[index]
                if current == "\\":
                    out[index] = " "
                    if index + 1 < length and source[index + 1] != "\n":
                        out[index + 1] = " "
                    index += 2
                    continue
                if quote == "`" and current == "$" and index + 1 < length \
                        and source[index + 1] == "{":
                    # An interpolation is code: leave it visible.
                    depth += 1
                    index += 2
                    continue
                if depth and current == "}":
                    depth -= 1
                    index += 1
                    continue
                if depth:
                    index += 1
                    continue
                if current == quote:
                    index += 1
                    break
                if current != "\n":
                    out[index] = " "
                index += 1
            continue

        index += 1

    return "".join(out)


def _line_of(offsets: list[int], position: int) -> int:
    """1-based line for an offset, by binary search over line starts."""
    import bisect

    return bisect.bisect_right(offsets, position)


def _body_span(masked: str, start: int) -> tuple[int, int] | None:
    """From a declaration, the offsets of its body's braces. None if unclosed."""
    opening = masked.find("{", start)
    if opening == -1:
        return None
    # An arrow function may have no block body: `const f = (x) => x + 1`.
    arrow = masked.find("=>", start)
    semicolon = masked.find(";", start)
    if arrow != -1 and arrow < opening and 0 <= semicolon < opening:
        return None

    depth = 0
    for position in range(opening, len(masked)):
        char = masked[position]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return opening, position
    return None


def _skip_balanced(masked: str, start: int, opener: str, closer: str) -> int:
    """Offset just past the balanced pair starting at `start`, or `start`."""
    if start >= len(masked) or masked[start] != opener:
        return start
    depth = 0
    for position in range(start, len(masked)):
        char = masked[position]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return position + 1
    return start


def _is_function_form(masked: str, match: re.Match) -> bool:
    """Whether `const x = …` really assigns a function.

    `const total = (a + b);` matches the same shape as `const f = (a, b) =>`
    and is not a declaration of anything callable. Without this check the map
    fills with symbols that have no body, no calls and no reason to exist —
    and a map you cannot trust is worse than a gap you can name.
    """
    if "function" in match.group(0):
        return True

    position = match.end()
    if re.match(rf"\s*{_IDENT}\s*=>", masked[position:]):
        return True  # `const f = x => …`

    while position < len(masked) and masked[position].isspace():
        position += 1
    if position < len(masked) and masked[position] == "<":
        position = _skip_balanced(masked, position, "<", ">")
        while position < len(masked) and masked[position].isspace():
            position += 1
    after = _skip_balanced(masked, position, "(", ")")
    if after == position:
        return False
    # A return type annotation may sit between the parameters and the arrow.
    tail = masked[after : after + 200]
    return bool(re.match(r"\s*(?::[^=;{]*)?=>", tail))


def _calls(fragment: str) -> tuple[str, ...]:
    found: dict[str, None] = {}
    for match in _CALL.finditer(fragment):
        name = match.group(1)
        if name.split(".")[0] in NOT_CALLS or name in NOT_CALLS:
            continue
        found.setdefault(name, None)
    return tuple(found)


def _params(masked: str, header_end: int) -> tuple[str, ...]:
    """The parameter names of the declaration whose header ends here."""
    opening = masked.find("(", header_end - 1)
    if opening == -1:
        return ()
    depth, closing = 0, -1
    for position in range(opening, len(masked)):
        char = masked[position]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                closing = position
                break
    if closing == -1:
        return ()

    names: list[str] = []
    depth = 0
    current = ""
    for char in masked[opening + 1 : closing] + ",":
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
        if char == "," and depth == 0:
            match = re.match(rf"\s*(?:\.\.\.)?({_IDENT})", current)
            if match:
                names.append(match.group(1))
            current = ""
            continue
        current += char
    return tuple(names)


def _hash(fragment: str) -> str:
    """Identity of the body, blind to formatting — comments are already gone."""
    return hashlib.sha256(
        " ".join(fragment.split()).encode()
    ).hexdigest()[:16]


class TypeScriptIndexer:
    """Indexes one TypeScript or JavaScript file into flat symbols."""

    language = "typescript"

    def index_file(self, root: Path, relative: str) -> list[Symbol]:
        try:
            source = (Path(root) / relative).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return []
        return self.index_source(source, relative)

    def index_source(self, source: str, relative: str) -> list[Symbol]:
        masked = _mask(source)
        starts = [0] + [i + 1 for i, c in enumerate(masked) if c == "\n"]
        module = module_name(relative)
        symbols: list[Symbol] = []
        taken: set[str] = set()

        def emit(name: str, kind: str, header_end: int,
                 span: tuple[int, int] | None) -> None:
            full = f"{module}.{name}" if module else name
            if full in taken:  # an overload signature, or a re-export
                return
            taken.add(full)
            body = masked[span[0] : span[1] + 1] if span else ""
            symbols.append(
                Symbol(
                    name=full,
                    path=relative,
                    lineno=_line_of(starts, header_end),
                    end_lineno=_line_of(starts, span[1]) if span
                    else _line_of(starts, header_end),
                    ast_hash=_hash(body),
                    kind=kind,
                    calls=_calls(body),
                    params=_params(masked, header_end),
                )
            )

        for pattern, checked in ((_FUNCTION, False), (_ASSIGNED, True)):
            for match in pattern.finditer(masked):
                if match.group(1) in NOT_NAMES:
                    continue
                if checked and not _is_function_form(masked, match):
                    continue
                emit(match.group(1), "function", match.end(),
                     _body_span(masked, match.end()))

        for match in _CLASS.finditer(masked):
            name = match.group(1)
            span = _body_span(masked, match.end())
            emit(name, "class", match.end(), span)
            if span is None:
                continue
            body = masked[span[0] + 1 : span[1]]
            for method in _METHOD.finditer(body):
                method_name = method.group(1)
                if method_name in NOT_NAMES:
                    continue
                header_end = span[0] + 1 + method.end()
                emit(f"{name}.{method_name}", "method", header_end,
                     _body_span(masked, header_end))

        return symbols
