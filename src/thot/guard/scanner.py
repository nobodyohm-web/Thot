"""Apply the ported security patterns across a repository.

Two rules keep this from becoming the noise generator that pattern scanners
usually are:

- One finding per rule per file. A file that pickles in nine places has one
  problem, not nine.
- No proof is claimed. These findings are `PLAUSIBLE` by construction, scored
  without an accessibility bonus, and say so — the taint engine is what proves
  a path.
"""

from __future__ import annotations

import ast
import hashlib
import io
import math
import re
import tokenize
from collections import Counter
from pathlib import Path

# The catalogue's regexes are read as data, not only executed — see
# `_literal_gate`. `re._parser` is private and this is the only use of it, so
# a version of Python that moves it costs the pre-filter and nothing else.
try:
    from re import _constants as _sre
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - depends on the interpreter build
    _sre = None
    _sre_parse = None

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.codemap.ts_indexer import _skip_balanced
from thot.taint.js_catalog import binds
from thot.guard.patterns import _JS_EXTS as _JS_SUFFIXES
from thot.guard.audit_rules import THOT_PATTERNS
from thot.guard.patterns import AUDIT_PATTERNS, SECURITY_PATTERNS
from thot.scoring.role import Role, role_of
from thot.scoring.severity import compute_severity

# Impact per rule. The upstream data carries a reminder but no severity, and
# treating a disabled TLS check like an eval() of user input would make the
# whole sweep unreadable.
# The module a rule's call has to be bound from, when its bare name is
# ordinary. `exec(` matches a local helper, a method definition and an
# interface signature as readily as `child_process.exec`.
#
# Asked as a binding, not as an import. "Does this file mention the module"
# was the first answer and it was too coarse: `wsl-clipboard-image.ts`
# imports `child_process`, binds only `execFileSync` from it, and calls a
# destructured parameter named `exec` that opens no shell.
#
# The price is a call reached through a local wrapper — `import { exec }
# from "./shell"` — which is not bound from the module and so goes unseen.
# The taint engine pays the same price for the same reason.
_BOUND_FROM: dict[str, str] = {
    "child_process_exec": "child_process",
}


_IMPACT: dict[str, Severity] = {
    "eval_injection": Severity.CRITICAL,
    "new_function_injection": Severity.CRITICAL,
    "os_system_injection": Severity.CRITICAL,
    "python_subprocess_shell": Severity.CRITICAL,
    "child_process_exec": Severity.CRITICAL,
    "go_exec_shell_injection": Severity.CRITICAL,
    "pickle_deserialization": Severity.CRITICAL,
    "pickle_variants_load": Severity.CRITICAL,
    "pickle_wrapper_load": Severity.CRITICAL,
    "marshal_loads": Severity.CRITICAL,
    "shelve_open": Severity.HIGH,
    "unsafe_yaml_load": Severity.CRITICAL,
    "yaml_unsafe_load_variants": Severity.CRITICAL,
    "torch_unsafe_load": Severity.HIGH,
    "xml_unsafe_parse": Severity.HIGH,
    "react_dangerously_set_html": Severity.HIGH,
    "document_write_xss": Severity.HIGH,
    "innerHTML_xss": Severity.HIGH,
    "outerHTML_xss": Severity.HIGH,
    "insertAdjacentHTML_xss": Severity.HIGH,
    "tls_verification_disabled": Severity.HIGH,
    "node_createcipher_no_iv": Severity.HIGH,
    "aes_ecb_mode": Severity.MEDIUM,
    "script_src_without_sri": Severity.MEDIUM,
    "github_actions_workflow": Severity.MEDIUM,
    "hardcoded_credential": Severity.HIGH,
    # A guess about a name, not a recognised key shape: reported, ranked
    # below the rules that recognise one.
    "hardcoded_secret_assignment": Severity.MEDIUM,
}

_DEFAULT_IMPACT = Severity.MEDIUM

# Reminders are written for a model mid-edit and run several paragraphs. A
# report needs the first one.
_SCENARIO_CHARS = 400


_PY_SUFFIXES = (".py", ".pyi")


def code_only(relative: str, text: str) -> str:
    """Blank out string literals and comments, preserving offsets.

    A rule catalog, a test fixture and a piece of documentation all *mention*
    dangerous calls without making them. Scanning raw text flags all three:
    on Thot's own source that was 25 findings and every one was false. Blanking
    with spaces rather than deleting keeps every line number intact, so a real
    finding still points at the right line.

    JavaScript and TypeScript get their comments blanked and their string
    bodies kept, by the routine the taint engine already uses. Comments,
    because a JSDoc line reading "prefer this over `exec()`" was a HIGH
    finding on Hermes, ranked above findings with a traced path behind them.
    Bodies kept, because blanking them too was an over-reach that this
    project's own record caught: `state-snapshot.ts:163` holds a Python
    program in a template literal, Prime runs it, its `dill.load` is real,
    and the panel had confirmed it before the blanking silenced it.

    Every other language is scanned as-is, and so is a file that will not
    tokenise — a syntax error must never silently disable the sweep.
    """
    if relative.endswith(_JS_SUFFIXES):
        from thot.codemap.ts_indexer import _mask

        try:
            return _mask(text, strings=False)
        except RecursionError:
            # Nested template literals exhaust the masker's mutual recursion.
            # Until now the only caller was the indexer, which catches per
            # file; this one is reached straight from the sweep, so it carries
            # its own net. Scanned as-is, exactly like a Python file that will
            # not tokenise: one file's shape must never take the sweep down.
            return text

    if not relative.endswith(_PY_SUFFIXES):
        return text

    out = list(text)
    lines = text.splitlines(keepends=True)
    starts = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line)

    def absolute(row: int, column: int) -> int:
        if row - 1 >= len(starts):
            return len(out)
        return starts[row - 1] + column

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError):
        return text

    for token in tokens:
        if token.type not in (tokenize.STRING, tokenize.COMMENT):
            continue
        begin = absolute(*token.start)
        end = absolute(*token.end)
        for index in range(begin, min(end, len(out))):
            if out[index] != "\n":
                out[index] = " "
    return "".join(out)


# Rules that describe an injection: untrusted input reaching a command. A
# call handed a literal has no input to inject, and the sweep reported
# `execSync("xclip -selection clipboard")` and `os.system("clear")` at the
# same rank as a command read from configuration. Only these three — a
# constant argument says nothing about an unsafe deserialiser.
_INJECTION_RULES = frozenset({
    "child_process_exec",
    "os_system_injection",
    "python_subprocess_shell",
})

_IDENTIFIER = re.compile(r"[A-Za-z_]")


# Rules that recognise a credential. Judged, because the shape of a key and
# the shape of the documentation's example of that key are the same shape:
# `AKIAIOSFODNN7EXAMPLE` is in AWS's own docs and therefore in more
# repositories than any real key ever will be.
_CREDENTIAL_RULES = frozenset({
    "hardcoded_credential",
    "hardcoded_secret_assignment",
})

_PLACEHOLDER_MARKERS = (
    "example", "placeholder", "your", "changeme", "change_me", "change-me",
    "redacted", "dummy", "fake", "sample", "notreal", "not-real", "insert",
    "replace", "todo", "test", "xxxx", "0000", "1234567890", "abcdef",
    "<", ">", "{", "}", "$",
)

# The alphabet a key is drawn from. Anything else in the value — a dot, a
# colon, a space, a Japanese character — says the string names or describes
# something. Measured on hermes/, that one condition is what separates a
# credential from `'hermes.desktop.layoutTree.v2'`, `'conn:local::research'`
# and `'credits.grant_spent'`.
_KEY_ALPHABET = re.compile(r"[A-Za-z0-9+/=_\-]{16,}\Z")

# Shannon bits per character. A 24-character value drawn from an alphabet of
# 62 carries about 4.6; `changeme-changeme-change` carries 2.9 and
# `aaaaaaaaaaaaaaaaaaaaaaaa` carries 0. The threshold separates a key from a
# sentence, which is what the name-based rule needs and all it needs.
_MIN_SECRET_ENTROPY = 3.0


def _looks_like_a_key(value: str) -> bool:
    """Whether this value could be a credential rather than a name for one.

    The digit is what rules out `"token": "TELEGRAM_BOT_TOKEN"` — a table
    mapping a setting to the variable it is read from, which is the shape
    this rule exists to recommend, and which it reported on Thot's own
    source. A generated key of any provider carries digits; a name for one
    carries words.
    """
    if not _KEY_ALPHABET.match(value):
        return False
    if not any(char.isdigit() for char in value):
        return False
    if not any(char.isalpha() for char in value):
        return False
    # Below 32 characters, one case throughout reads as a slug rather than as
    # something generated: `bearer-token-123` against `Zq7Z4hV9nX2pL8sK`.
    mixed = (any(char.islower() for char in value)
             and any(char.isupper() for char in value))
    return mixed or len(value) >= 32


def _assigned_value(matched: str) -> str:
    """The literal to the right of the assignment, or the whole match.

    Read from the end, because the name is quoted too in every mapping
    syntax there is — `"token": "TELEGRAM_BOT_TOKEN"` has four quotes and
    only the last pair holds the value.
    """
    trimmed = matched.rstrip()
    if trimmed[-1:] in ('"', "'"):
        opening = trimmed.rfind(trimmed[-1], 0, len(trimmed) - 1)
        if opening != -1:
            return trimmed[opening + 1:-1]
    return matched


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(value).values()
    )


def _is_placeholder(rule: str, matched: str) -> bool:
    """Whether this match is a stand-in for a credential rather than one.

    False negatives are the deliberate side of this: a real key that happens
    to spell `dummy` inside its base64 goes unreported. A scanner nobody
    reads reports nothing at all, and the documentation example is the single
    most common string this catalogue will ever meet.
    """
    lowered = matched.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if rule == "hardcoded_secret_assignment":
        value = _assigned_value(matched)
        return (not _looks_like_a_key(value)
                or _entropy(value) < _MIN_SECRET_ENTROPY)
    return False


def _spans(text: str, pattern: dict) -> list[tuple[int, int]]:
    """Every place a rule's own matcher fires, as (start, end), in order."""
    found: list[tuple[int, int]] = []
    regex = pattern.get("regex")
    if regex:
        found += [(m.start(), m.end()) for m in re.finditer(regex, text)]
    for needle in pattern.get("substrings") or ():
        start = text.find(needle)
        while start != -1:
            found.append((start, start + len(needle)))
            start = text.find(needle, start + 1)
    return sorted(found)


def _first_argument(masked: str, opening: int) -> tuple[int, int] | None:
    """The span of the first argument of the call whose `(` is at `opening`."""
    depth = 0
    start = opening + 1
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return start, index
            depth -= 1
        elif char == "," and depth == 0:
            return start, index
    return None  # unclosed: not something to draw a conclusion from


def _only_literals(node: ast.AST) -> bool:
    """Whether this expression's value can only ever be a literal.

    A conditional's test is deliberately ignored: it chooses between the
    branches, it cannot become one. `"cls" if os.name == "nt" else "clear"`
    reads a name and is a constant command all the same, which is the case
    the masked text cannot answer.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.IfExp):
        return _only_literals(node.body) and _only_literals(node.orelse)
    if isinstance(node, ast.BinOp):
        # Any operator: two literals joined by one produce a literal, and
        # narrowing this to `+` was a restriction nothing justified —
        # `"echo %s" % "hi"` is the string `echo hi` and nothing else.
        return _only_literals(node.left) and _only_literals(node.right)
    return False


def _literal_python_argument(fragment: str) -> bool:
    """The same question, answered exactly, for a file Python can parse."""
    try:
        tree = ast.parse(fragment.strip(), mode="eval")
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False  # unparseable on its own: draw no conclusion from it
    return _only_literals(tree.body)


def _constant_command(
    relative: str, structural: str, source: str, span: tuple[int, int]
) -> bool:
    """Whether the call at this match is handed a literal command.

    Two texts, because neither answers alone. The masked one shows whether
    any name is read — a literal is blanked, a `${…}` interpolation is not.
    The raw one shows an f-string's braces, which Python 3.11 hides by
    tokenising the whole thing as one string: without it, the editor command
    at `cli_commands_mixin.py:3198` would read as constant.
    """
    start, end = span
    opening = structural.find("(", start)
    if opening == -1 or opening > end + 2:
        # The match is not a call — `from os import system` is the rule's own
        # substring, and the next `(` in the file belongs to something else.
        return False
    argument = _first_argument(structural, opening)
    if argument is None:
        return False
    left, right = argument
    if _IDENTIFIER.search(structural[left:right]):
        # A name is read — which does not settle it where the language can
        # be parsed and the names might only pick between literals.
        #
        # The suffix says what this parser is for; no test can tell it from
        # its absence, and the reason is worth writing down rather than
        # deleting. Reaching here at all takes a name in the fragment, and
        # no JavaScript expression that reads a name is a Python expression
        # made only of literals — `a if b else c` is not JavaScript.
        return (relative.endswith(_PY_SUFFIXES)
                and _literal_python_argument(source[left:right]))
    return "{" not in source[left:right]


def _is_declaration(structural: str, span: tuple[int, int]) -> bool:
    """Whether this match declares a function rather than calling one.

    The last shape the sweep could not tell apart: a method named `exec` in
    a file that genuinely imports `child_process` — an SSH connection class
    is exactly that — passes the import gate and reads a name, so nothing
    else separates it from a call but its shape.

    What follows the parameter list answers for all of them: a body opens
    with `{`, a signature annotates its return with `:`, and a call is
    followed by whatever the surrounding expression wants. Looking for
    `function` or `async` before the name was tried and dropped — it decides
    nothing this does not, and it cannot read a class method, which carries
    no keyword at all.

    The closing paren is found by balance, or a default parameter holding a
    function — `exec(onData = () => {}, options)` — would end the list at
    the wrong place and the declaration would read as a call.
    """
    start, end = span
    opening = structural.find("(", start)
    if opening == -1 or opening > end + 2:
        return False
    after = _skip_balanced(structural, opening, "(", ")")
    if after == opening:
        return False  # unclosed: not something to draw a conclusion from
    tail = structural[after:after + 200].lstrip()
    return tail.startswith("{") or tail.startswith(":")


# The rule wants the word `Safe` within eighty characters of the call, which
# a loader held in a variable never satisfies. Both yaml findings on Hermes
# were that: `Loader=loader` and `Loader=_get_fast_yaml_loader()`, each
# resolving to `getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader`.
_YAML_RULE = "unsafe_yaml_load"
_SAFE_LOADER = "SafeLoader"


def _structural(relative: str, text: str, scannable: str) -> str:
    """The same text with literals opaque, for reasoning about offsets.

    `code_only` keeps JavaScript string bodies on purpose — a rule has to
    read what a literal says. Balancing brackets is the opposite need: the
    comma in `execSync("a,b", opts)` is not an argument separator, and the
    brace in a template holding a program is not a body. Same offsets, two
    readings, and the structural one is never matched against.

    The two readings only differ for JavaScript. Everywhere else the caller's
    `code_only` result *is* the structural one, and recomputing it re-ran the
    pure-Python tokenizer over every `.py` file a second time: measured on
    hermes/ (7080 files), a sweep of 46.29 s against one of 34.17 s, same 47
    findings.
    """
    if relative.endswith(_JS_SUFFIXES):
        from thot.codemap.ts_indexer import _mask

        try:
            return _mask(text)
        except RecursionError:
            return text
    return scannable


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _all_safe(candidates: list, env: dict, returns: dict, depth: int) -> bool:
    """Every binding that is not a `None` sentinel names a safe loader.

    The sentinel is skipped rather than counted unsafe — `_fast_yaml_loader
    = None` at module scope is the lazy-initialisation shape, not a loader.
    Skipping it cannot empty the question, because a name with nothing but
    sentinels behind it is unresolved, and unresolved is not safe.
    """
    real = [node for node in candidates if not _is_none(node)]
    return bool(real) and all(
        _safe_loader(node, env, returns, depth) for node in real
    )


def _safe_loader(node: ast.AST, env: dict, returns: dict, depth: int = 3) -> bool:
    """Whether this expression can only ever produce a safe YAML loader.

    `depth` counts indirections followed — a name looked up, a function's
    returns read — and not structural descent. Spending it on the shape of
    an expression exhausted it before the answer: the lazy initialiser in
    `utils.py` is a call, reading a global, holding an `or`, holding a
    `getattr`, and only the first two of those are indirections.
    """
    if depth < 0:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and node.value.endswith(_SAFE_LOADER)
    if isinstance(node, ast.Attribute):
        return node.attr.endswith(_SAFE_LOADER)
    if isinstance(node, ast.Name):
        if node.id.endswith(_SAFE_LOADER):
            return True
        return _all_safe(env.get(node.id, []), env, returns, depth - 1)
    if isinstance(node, ast.BoolOp):
        return _all_safe(list(node.values), env, returns, depth)
    if isinstance(node, ast.Call):
        function = node.func
        if isinstance(function, ast.Name) and function.id == "getattr":
            # `getattr(yaml, "CSafeLoader", None)` — the name asked for is
            # what decides; the default is what the `or` beside it handles.
            return len(node.args) >= 2 and _safe_loader(
                node.args[1], env, returns, depth
            )
        if isinstance(function, ast.Name):
            return _all_safe(
                returns.get(function.id, []), env, returns, depth - 1
            )
        if isinstance(function, ast.Attribute):
            return function.attr.endswith(_SAFE_LOADER)
    return False


def _local_bindings(tree: ast.AST) -> tuple[dict, dict]:
    """What each name is assigned, and what each function returns.

    Every binding of a name is kept, not the last: a name assigned twice is
    only safe if both assignments are.
    """
    env: dict[str, list] = {}
    returns: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.setdefault(target.id, []).append(node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            returns.setdefault(node.name, []).extend(
                inner.value
                for inner in ast.walk(node)
                if isinstance(inner, ast.Return) and inner.value is not None
            )
    return env, returns


def _imports_pyyaml(tree: ast.AST) -> bool:
    """Whether the name `yaml` in this file is PyYAML itself.

    `import yaml` only. `from ruamel import yaml` binds the same name to a
    different library, and an alias — `import yaml as y` — binds a name the
    rule's own `yaml.load(` never matches, so it needs no clause of its own.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "yaml" for alias in node.names
        ):
            return True
    return False


def _unsafe_yaml_lines(source: str) -> set[int] | None:
    """The lines where `yaml.load` is called without a loader that is safe.

    None when the file will not parse — nothing to conclude from that, so
    the rule keeps whatever its own matcher found.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    if not _imports_pyyaml(tree):
        # The rule is named for one module function. `xai_retirement.py`
        # binds `yaml` to a ruamel round-trip loader and never imports
        # PyYAML at all, so `yaml.load(fh)` there is a method on an object.
        # The limit this leaves: a file that imports PyYAML and shadows the
        # name locally is read as the module's.
        return set()
    env, returns = _local_bindings(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not (isinstance(function, ast.Attribute) and function.attr == "load"):
            continue
        if not (isinstance(function.value, ast.Name)
                and function.value.id == "yaml"):
            continue
        loader = next(
            (word.value for word in node.keywords if word.arg == "Loader"), None
        )
        if loader is None and len(node.args) >= 2:
            loader = node.args[1]
        if loader is None or not _safe_loader(loader, env, returns):
            lines.add(node.lineno)
    return lines


def _is_foreign_name(
    source: str, masked: str, span: tuple[int, int], module: str
) -> bool:
    """Whether the name called here is not the one that module exports.

    Asked of the raw source, because the module name lives inside a string
    literal that masking blanks. A dotted match — `child_process.exec` —
    names the module at the call site and needs no binding to vouch for it.
    """
    start, end = span
    matched = masked[start:end]
    if "." in matched:
        return False
    called = re.match(r"[A-Za-z_$][\w$]*", matched)
    if called is None:
        return False
    return not binds(source, module, called.group(0))


def _fire_line(
    pattern: dict, name: str, relative: str,
    masked: str, structural: str, source: str,
) -> int | None:
    """The line to report, or None when every match on the rule is inert."""
    module = _BOUND_FROM.get(name)
    judged = name in _INJECTION_RULES
    credential = name in _CREDENTIAL_RULES
    yaml_lines = (
        _unsafe_yaml_lines(source)
        if name == _YAML_RULE and relative.endswith(_PY_SUFFIXES)
        else None
    )
    if module is None and not judged and not credential and yaml_lines is None:
        return _first_line(masked, pattern)
    spans = _spans(masked, pattern)
    if not spans:
        return _first_line(masked, pattern)  # a rule that fires on the path
    for span in spans:
        line = masked.count("\n", 0, span[0]) + 1
        if yaml_lines is not None and line not in yaml_lines:
            continue
        if credential and _is_placeholder(name, masked[span[0]:span[1]]):
            continue
        if module and _is_foreign_name(source, structural, span, module):
            continue
        if judged and _constant_command(relative, structural, source, span):
            continue
        if judged and _is_declaration(structural, span):
            continue
        return line
    return None


def _first_line(text: str, pattern: dict) -> int:
    """Where the rule fires, so the finding points at code and not at line 1."""
    regex = pattern.get("regex")
    if regex:
        match = re.search(regex, text)
        if match:
            return text.count("\n", 0, match.start()) + 1
    for needle in pattern.get("substrings") or ():
        index = text.find(needle)
        if index != -1:
            return text.count("\n", 0, index) + 1
    return 1


def _line_identity(text: str, line: int) -> str:
    """Hash of the triggering line, whitespace-normalised.

    This is what a stored verdict is keyed on, so the granularity is a safety
    property, not a detail. Keying on the rule name alone made a dismissal
    immortal — dismiss one os.system in a file and every later os.system in
    that file inherits the pardon. Keying on the whole file would be the
    opposite failure: any unrelated edit would resurrect settled decisions.

    The triggering line is the right unit: change what the dangerous call
    does and the verdict expires; reformat or edit around it and it holds.
    """
    lines = text.splitlines()
    raw = lines[line - 1] if 0 < line <= len(lines) else ""
    normalised = " ".join(raw.split())
    return hashlib.sha256(normalised.encode()).hexdigest()[:16]


# A rule proves an absence far more often than a presence, and `re` proves it
# the expensive way: it cannot factor an alternation, so it walks the text
# character by character. Measured on hermes/ (7080 files): 117 750 searches
# to produce 47 findings. Asking `str.__contains__` first — a C skip loop —
# leaves 7806 of them and takes the sweep from 34.17 s to 17.28 s on the same
# 47 findings.
#
# Below this length a literal filters nothing: `(` is in every source file,
# and the lookup costs more than the search it was meant to save.
_MIN_GATE_LITERAL = 4

_GATE_CACHE: dict[str, tuple[str, ...] | None] = {}


def _leading_literal(sequence) -> str:
    """The literal every match of `sequence` starts with, possibly empty."""
    head: list[str] = []
    for op, argument in sequence:
        if op is _sre.LITERAL:
            head.append(chr(argument))
        elif op not in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            break
    return ''.join(head)


def _mandatory_literals(sequence) -> tuple[str, ...] | None:
    """Literals of which every match of `sequence` contains at least one.

    None when no such set can be proven, which is the answer for a rule built
    out of character classes. Only what a match must traverse contributes: an
    optional repeat and a back-reference yield nothing, a group is entered
    only where it cannot be skipped, and a zero-width assertion is stepped
    over rather than cutting the literal run around it — `\\bos\\.system` has
    to spell `os.system`, boundary and all.
    """
    best: tuple[str, ...] | None = None
    run: list[str] = []

    def rank(candidate: tuple[str, ...]) -> tuple[int, int]:
        return (min(len(item) for item in candidate),
                sum(len(item) for item in candidate))

    def consider(candidate: tuple[str, ...] | None) -> None:
        nonlocal best
        if not candidate or any(len(item) < _MIN_GATE_LITERAL for item in candidate):
            return
        # A text holding `postgresql` holds `postgres`: testing for both is
        # one substring pass wasted on every file in the repository.
        candidate = tuple(
            item for item in candidate
            if not any(other != item and other in item for other in candidate)
        )
        if best is None or rank(candidate) > rank(best):
            best = candidate

    def flush() -> None:
        if run:
            consider((''.join(run),))
            run.clear()

    for op, argument in sequence:
        if op is _sre.LITERAL:
            run.append(chr(argument))
            continue
        if op in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            continue  # matches the empty string: the run is uninterrupted
        prefix = ''.join(run)
        flush()
        if op is _sre.SUBPATTERN:
            # A group that turns a flag on mid-pattern is read as opaque:
            # `(?i:…)` would make its literals unusable as a substring test.
            if not argument[1] and not argument[2]:
                consider(_mandatory_literals(argument[3]))
        elif op in (_sre.MAX_REPEAT, _sre.MIN_REPEAT):
            if argument[0] >= 1:
                consider(_mandatory_literals(argument[2]))
        elif op is _sre.BRANCH:
            arms = [_mandatory_literals(arm) for arm in argument[1]]
            if all(arms):
                consider(tuple(sorted({lit for arm in arms for lit in arm})))
            # The parser factors a common prefix out of an alternation:
            # `(?:ghp_|gho_|ghu_)` parses as `gh` followed by `(?:p_|o_|u_)`,
            # and neither half is long enough to filter on. Gluing the run
            # back onto each arm's own leading literal recovers the branch
            # the source spelled, which is the one worth testing for.
            if prefix:
                heads = [_leading_literal(arm) for arm in argument[1]]
                if all(heads):
                    consider(tuple(sorted({prefix + head for head in heads})))
        elif op is _sre.ATOMIC_GROUP:
            consider(_mandatory_literals(argument))
    flush()
    return best


def _literal_gate(regex: str) -> tuple[str, ...] | None:
    """A substring test that every match of `regex` passes, or None.

    Derived from the parsed pattern, never written by hand. A hand-written
    gate is a silent `return False` for the branch its author forgot: listing
    `verify=False` and `rejectUnauthorized` but not
    `ssl._create_unverified_context` switches tls_verification_disabled off
    and nothing in the output says so.
    """
    if regex in _GATE_CACHE:
        return _GATE_CACHE[regex]
    gate: tuple[str, ...] | None = None
    if _sre is not None:
        try:
            parsed = _sre_parse.parse(regex)
            # Case folding would make a case-sensitive substring test wrong.
            if not parsed.state.flags & re.IGNORECASE:
                gate = _mandatory_literals(parsed)
        except Exception:  # an unparseable rule is simply left ungated
            gate = None
    _GATE_CACHE[regex] = gate
    return gate


def _applies(pattern: dict, relative: str, text: str) -> bool:
    path_check = pattern.get("path_check")
    if path_check is not None and not path_check(relative):
        return False
    path_filter = pattern.get("path_filter")
    if path_filter is not None and not path_filter(relative):
        return False

    regex = pattern.get("regex")
    substrings = pattern.get("substrings")
    if regex is None and not substrings:
        # A path-only rule (a CI workflow, say) fires on the path alone.
        return path_check is not None
    if regex:
        # The gate answers only for the regex. `substrings` is the rule's
        # other arm, not a precondition of this one: child_process_exec and
        # os_system_injection carry both, and stopping here would drop
        # `child_process.exec` and `from os import system` on the floor.
        gate = _literal_gate(regex)
        if gate is None or any(literal in text for literal in gate):
            if re.search(regex, text):
                return True
    return any(needle in text for needle in substrings or ())


def _scenario(pattern: dict) -> str:
    reminder = (pattern.get("reminder") or "").strip()
    condensed = " ".join(reminder.split())
    if len(condensed) <= _SCENARIO_CHARS:
        return condensed
    return condensed[:_SCENARIO_CHARS].rsplit(" ", 1)[0] + "…"


def scan_text(relative: str, text: str, rules=None) -> list[Finding]:
    """Every rule that fires in one file, at most once each.

    `rules` defaults to the whole catalogue, which is what the write-time
    plugin wants: it is about to write this file, so every reminder applies.
    The audit passes `AUDIT_PATTERNS` instead — see the note beside it.
    """
    findings: list[Finding] = []
    scannable = code_only(relative, text)
    structural = _structural(relative, text, scannable)
    for pattern in (SECURITY_PATTERNS if rules is None else rules):
        name = pattern.get("ruleName", "?")
        # A rule that reads raw text sees the file as written; every other
        # rule sees it with literals and comments blanked. Both views have
        # the same offsets, so a line number means the same thing in either.
        subject = text if pattern.get("raw") else scannable
        try:
            if not _applies(pattern, relative, subject):
                continue
        except re.error:  # a bad regex must not take the audit down
            continue

        # A Thot rule states its own impact: severity is a property of
        # the weakness, not of which catalogue the rule came from.
        impact = pattern.get("impact") or _IMPACT.get(name, _DEFAULT_IMPACT)
        line = _fire_line(pattern, name, relative,
                          subject, structural, text)
        if line is None:
            continue  # every match is a literal: nothing to inject into
        location = CodeRef(
            path=relative,
            line=line,
            symbol=None,
            # Keyed on what the rule read: for a credential the secret *is*
            # the line, and hashing the blanked view would give every key in
            # a file the same identity — one dismissal pardoning the next.
            ast_hash=_line_identity(subject, line),
        )
        rule = f"pattern.{name}"
        role = role_of(relative)
        provenance = {"phase": "motif", "source": "hermes/security-guidance"}
        if role is not Role.PRODUCTION:
            # Said on the finding, not only folded into the number: a reader
            # has to see *why* a dangerous-looking call was ranked low.
            provenance["rôle"] = role.value
        findings.append(
            Finding(
                id=Finding.compute_id(rule, location),
                rule=rule,
                severity=compute_severity(
                    impact, None, Confidence.PLAUSIBLE,
                    # `distance=0`, and not the unknown-reach penalty the
                    # taint engine takes. A pattern rule makes no claim about
                    # who calls this file: `hashlib.md5(...)` is a weak hash
                    # whether one entry point reaches it or none do, and the
                    # weakness is in the line as written. Charging it a
                    # reachability discount is a category error, and it was an
                    # expensive one — 0.5 x 0.8 x 0.6 = 0.24 against a MEDIUM
                    # threshold of 0.25, so *every* medium-impact pattern in
                    # the catalogue was ranked `low` and hidden by the default
                    # report. Measured on 18 300 labelled cases, four rules
                    # scoring +100 % with no false positive at all were
                    # invisible: 7 points of Youden, bought back for nothing.
                    # `role` still applies — a weak hash in a test fixture is
                    # still not news.
                    entrypoints_known=False, role=role,
                    reachable=True,
                ),
                confidence=Confidence.PLAUSIBLE,
                location=location,
                failure_scenario=_scenario(pattern),
                provenance=provenance,
            )
        )
    return findings


# The forked catalogue plus Thot's own. Built once: `sweep_patterns` runs
# it over every file in the scope, and rebuilding the list per file cost
# a concatenation seven thousand times on a real tree.
SWEEP_RULES = AUDIT_PATTERNS + THOT_PATTERNS


def sweep_patterns(root: Path, files: list[str]) -> list[Finding]:
    """Run every rule over every file the scope selected."""
    root = Path(root)
    findings: list[Finding] = []
    for relative in files:
        try:
            text = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(relative, text, SWEEP_RULES))
    return findings
