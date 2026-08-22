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

import hashlib
import io
import re
import tokenize
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.taint.js_catalog import imports
from thot.guard.patterns import _JS_EXTS as _JS_SUFFIXES
from thot.guard.patterns import SECURITY_PATTERNS
from thot.scoring.role import Role, role_of
from thot.scoring.severity import compute_severity

# Impact per rule. The upstream data carries a reminder but no severity, and
# treating a disabled TLS check like an eval() of user input would make the
# whole sweep unreadable.
# The module a rule's call has to come from, when its bare name is ordinary.
# `exec(` matches a local helper, a method definition and an interface
# signature as readily as `child_process.exec`, and the sweep had no way to
# tell them apart. The taint engine has gated this on the file's imports
# since it was written; the same gate, from the same helper, applies here.
#
# The price is a call reached through a local wrapper — `import { exec } from
# "./shell"` — which the gate now skips. The taint engine already pays it,
# and it buys back three of the eight HIGH `exec` findings on the two
# shipped trees, every one of which was prose or a declaration.
_NEEDS_IMPORT: dict[str, tuple[str, ...]] = {
    "child_process_exec": ("child_process",),
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

    JavaScript and TypeScript are masked by the same routine the taint
    engine uses, which is where this was measured: on the two shipped trees,
    a JSDoc line reading "prefer this over `exec()`" and a Python snippet
    held in a TypeScript template literal both became HIGH findings — ranked
    above findings that had a traced path behind them.

    Every other language is scanned as-is, and so is a file that will not
    tokenise — a syntax error must never silently disable the sweep. Blanking
    literals is safe only while no rule needs to match inside one; none of
    the 25 looks for a secret or a URL.
    """
    if relative.endswith(_JS_SUFFIXES):
        from thot.codemap.ts_indexer import _mask

        try:
            return _mask(text)
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


def _constant_command(masked: str, source: str, span: tuple[int, int]) -> bool:
    """Whether the call at this match is handed a literal command.

    Two texts, because neither answers alone. The masked one shows whether
    any name is read — a literal is blanked, a `${…}` interpolation is not.
    The raw one shows an f-string's braces, which Python 3.11 hides by
    tokenising the whole thing as one string: without it, the editor command
    at `cli_commands_mixin.py:3198` would read as constant.
    """
    start, end = span
    opening = masked.find("(", start)
    if opening == -1 or opening > end + 2:
        # The match is not a call — `from os import system` is the rule's own
        # substring, and the next `(` in the file belongs to something else.
        return False
    argument = _first_argument(masked, opening)
    if argument is None:
        return False
    left, right = argument
    if _IDENTIFIER.search(masked[left:right]):
        return False
    return "{" not in source[left:right]


def _fire_line(pattern: dict, name: str, masked: str, source: str) -> int | None:
    """The line to report, or None when every match on the rule is inert."""
    if name not in _INJECTION_RULES:
        return _first_line(masked, pattern)
    spans = _spans(masked, pattern)
    if not spans:
        return _first_line(masked, pattern)
    for span in spans:
        if not _constant_command(masked, source, span):
            return masked.count("\n", 0, span[0]) + 1
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
    if regex and re.search(regex, text):
        return True
    return any(needle in text for needle in substrings or ())


def _scenario(pattern: dict) -> str:
    reminder = (pattern.get("reminder") or "").strip()
    condensed = " ".join(reminder.split())
    if len(condensed) <= _SCENARIO_CHARS:
        return condensed
    return condensed[:_SCENARIO_CHARS].rsplit(" ", 1)[0] + "…"


def scan_text(relative: str, text: str) -> list[Finding]:
    """Every rule that fires in one file, at most once each."""
    findings: list[Finding] = []
    scannable = code_only(relative, text)
    for pattern in SECURITY_PATTERNS:
        name = pattern.get("ruleName", "?")
        needed = _NEEDS_IMPORT.get(name)
        # Asked of the raw text, never the masked one: the module name lives
        # inside a string literal, which masking blanks.
        if needed and not any(imports(text, module) for module in needed):
            continue
        try:
            if not _applies(pattern, relative, scannable):
                continue
        except re.error:  # a bad regex must not take the audit down
            continue

        impact = _IMPACT.get(name, _DEFAULT_IMPACT)
        line = _fire_line(pattern, name, scannable, text)
        if line is None:
            continue  # every match is a literal: nothing to inject into
        location = CodeRef(
            path=relative,
            line=line,
            symbol=None,
            ast_hash=_line_identity(scannable, line),
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
                    entrypoints_known=False, role=role,
                ),
                confidence=Confidence.PLAUSIBLE,
                location=location,
                failure_scenario=_scenario(pattern),
                provenance=provenance,
            )
        )
    return findings


def sweep_patterns(root: Path, files: list[str]) -> list[Finding]:
    """Run every rule over every file the scope selected."""
    root = Path(root)
    findings: list[Finding] = []
    for relative in files:
        try:
            text = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(relative, text))
    return findings
