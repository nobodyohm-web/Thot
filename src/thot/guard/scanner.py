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

import io
import re
import tokenize
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.guard.patterns import SECURITY_PATTERNS
from thot.scoring.severity import compute_severity

# Impact per rule. The upstream data carries a reminder but no severity, and
# treating a disabled TLS check like an eval() of user input would make the
# whole sweep unreadable.
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
    """Blank out Python string literals and comments, preserving offsets.

    A rule catalog, a test fixture and a piece of documentation all *mention*
    dangerous calls without making them. Scanning raw text flags all three:
    on Thot's own source that was 25 findings and every one was false. Blanking
    with spaces rather than deleting keeps every line number intact, so a real
    finding still points at the right line.

    Not applicable outside Python, and a file that will not tokenise is scanned
    as-is — a syntax error must never silently disable the sweep.
    """
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
        try:
            if not _applies(pattern, relative, scannable):
                continue
        except re.error:  # a bad regex must not take the audit down
            continue

        impact = _IMPACT.get(name, _DEFAULT_IMPACT)
        location = CodeRef(
            path=relative, line=_first_line(scannable, pattern), symbol=None,
            ast_hash=name,  # stable identity: the rule, not the line
        )
        rule = f"pattern.{name}"
        findings.append(
            Finding(
                id=Finding.compute_id(rule, location),
                rule=rule,
                severity=compute_severity(
                    impact, None, Confidence.PLAUSIBLE, entrypoints_known=False
                ),
                confidence=Confidence.PLAUSIBLE,
                location=location,
                failure_scenario=_scenario(pattern),
                provenance={"phase": "motif", "source": "hermes/security-guidance"},
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
