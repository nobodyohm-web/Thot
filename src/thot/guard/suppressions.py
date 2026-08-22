"""Where old, wrong security reasoning hides.

Twice in one audit a comment disarming a scanner turned out to be false.
`# nosec B310 — scheme checked above` sat on an SSRF whose scheme check
stopped `file://` and nothing else. `# noqa: S310 (configured peers)` sat on
a fetch whose URL arrives from a model through a tool argument. Both were
true about the code at the moment they were written, and neither was true
any more.

That is what makes a suppression worth reporting as a class. It is a claim
about the code, written once, that no tool re-checks and that outlives the
callers it described — and it is invisible to every scanner *by design*,
including the ones Thot ships. A finding here does not say the line is
dangerous. It says nobody has re-read the reason it was excused.

Reported LOW on purpose: most suppressions are fine, and the point is to put
them in front of a reader — and, in a deep pass, in front of an agent that
can go and check whether the justification still holds.
"""

from __future__ import annotations

import re
from pathlib import Path

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.guard.scanner import _line_identity
from thot.scoring.role import Role, role_of
from thot.scoring.severity import compute_severity

RULE = "suppression.security"

# Only suppressions that silence a *security* check. `# noqa: E501` is a line
# length, `// @ts-ignore` is a type — neither is a claim about safety, and
# reporting them would bury the ones that are.
MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"#\s*nosec\b(?P<tail>[^\n]*)"), "bandit"),
    (re.compile(r"#\s*noqa:\s*(?P<tail>[^\n]*\bS\d+[^\n]*)"), "flake8-bandit"),
    (re.compile(r"#\s*nosemgrep\b(?P<tail>[^\n]*)"), "semgrep"),
    (
        re.compile(
            r"//\s*eslint-disable(?:-next-line|-line)?\s+(?P<tail>[^\n]*security[^\n]*)"
        ),
        "eslint-security",
    ),
    (re.compile(r"@SuppressWarnings\((?P<tail>[^)\n]*)\)"), "java"),
    (re.compile(r"#\s*type:\s*ignore\[(?P<tail>[^\]\n]*security[^\]\n]*)\]"), "mypy"),
)

# Suffixes worth reading. A suppression in a lock file or a minified bundle
# is not something anyone wrote on purpose.
READABLE = (
    ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".java", ".kt", ".go", ".rb", ".rs", ".php", ".cs",
)


def _justification(tail: str) -> str:
    """The words after the marker — the claim, when there is one."""
    cleaned = tail.strip(" \t:#-—,")
    return " ".join(cleaned.split())[:200]


PYTHON_SUFFIXES = (".py", ".pyi")


def _python_comments(text: str) -> dict[int, str] | None:
    """Real comments only, by line — or None when the file will not parse.

    A regular expression cannot tell `# nosec` in a comment from `# nosec`
    quoted inside a docstring, and this module's own docstring quotes two of
    them. Python hands out its comment tokens for free; using them is both
    exact and cheaper than pretending otherwise.
    """
    import io
    import tokenize

    found: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                found.setdefault(token.start[0], token.string)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    return found


def scan_text(relative: str, text: str) -> list[Finding]:
    """Every security suppression in one file."""
    if not relative.lower().endswith(READABLE):
        return []

    findings: list[Finding] = []
    role = role_of(relative)
    seen: set[str] = set()

    comments: dict[int, str] | None = None
    if relative.lower().endswith(PYTHON_SUFFIXES):
        comments = _python_comments(text)

    for number, line in enumerate(text.splitlines(), start=1):
        if comments is not None:
            # Exact: the token, not the line it sits on.
            line = comments.get(number, "")
            if not line:
                continue
        for pattern, family in MARKERS:
            match = pattern.search(line)
            if match is None:
                continue
            location = CodeRef(
                path=relative,
                line=number,
                symbol=None,
                ast_hash=_line_identity(text, number),
                # Several suppressions in one file are several claims; the
                # line's own identity keeps them apart, so dismissing one
                # does not pardon the rest.
                site=f"{family}#{number}",
            )
            identity = Finding.compute_id(RULE, location)
            if identity in seen:
                continue
            seen.add(identity)

            reason = _justification(match.groupdict().get("tail") or "")
            provenance = {"phase": "motif", "outil": family}
            if role is not Role.PRODUCTION:
                provenance["rôle"] = role.value
            findings.append(
                Finding(
                    id=identity,
                    rule=RULE,
                    severity=compute_severity(
                        Severity.LOW, None, Confidence.PLAUSIBLE,
                        entrypoints_known=False, role=role,
                    ),
                    confidence=Confidence.PLAUSIBLE,
                    location=location,
                    failure_scenario=(
                        f"Un contrôle de sécurité est désactivé ici ({family})"
                        + (f", au motif : « {reason} »" if reason else
                           ", sans motif écrit")
                        + ". Cette justification n'est vérifiée par aucun "
                        "outil et survit aux appelants qu'elle décrivait : "
                        "reste-t-elle vraie du code tel qu'il est aujourd'hui ?"
                    ),
                    provenance=provenance,
                )
            )
            break  # one finding per line: it is one claim

    return findings


def sweep_suppressions(root: Path, files: list[str]) -> list[Finding]:
    """Every security suppression in scope."""
    root = Path(root)
    findings: list[Finding] = []
    for relative in files:
        if not relative.lower().endswith(READABLE):
            continue
        try:
            text = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(relative, text))
    return findings
