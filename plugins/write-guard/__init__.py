"""Warn on a dangerous write, without blocking it.

This is the original use Hermes Agent made of these patterns, kept: the file
is written and the warning rides back to the model, which corrects itself on
the next turn. Blocking would be worse — a model that cannot write cannot fix
anything, and a false positive would deadlock the session.
"""

from __future__ import annotations


def pre_write(*, path: str = "", content: str = "", **_: object) -> str:
    from thot.guard.scanner import scan_text

    findings = scan_text(path, content)
    if not findings:
        return ""

    lines = [
        "⚠ Motifs à risque dans ce que tu viens d'écrire — corrige si ce n'est "
        "pas intentionnel :"
    ]
    for finding in findings[:4]:
        rule = finding.rule.removeprefix("pattern.")
        lines.append(f"  · {rule} ({path}:{finding.location.line})")
        lines.append(f"    {finding.failure_scenario[:220]}")
    return "\n".join(lines)
