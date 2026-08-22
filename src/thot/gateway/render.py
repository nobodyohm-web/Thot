"""Findings, written for a phone.

A terminal report is a table. A chat report is read one-handed, on a train,
by someone who wants to know whether to open a laptop. Different question,
different shape: the count first, the worst three next, and nothing else.
"""

from __future__ import annotations

from thot.contracts import Finding

MARK = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
    "info": "·",
}

# Three is what fits above the fold in every client tested. The rest is a
# count, because a list nobody scrolls is a list nobody reads.
SHOWN = 3


def line(index: int, finding: Finding) -> str:
    mark = MARK.get(finding.severity.value, "·")
    return (f"{index}. {mark} {finding.rule}\n"
            f"   {finding.location.path}:{finding.location.line}")


def counts(findings: list[Finding]) -> str:
    tally: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.value
        tally[key] = tally.get(key, 0) + 1
    order = ("critical", "high", "medium", "low", "info")
    return " · ".join(f"{tally[k]} {k}" for k in order if k in tally)


def report(findings: list[Finding], *, root: str = "", title: str = "Audit",
           shown: int = SHOWN, engine: str | None = None) -> str:
    """The message a scheduled audit pushes.

    `engine` names what argued. What the nightly loop sends is exactly the
    cascade's product — `_is_news` keeps confirmations and contested
    refutations and nothing else — and the message used to carry severity
    counts alone. This is the only place the panel's work reaches someone who
    is not watching the terminal.
    """
    name = root.rstrip("/").rsplit("/", 1)[-1] if root else ""
    header = f"{title} — {name}" if name else title

    if not findings:
        return f"{header}\nRien de nouveau."

    said = {"confirmed": "confirmé", "refuted": "réfuté"}
    decided: dict[str, int] = {}
    for finding in findings:
        label = said.get(finding.confidence.value)
        if label:
            decided[label] = decided.get(label, 0) + 1
    judged = (
        "\njugé par " + str(engine) + " : "
        + " · ".join(f"{n} {k}(s)" for k, n in sorted(decided.items()))
        if engine and decided else ""
    )

    body = [f"{header}\n{len(findings)} finding(s) — {counts(findings)}{judged}", ""]
    body += [line(index, finding)
             for index, finding in enumerate(findings[:shown], start=1)]
    if len(findings) > shown:
        body.append(f"\n… {len(findings) - shown} de plus. `findings` pour la suite.")
    return "\n".join(body)


def detail(index: int, finding: Finding) -> str:
    """One finding, in full, for when someone asks about it."""
    parts = [line(index, finding)]
    if finding.location.symbol:
        parts.append(f"   dans {finding.location.symbol}")
    parts.append(f"   {finding.confidence.value}")
    if finding.failure_scenario:
        parts.append("")
        parts.append(finding.failure_scenario[:900])
    if finding.taint_path:
        parts.append("")
        parts.append("Chemin :")
        parts += [f"   {ref.path}:{ref.line} {ref.symbol}".rstrip()
                  for ref in finding.taint_path[:8]]
    return "\n".join(parts)
