"""A session, or an audit, as one HTML file you can send to someone.

Ported from Prime Agent's `core/export-html/`, minus its vendored
highlighter and marked.js: those exist so a transcript renders code the
way the terminal did, and Thot's transcripts are findings and French
prose. What is kept is the property that made it useful — **one file, no
network, no assets**. It opens from a USB stick, survives an email, and
does not phone anywhere when a security lead opens it.

Everything is escaped. A finding's scenario contains attacker-controlled
strings by construction: the payload that reaches the sink is quoted in
it. An export that rendered those as markup would be a stored XSS in the
report about the vulnerability.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone

STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2.5rem 1.5rem; background: #12100e; color: #e8e2d8;
       font: 15px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.4rem; margin: 0 0 .2rem; color: #d8a84e; letter-spacing: .04em; }
.meta { color: #8a8378; margin-bottom: 2rem; font-size: .85rem; }
section { border-left: 2px solid #2b2723; padding: .1rem 0 .1rem 1rem;
          margin: 0 0 1.4rem; }
section.user { border-color: #d8a84e; }
section.audit, section.verdict { border-color: #7a94b8; }
.role { color: #8a8378; font-size: .75rem; text-transform: uppercase;
        letter-spacing: .1em; margin-bottom: .35rem; }
pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #2b2723;
         vertical-align: top; }
th { color: #8a8378; font-weight: 400; font-size: .75rem;
     text-transform: uppercase; letter-spacing: .08em; }
.critical { color: #e06c5a; } .high { color: #d8874e; }
.medium { color: #d8c04e; } .low, .info { color: #8a8378; }
footer { color: #6b655c; font-size: .78rem; margin-top: 3rem;
         border-top: 1px solid #2b2723; padding-top: 1rem; }
@media (prefers-color-scheme: light) {
  body { background: #faf8f4; color: #26221d; }
  section { border-color: #ddd6c9; } .meta, .role, th, footer { color: #7a736a; }
  th, td { border-bottom-color: #e6dfd2; }
}
"""

PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>{style}</style></head>
<body><main>
<h1>{heading}</h1>
<p class="meta">{meta}</p>
{body}
<footer>{footer}</footer>
</main></body></html>
"""


def _escape(text: str) -> str:
    return html.escape(text or "", quote=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class Page:
    title: str
    html: str

    def write(self, path) -> object:
        from pathlib import Path

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.html, encoding="utf-8")
        return target


def findings_table(findings) -> str:
    if not findings:
        return "<p>Aucun finding.</p>"
    rows = []
    for index, finding in enumerate(findings, start=1):
        severity = finding.severity.value
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f'<td class="{severity}">{_escape(severity.upper())}</td>'
            f"<td>{_escape(finding.rule)}</td>"
            f"<td>{_escape(finding.location.path)}:{finding.location.line}</td>"
            f"<td>{_escape(finding.confidence.value)}</td>"
            f"<td><pre>{_escape(finding.failure_scenario)}</pre></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>#</th><th>Gravité</th><th>Règle</th>"
        "<th>Emplacement</th><th>Confiance</th><th>Scénario</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def audit_page(result, *, root: str = "") -> Page:
    """One audit, as a page a security lead can open without a terminal."""
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    tally = " · ".join(f"{n} {k}" for k, n in counts.items()) or "aucun finding"

    name = str(root).rstrip("/").rsplit("/", 1)[-1] or "dépôt"
    meta = (f"{len(result.manifest.files)} fichiers · {tally} · "
            f"analyse en {result.elapsed:.2f} s · {_now()}")

    return Page(
        title=f"Thot — {name}",
        html=PAGE.format(
            title=_escape(f"Thot — audit de {name}"),
            style=STYLE,
            heading=_escape(f"Audit — {name}"),
            meta=_escape(meta),
            body=findings_table(result.findings),
            footer=_escape(
                "Produit par Thot. Sans passe --deep, chaque finding est "
                "PLAUSIBLE : détecté statiquement, pas prouvé par exécution."
            ),
        ),
    )


def session_page(info, turns) -> Page:
    """One conversation, transcript and audits together."""
    blocks = []
    for turn in turns:
        content = (turn.content or "").strip()
        if not content:
            continue
        blocks.append(
            f'<section class="{_escape(turn.role)}">'
            f'<div class="role">{_escape(turn.role)}</div>'
            f"<pre>{_escape(content)}</pre></section>"
        )

    meta = (f"{info.root} · {len(turns)} message(s) · "
            f"ouverte le {info.started_at[:16]}")
    return Page(
        title=f"Thot — {info.title or info.id[:8]}",
        html=PAGE.format(
            title=_escape(f"Thot — {info.title or info.id[:8]}"),
            style=STYLE,
            heading=_escape(info.title or f"Session {info.id[:8]}"),
            meta=_escape(meta),
            body="".join(blocks) or "<p>Session vide.</p>",
            footer=_escape(f"Session {info.id} · exportée le {_now()} par Thot."),
        ),
    )
