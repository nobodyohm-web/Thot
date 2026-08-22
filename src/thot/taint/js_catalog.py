"""Sinks and sources for JavaScript and TypeScript.

Kept apart from the Python catalog rather than merged into it. The two
languages disagree about what a dangerous name looks like — `exec` is a
module function in Python and usually a destructured import in JavaScript,
`query` is a cursor method in one and a request property in the other — and a
single list would make each language answer for the other's false positives.

`needs` is the precision gate that makes bare names usable. Real JavaScript
writes `exec(cmd)` after `const { exec } = require("child_process")`, so
matching only the qualified form would miss nearly every real case; matching
the bare name everywhere would flag any function someone chose to call `exec`.
A rule with `needs` only fires in a file that actually imports that module.
"""

from __future__ import annotations

from dataclasses import dataclass

from thot.contracts import Severity


@dataclass(frozen=True)
class JsSink:
    id: str
    names: tuple[str, ...]          # matched on the last dotted segment
    impact: Severity
    description: str
    needs: tuple[str, ...] = ()     # modules the file must import
    dangerous_args: tuple[int, ...] = (0,)


@dataclass(frozen=True)
class JsSource:
    id: str
    patterns: tuple[str, ...]       # matched as a dotted prefix
    description: str


SINKS: tuple[JsSink, ...] = (
    JsSink(
        id="sink.js.exec",
        names=("exec", "execSync", "execFile", "execFileSync"),
        impact=Severity.CRITICAL,
        description="Exécution d'une commande shell",
        needs=("child_process",),
    ),
    JsSink(
        id="sink.js.spawn",
        names=("spawn", "spawnSync", "fork"),
        impact=Severity.HIGH,
        description="Lancement d'un sous-processus",
        needs=("child_process",),
    ),
    JsSink(
        id="sink.js.eval",
        names=("eval", "Function", "runInNewContext", "runInThisContext",
               "compileFunction"),
        impact=Severity.CRITICAL,
        description="Évaluation de code arbitraire",
    ),
    JsSink(
        id="sink.js.dynamic_require",
        names=("require",),
        impact=Severity.HIGH,
        description="Chargement d'un module choisi à l'exécution",
    ),
    JsSink(
        id="sink.js.sql",
        names=("query", "raw", "unprepared", "executeSql"),
        impact=Severity.HIGH,
        description="Requête SQL construite par concaténation",
        needs=("pg", "mysql", "mysql2", "sqlite3", "knex", "sequelize",
               "better-sqlite3", "typeorm", "postgres"),
    ),
    JsSink(
        id="sink.js.html",
        # `write` bare is not a sink, it is a verb: `socket.write`,
        # `process.stderr.write`, `stream.write`. Only the document's is one,
        # so this rule is written qualified — the matcher takes the whole
        # dotted name when the pattern carries a dot.
        names=("insertAdjacentHTML", "document.write", "document.writeln"),
        impact=Severity.HIGH,
        description="Écriture de HTML non échappé",
    ),
    JsSink(
        id="sink.js.path",
        names=("readFile", "readFileSync", "writeFile", "writeFileSync",
               "createReadStream", "createWriteStream", "unlink", "unlinkSync",
               "sendFile"),
        impact=Severity.MEDIUM,
        description="Chemin de fichier construit à partir d'une entrée",
        needs=("fs", "node:fs", "fs/promises", "express"),
    ),
    JsSink(
        id="sink.js.redirect",
        names=("redirect",),
        impact=Severity.MEDIUM,
        description="Redirection vers une destination non validée",
        needs=("express", "koa", "fastify"),
    ),
)

# Properties whose assignment is itself the sink: `el.innerHTML = value`.
ASSIGNMENT_SINKS: tuple[JsSink, ...] = (
    JsSink(
        id="sink.js.html",
        names=("innerHTML", "outerHTML"),
        impact=Severity.HIGH,
        description="Écriture de HTML non échappé",
    ),
    JsSink(
        id="sink.js.dangerous_html",
        names=("__html",),
        impact=Severity.HIGH,
        description="HTML injecté via dangerouslySetInnerHTML",
    ),
)

SOURCES: tuple[JsSource, ...] = (
    JsSource(
        id="source.js.request",
        patterns=("req.query", "req.body", "req.params", "req.headers",
                  "req.cookies", "req.url", "request.query", "request.body",
                  "request.params", "ctx.query", "ctx.params",
                  "ctx.request.body"),
        description="Requête HTTP entrante",
    ),
    JsSource(
        id="source.js.process",
        patterns=("process.argv", "process.env"),
        description="Environnement ou ligne de commande",
    ),
    JsSource(
        id="source.js.browser",
        patterns=("location.search", "location.hash", "location.href",
                  "window.name", "document.URL", "document.referrer",
                  "document.location"),
        description="Valeur contrôlée par l'URL ou la page",
    ),
    JsSource(
        id="source.js.message",
        patterns=("event.data", "message.data", "msg.data", "e.data"),
        description="Message reçu d'une autre origine",
    ),
)

# A tainted value that passes through one of these stops being tainted.
SANITIZERS: frozenset[str] = frozenset({
    "encodeURIComponent", "encodeURI", "escape", "escapeHtml", "escapeHTML",
    "Number", "parseInt", "parseFloat", "BigInt", "Boolean",
    "basename", "sanitize", "sanitizeHtml", "quote", "shellQuote",
    "validate", "assertSafe",
})

# What the file must be importing for a `needs` rule to fire.
IMPORT_MARKERS = (
    'require("{name}")', "require('{name}')",
    'from "{name}"', "from '{name}'",
    'import "{name}"', "import '{name}'",
)


def imports(source: str, module: str) -> bool:
    """Whether this file pulls in a module, in any of the four spellings.

    Reads the *raw* source, never the masked one: masking blanks the inside
    of every string literal, and the module name lives inside exactly that.
    A `require("child_process")` sitting in a comment would count — a
    negligible price for a gate that otherwise never fires.
    """
    for shape in IMPORT_MARKERS:
        if shape.format(name=module) in source:
            return True
        if shape.format(name=f"node:{module}") in source:
            return True
    return False
