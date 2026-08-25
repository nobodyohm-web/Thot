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

import re

from contextlib import contextmanager
from dataclasses import dataclass, replace

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
    # Whether somebody who is not running this process can choose the value.
    # `process.env` and `process.argv` belong to whoever started it; a
    # request, a page URL and a cross-origin message do not.
    remote: bool = False


@dataclass(frozen=True)
class JsCallbackSource:
    """A function the runtime calls for you, handing it an untrusted value.

    The parameter *is* the input. No line in the file ever assigns it, so an
    engine that only follows assignments and calls walks straight past the
    place the value arrives — which on browser and event-driven code is most
    of the code there is.
    """

    id: str
    names: tuple[str, ...]          # matched on the last dotted segment
    description: str
    parameters: tuple[int, ...] = (0,)
    remote: bool = True


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

# `target[key] = value` where the *key* is controlled. The payload is the
# key and not the value: a key of `__proto__` writes through to every object
# in the program, so what makes this a sink is the shape of the assignment
# rather than any name it mentions. Kept apart from ASSIGNMENT_SINKS for
# that reason — those match a property name, this one matches a hole.
PROTOTYPE_SINK = JsSink(
    id="sink.js.prototype",
    names=(),
    impact=Severity.HIGH,
    description="Pollution de prototype : clé d'affectation contrôlée",
)

# Names that, mentioned in a statement, mean the author already thought about
# this. A merge loop that refuses `__proto__` by name is fixed; reporting it
# anyway is how a scanner teaches people to stop reading its output.
PROTOTYPE_GUARDS: tuple[str, ...] = ("__proto__", "constructor", "prototype")

SOURCES: tuple[JsSource, ...] = (
    JsSource(
        id="source.js.request",
        patterns=("req.query", "req.body", "req.params", "req.headers",
                  "req.cookies", "req.url", "request.query", "request.body",
                  "request.params", "ctx.query", "ctx.params",
                  "ctx.request.body"),
        description="Requête HTTP entrante",
        remote=True,
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
        remote=True,
    ),
    JsSource(
        id="source.js.network",
        # A remote service is not an attacker, but it is not this program
        # either: a value it returns has crossed a boundary, and the audit
        # question — could a command be built from it — has the same answer
        # as for a request parameter.
        patterns=("fetch", "axios"),
        description="Réponse d'un service distant",
        remote=True,
    ),
    JsSource(
        id="source.js.message",
        patterns=("event.data", "message.data", "msg.data", "e.data"),
        description="Message reçu d'une autre origine",
        remote=True,
    ),
)

CALLBACK_SOURCES: tuple[JsCallbackSource, ...] = (
    JsCallbackSource(
        id="source.js.event",
        names=("addEventListener",),
        description="Événement reçu par la page",
    ),
)

# Methods that hand the callback whatever the receiver already holds. These
# carry taint, they do not introduce it: `list.map(f)` taints `f`'s parameter
# only when `list` is tainted. That difference is the whole distance between
# following a value and inventing one.
CARRIER_METHODS: frozenset[str] = frozenset({
    "then", "map", "forEach", "filter", "find", "flatMap", "some", "every",
})

# Sinks whose seriousness depends on how far the value travelled — the same
# list, and the same reasoning, as `codemap.catalog.TRAVEL_SENSITIVE`. Kept
# here rather than imported so the two languages' catalogues stay
# independent, which is the whole premise of this file.
TRAVEL_SENSITIVE: frozenset[str] = frozenset({"sink.js.path"})

_ONE_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


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


def bindings(clause: str) -> list[tuple[str, str]]:
    """`{ a, b as c }` -> [("a", "a"), ("b", "c")] — (exported, local)."""
    pairs = []
    for piece in clause.split(","):
        piece = piece.strip()
        if not piece or piece.startswith("type "):
            continue
        if " as " in piece:
            exported, _, local = piece.partition(" as ")
            pairs.append((exported.strip(), local.strip()))
        else:
            pairs.append((piece, piece))
    return [(a, b) for a, b in pairs if a.isidentifier() and b.isidentifier()]


# A named import or a destructuring require, from any specifier. The relative
# form the crossing pass needs is a narrowing of this one, not a different
# shape.
_CLAUSE = re.compile(
    r"""import\s*(?:type\s+)?\{(?P<clause>[^}]*)\}\s*from\s*['"](?P<spec>[^'"]+)['"]"""
    r"""|(?:const|let|var)\s*\{(?P<clause2>[^}]*)\}\s*=\s*require\s*\(\s*"""
    r"""['"](?P<spec2>[^'"]+)['"]\s*\)"""
)


def binds(source: str, module: str, name: str) -> bool:
    """Whether this file binds `name`, locally, from `module`.

    `imports` asks whether the module appears at all, which is the question
    a `needs` rule wants. It is too coarse for a rule that matches a bare
    name: `wsl-clipboard-image.ts` imports `child_process`, binds only
    `execFileSync` from it, and calls a destructured parameter named `exec`
    that opens no shell. The module is there; the name is somebody else's.

    Raw source again, for the reason `imports` gives. A namespace import —
    `import * as cp from "child_process"` — binds no plain name and answers
    False; the call it enables is `cp.exec(`, which a bare-name rule does
    not match either.
    """
    wanted = (module, f"node:{module}")
    for match in _CLAUSE.finditer(source):
        clause = match.group("clause") or match.group("clause2") or ""
        specifier = match.group("spec") or match.group("spec2") or ""
        if specifier not in wanted:
            continue
        if any(local == name for _, local in bindings(clause)):
            return True
    return False


@dataclass(frozen=True)
class JsCatalog:
    """What counts as dangerous here, built-ins plus whatever the repo adds.

    The built-in rules know Node and the browser. They cannot know the
    `runShell` your team wrote, the queue your service consumes, or the
    escaper that makes a value safe in your codebase — and without somewhere
    to say so, every audit of a real system is wrong in the same places.
    """

    sinks: tuple[JsSink, ...] = SINKS
    assignment_sinks: tuple[JsSink, ...] = ASSIGNMENT_SINKS
    prototype_sink: JsSink = PROTOTYPE_SINK
    sources: tuple[JsSource, ...] = SOURCES
    callback_sources: tuple[JsCallbackSource, ...] = CALLBACK_SOURCES
    carriers: frozenset[str] = CARRIER_METHODS
    sanitizers: frozenset[str] = SANITIZERS

    def source(self, rule_id: str):
        """A source rule by id, callbacks included: `addEventListener` is a
        source, and a finding that starts there has to be rankable too."""
        for rule in self.sources:
            if rule.id == rule_id:
                return rule
        for rule in self.callback_sources:
            if rule.id == rule_id:
                return rule
        return None

    def impact_for(self, sink: JsSink, source_id: str = "") -> Severity:
        """A sink's impact, given where the value came from.

        Unknown provenance counts as local, exactly as on the Python side:
        assuming remote would put every unattributed file path back at the
        top of the report, and `--all` still shows what the discount hides.
        """
        if sink.id not in TRAVEL_SENSITIVE:
            return sink.impact
        found = self.source(source_id) if source_id else None
        return sink.impact if (found is not None and found.remote) \
            else _ONE_DOWN[sink.impact]

    def merged(
        self,
        *,
        sinks: tuple[JsSink, ...] = (),
        sources: tuple[JsSource, ...] = (),
        callback_sources: tuple[JsCallbackSource, ...] = (),
        carriers: frozenset[str] = frozenset(),
        sanitizers: frozenset[str] = frozenset(),
    ) -> "JsCatalog":
        """Add rules, replacing built-ins that share an id.

        Replacing rather than appending is what lets a team downgrade a sink
        they have deliberately accepted, instead of only ever adding noise.
        """
        def fold(base, extra):
            by_id = {rule.id: rule for rule in base}
            for rule in extra:
                by_id[rule.id] = rule
            return tuple(by_id.values())

        return replace(
            self,
            sinks=fold(self.sinks, sinks),
            sources=fold(self.sources, sources),
            callback_sources=fold(self.callback_sources, callback_sources),
            carriers=self.carriers | carriers,
            sanitizers=self.sanitizers | sanitizers,
        )


DEFAULT_JS_CATALOG = JsCatalog()
_ACTIVE = DEFAULT_JS_CATALOG


def active() -> JsCatalog:
    return _ACTIVE


@contextmanager
def using(catalog: JsCatalog):
    """Install a catalog for the duration of a block, then restore it.

    Scoped rather than assigned, so one repository's rules can never leak
    into the next analysis in the same process.
    """
    global _ACTIVE
    previous = _ACTIVE
    _ACTIVE = catalog
    try:
        yield catalog
    finally:
        _ACTIVE = previous
