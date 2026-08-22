"""Declarative catalog of dangerous sinks and untrusted sources."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from thot.contracts import Severity


@dataclass(frozen=True)
class SinkRule:
    """A dangerous call.

    `dangerous_args` lists the positional argument indices whose taint actually
    matters. For `cursor.execute(query, params)` only index 0 is dangerous:
    values passed through index 1 are bound parameters, which is the safe form.
    An empty tuple means every argument counts.
    """

    id: str
    patterns: tuple[str, ...]
    impact: Severity
    description: str
    dangerous_args: tuple[int, ...] = (0,)
    match_mode: str = "qualified"


@dataclass(frozen=True)
class EntrySourceRule:
    """A function whose *parameters* are untrusted, because of who calls it.

    Sources are expressions — `sys.argv`, `os.environ`. That covers a program
    someone runs and misses a program something calls: an agent tool receives
    its untrusted input as named parameters, filled by a registry from what a
    model asked for, and no expression appears anywhere in the body.

    Measured cost of not having this: four SSRF vulnerabilities in one
    afternoon, every one of them reached through a tool argument, none of
    them found by taint. They were found by pattern rules, which recognise a
    shape and prove nothing.

    Empty by default. Which functions a registry calls is a fact about a
    codebase, and guessing it would put a source under every parameter in
    every program.
    """

    id: str
    patterns: tuple[str, ...]
    description: str
    match_mode: str = "prefix"
    # Which parameters arrive from outside. Empty means all of them, which
    # is right for a handler and wrong for a helper that happens to live in
    # the same package: `base_url` is configuration, and a rule naming a
    # whole package would taint it. Naming the parameter is what makes the
    # rule about a convention — `args` filled from what a model asked for —
    # rather than about a directory.
    parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceRule:
    id: str
    patterns: tuple[str, ...]
    description: str
    match_mode: str = "qualified"


DEFAULT_SINKS: tuple[SinkRule, ...] = (
    SinkRule(
        id="sink.os.system",
        patterns=("os.system", "os.popen"),
        impact=Severity.CRITICAL,
        description="Exécution d'une commande shell",
    ),
    SinkRule(
        id="sink.subprocess.shell",
        patterns=("subprocess.run", "subprocess.call", "subprocess.Popen",
                  "subprocess.check_output", "subprocess.check_call"),
        impact=Severity.CRITICAL,
        description="Lancement d'un sous-processus",
    ),
    SinkRule(
        id="sink.eval",
        patterns=("eval", "exec"),
        impact=Severity.CRITICAL,
        description="Évaluation de code arbitraire",
        match_mode="bare",
    ),
    SinkRule(
        id="sink.deserialization",
        patterns=("pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
                  "dill.loads"),
        impact=Severity.CRITICAL,
        description="Désérialisation de données non fiables",
    ),
    SinkRule(
        id="sink.sql",
        patterns=("execute", "executemany", "executescript"),
        impact=Severity.HIGH,
        description="Exécution d'une requête SQL",
        match_mode="method",
    ),
    SinkRule(
        id="sink.fs.write",
        patterns=("shutil.copy", "shutil.move", "os.remove", "os.unlink",
                  "shutil.rmtree"),
        impact=Severity.MEDIUM,
        description="Accès au système de fichiers",
    ),
    SinkRule(
        id="sink.network",
        patterns=("requests.get", "requests.post", "urllib.request.urlopen",
                  "httpx.get", "httpx.post"),
        impact=Severity.MEDIUM,
        description="Requête réseau sortante",
        dangerous_args=(),
    ),
)

DEFAULT_SOURCES: tuple[SourceRule, ...] = (
    SourceRule(
        id="source.argv",
        patterns=("sys.argv",),
        description="Arguments de ligne de commande",
    ),
    SourceRule(
        id="source.environ",
        patterns=("os.environ", "os.getenv"),
        description="Variables d'environnement",
        match_mode="prefix",
    ),
    SourceRule(
        id="source.stdin",
        patterns=("input", "sys.stdin.read", "sys.stdin.readline"),
        description="Entrée standard",
    ),
    SourceRule(
        id="source.http",
        patterns=("request.args", "request.form", "request.json", "request.data",
                  "request.values", "request.get_json", "request.cookies",
                  "request.headers", "request.files", "request.query_params",
                  "request.body", "request.POST", "request.GET"),
        description="Requête HTTP entrante",
        match_mode="prefix",
    ),
)


@dataclass(frozen=True)
class Catalog:
    """Everything the taint engine knows about dangerous code.

    Held as a value rather than module constants so a repository can extend it
    without patching Thot. The built-in rules cover the standard library; only
    the team knows its own shell wrapper and its own validators.
    """

    sinks: tuple[SinkRule, ...]
    sources: tuple[SourceRule, ...]
    sanitizers: frozenset[str]
    entry_sources: tuple[EntrySourceRule, ...] = ()

    def match_sink(self, call_name: str) -> SinkRule | None:
        for rule in self.sinks:
            if _matches(call_name, rule.patterns, rule.match_mode):
                return rule
        return None

    def match_entry(self, symbol_name: str) -> EntrySourceRule | None:
        """Whether this function's parameters arrive from somewhere untrusted."""
        for rule in self.entry_sources:
            if _matches(symbol_name, rule.patterns, rule.match_mode):
                return rule
        return None

    def match_source(self, expression: str) -> SourceRule | None:
        for rule in self.sources:
            if _matches(expression, rule.patterns, rule.match_mode):
                return rule
        return None

    def is_sanitizer(self, call_name: str) -> bool:
        if call_name in self.sanitizers:
            return True
        return call_name.rsplit(".", 1)[-1] in self.sanitizers


def _matches(call_name: str, patterns: tuple[str, ...], mode: str = "qualified") -> bool:
    """Match a call name against a rule's patterns.

    Three modes, because one rule fits none of them:

    - ``qualified`` — the module path must be there: ``requests.get`` matches
      itself and ``a.b.requests.get``, but never a bare ``get``. Matching the
      last segment alone would turn every ``payload.get(...)`` in a codebase
      into a network call, which is by far the largest source of noise.
    - ``method`` — the receiver is never statically known, so any
      ``<something>.execute`` counts. Required for DB-API and ORM calls.
    - ``bare`` — builtins only: ``eval`` matches, ``obj.eval`` does not.
    - ``prefix`` — the pattern names a tainted *object*, so anything read off
      it is tainted too: ``request.args`` covers ``request.args.get`` and
      ``request.args.getlist``. Untrusted input is almost never read as a bare
      attribute, so without this the HTTP sources match nothing real.
    """
    for pattern in patterns:
        if call_name == pattern:
            return True
        if mode in {"qualified", "prefix"} and call_name.endswith("." + pattern):
            return True
        if mode == "method" and call_name.rsplit(".", 1)[-1] == pattern:
            return True
        if mode == "prefix":
            if call_name.startswith(pattern + "."):
                return True
            if "." + pattern + "." in call_name:
                return True
    return False


def match_sink(call_name: str) -> SinkRule | None:
    return active().match_sink(call_name)


def match_source(expression: str) -> SourceRule | None:
    return active().match_source(expression)


def match_entry(symbol_name: str) -> EntrySourceRule | None:
    return active().match_entry(symbol_name)


# Calls that neutralise untrusted data. A tainted value passing through one of
# these stops being tainted — this is what separates a usable tool from a
# scanner that flags every escaped string.
SANITIZERS: frozenset[str] = frozenset(
    {
        "int", "float", "bool", "len", "abs", "round",
        "shlex.quote", "quote", "quote_plus",
        "os.path.basename", "basename",
        "html.escape", "escape", "re.escape",
        "urllib.parse.quote", "secure_filename",
        "uuid.UUID", "json.dumps",
    }
)


def is_sanitizer(call_name: str) -> bool:
    """True when a call breaks the taint chain."""
    return active().is_sanitizer(call_name)


DEFAULT_CATALOG = Catalog(
    sinks=DEFAULT_SINKS, sources=DEFAULT_SOURCES, sanitizers=SANITIZERS
)

# The catalog in force for the current analysis. Global because the taint
# engine reads it from a dozen places and threading it through every one of
# them would buy nothing: an audit analyses one repository at a time.
_ACTIVE: Catalog = DEFAULT_CATALOG


def active() -> Catalog:
    return _ACTIVE


@contextmanager
def using(catalog: Catalog):
    """Install a catalog for the duration of a block, then restore it.

    Scoped rather than assigned, so a custom catalog can never leak from one
    analysis into the next — or from one test into another.
    """
    global _ACTIVE
    previous = _ACTIVE
    _ACTIVE = catalog
    try:
        yield catalog
    finally:
        _ACTIVE = previous
