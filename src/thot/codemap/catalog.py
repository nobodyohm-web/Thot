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
    # Modules the file must import for this rule to mean anything. Only a
    # rule matching a bare method name needs it: `execute` belongs to a
    # database cursor, an LLM relay, a pipeline and a console engine alike,
    # and the JavaScript catalog has gated its own bare names this way from
    # the start.
    needs: tuple[str, ...] = ()


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
    # Whether somebody who is not running this process can choose the value.
    # The command line, the environment and stdin all belong to whoever
    # started the program; a request does not.
    remote: bool = False


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
        id="sink.xss",
        # The escape hatches, and only the escape hatches. Every one of these
        # exists to tell a template engine "this string is already safe, do
        # not escape it" — which is exactly the sentence that is false when
        # the string came from a request.
        #
        # `HttpResponse` and `render` are deliberately absent: returning a
        # value through them is what a view *does*, and Django escapes it on
        # the way out. Measured, the safe half of this category reaches the
        # same `HttpResponse` through `Template(...).render(...)` or after
        # `html.escape`, so a rule on the response would have fired on all
        # three hundred cases and separated nothing.
        patterns=("mark_safe", "django.utils.safestring.mark_safe",
                  "format_html", "Markup", "markupsafe.Markup",
                  "flask.Markup", "jinja2.Markup",
                  # And one that is not an escape hatch but a declaration.
                  # `HTMLResponse` is not `HttpResponse`: Django's escapes on
                  # the way out, which is why returning a value through it is
                  # what a view does and why it stays absent from this list.
                  # Starlette's sets the content type to HTML and escapes
                  # nothing, so a body built by concatenation is the bug
                  # itself.
                  "HTMLResponse", "starlette.responses.HTMLResponse",
                  "fastapi.responses.HTMLResponse"),
        impact=Severity.HIGH,
        description="HTML rendu sans échappement",
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
        # The price, measured on Hermes: a connection handed to a file that
        # imports no driver goes unseen — one production site out of 110
        # candidates, against 28 that were never SQL at all.
        #
        # That price turned out to be far higher than Hermes showed. Against
        # 100 labelled SQL-injection cases whose sink was `db.execute` behind
        # `from app_runtime import db`, the import gate scored 0/100: hiding
        # the driver behind a local wrapper is the normal shape, not the
        # exception. `sql:text` is the way back in — the file writes a query
        # out in full, which says SQL is being composed here more directly
        # than any import does. See `taint/engine.py::_file_gates`.
        needs=("sql:text",
               "sqlite3", "aiosqlite", "psycopg", "psycopg2", "pymysql",
               "MySQLdb", "mysql", "mariadb", "sqlalchemy", "asyncpg",
               "duckdb", "oracledb", "cx_Oracle", "pyodbc", "django",
               "peewee", "tortoise", "databases", "sqlmodel"),
    ),
    SinkRule(
        id="sink.fs.write",
        patterns=("shutil.copy", "shutil.move", "os.remove", "os.unlink",
                  "shutil.rmtree"),
        impact=Severity.MEDIUM,
        description="Accès au système de fichiers",
        # Same profile as `sink.network` below and the same cause — read its
        # note. 68 refutations, qualified patterns, and the taint arriving
        # through a parameter. Worth its noise all the same: this is the rule
        # whose candidate the panel confirmed into a real path traversal, a
        # tree entry named `..` reaching `shutil.rmtree` in Hermes.
    ),
    SinkRule(
        id="sink.fs.read",
        # `open` and the four ways to ask what is in a directory. Same
        # weakness — the caller chooses the path and gets back what is
        # there — and `os.listdir` was missing: 150 cases in the corpus
        # write it, all on the vulnerable half, and no safe case anywhere
        # writes it at all. Worth +0,0000 there, because BenchProctor
        # labels those cases CWE-209, which is an error message and not a
        # directory. The sink is real regardless of what the corpus calls it.
        patterns=("open", "os.listdir", "os.scandir", "os.walk",
                  "glob.glob", "glob.iglob"),
        # MEDIUM as written, and discounted by `impact_for` when the path
        # never left the machine — see TRAVEL_SENSITIVE below. This rule
        # spent a while pinned at LOW instead, because a candidate did not
        # record which source rule started it and the two cases could not be
        # told apart. They can now.
        impact=Severity.MEDIUM,
        description="Ouverture d'un fichier par chemin",
        match_mode="bare",
        # Path traversal — CWE-22 — went past this catalogue entirely:
        # `sink.fs.write` knows `shutil.move` and `os.remove`, and nothing
        # knew `open`. Measured on a corpus of eleven vulnerability classes,
        # seven were caught and this was one of the four that were not.
        #
        # The price, measured before adding it: zero further candidates on
        # Thot (14), on Prime (25) and on Hermes (401 → 401). It fires only
        # where a tainted value reaches the call, which none of the three
        # trees does — and it turns three of the corpus's pattern-only hits
        # into proven taint paths (pickle, `yaml.load`, `with open(...) as`),
        # since the file being opened was already the vector.
        #
        # `bare`, because it is a builtin: qualifying it would miss every
        # ordinary call, and `connexion.open` is not this function.
    ),
    SinkRule(
        id="sink.network",
        patterns=("requests.get", "requests.post", "urllib.request.urlopen",
                  "httpx.get", "httpx.post",
                  # Added only once the host-allow-list and resolved-range
                  # guards were recognised, and the order was not a
                  # preference: measured, this pattern *alone* took `ssrf`
                  # from 44 true positives against 56 false ones to 97
                  # against 108 — more right answers and a worse rule, J
                  # still negative. With the guards in place the same line
                  # gives 97 against 0.
                  "socket.create_connection"),
        impact=Severity.MEDIUM,
        description="Requête réseau sortante",
        dangerous_args=(),
        # Measured and deliberately left alone. This rule produced 143
        # candidates on Hermes and 149 refutations across the three trees,
        # against no confirmation ever — the same shape that made `sink.sql`
        # worth gating. It is not the same cause. Its patterns are already
        # qualified, and the taint does not come from a misread name: it
        # comes from the enclosing function's own parameter, which the
        # engine holds untrusted until a caller proves otherwise. In a
        # codebase where every HTTP helper takes a URL parameter, that is
        # every helper. A `needs` gate would buy nothing here; what would is
        # knowing which entry points actually reach those parameters, which
        # is the call graph's job and not this catalog's.
    ),
    SinkRule(
        id="sink.log",
        # CWE-117, and the same forgery as CWE-93 against a different
        # reader: both a header and a log line end at a newline, so a value
        # carrying one writes a record the author did not.
        patterns=("info", "warning", "warn", "error", "debug", "critical",
                  "exception"),
        impact=Severity.MEDIUM,
        description="Écriture non neutralisée dans un journal",
        # The level names are ordinary English words — `response.error`,
        # `parser.info` — so the import is the gate, exactly as `sql:text`
        # gates `sink.sql`. A file that imports a logging library and calls
        # `.warning(...)` is logging.
        match_mode="method",
        # The message, and only the message. `logger.info('failed: %s', exc)`
        # hands the value to the logging machinery instead of writing it into
        # the string the author wrote, and reading those arguments too is
        # measured at +0.0000 on the corpus and 4 844 further findings on
        # hermes — every `except Exception as exc: log.error('...', exc)` in
        # the tree. What is not covered is stated rather than hidden.
        dangerous_args=(0,),
        needs=("logging", "structlog", "loguru"),
    ),
    SinkRule(
        id="sink.redirect",
        # Where the *user's browser* is sent, which is a different question
        # from where a request goes. `redirect` is Django's and Flask's;
        # `RedirectResponse` is FastAPI's and takes its target by keyword;
        # `HttpResponseRedirect` is the class Django's shortcut wraps.
        #
        # `url_for` is deliberately absent: it names a route by symbol and
        # builds the URL itself, so a tainted argument reaching it lands in
        # a query string, not in the host.
        patterns=("redirect", "RedirectResponse", "HttpResponseRedirect"),
        impact=Severity.MEDIUM,
        description="Redirection vers une destination non validée",
        match_mode="bare",
        # Every argument, not just the first: FastAPI spells the destination
        # `url=` and Flask accepts `location=`, and the default of index 0
        # saw neither. What the extra arguments carry is `permanent=True` and
        # `status_code=302` — literals, which reference no name and cost
        # nothing to consider.
        dangerous_args=(),
        # `redirect` is a bare name a great many programs use for something
        # else. Gated the way `execute` is, on the frameworks that own these
        # three spellings — `werkzeug` because Flask's redirect lives there,
        # `starlette` because FastAPI's response class does.
        needs=("django", "flask", "werkzeug", "fastapi", "starlette"),
    ),
    SinkRule(
        id="sink.template",
        # The template *source*, never the context. `Template('{{ v }}')`
        # compiles a constant and hands the value to an engine that escapes
        # it — which is what the safe half of the `xss` category does, ten
        # cases of it, so a rule on the call instead of on its first argument
        # would have fired on every one of them and separated nothing.
        #
        # `from_string` is deliberately absent for the same reason it would
        # have been cheap to add: all seventeen of its appearances in the
        # corpus are in cases labelled safe. A pattern that can only lose is
        # not worth the line.
        patterns=("Template", "render_template_string"),
        impact=Severity.CRITICAL,
        description="Modèle rendu depuis une source non fiable",
        match_mode="bare",
        needs=("django", "flask", "jinja2"),
    ),
    SinkRule(
        id="sink.xpath",
        patterns=("xpath",),
        impact=Severity.HIGH,
        description="Expression XPath composée avec une valeur non fiable",
        match_mode="method",
        needs=("lxml", "xml"),
    ),
    SinkRule(
        id="sink.ldap",
        patterns=("search_s", "search_st", "search_ext_s"),
        impact=Severity.HIGH,
        description="Filtre LDAP composé avec une valeur non fiable",
        match_mode="method",
        # The filter, third. A search base is chosen by the application, and
        # counting it would double the rule's surface for nothing.
        dangerous_args=(2,),
        needs=("ldap", "ldap3"),
    ),
    SinkRule(
        id="sink.nosql",
        patterns=("find", "find_one", "find_one_and_update", "update_one",
                  "update_many", "delete_one", "delete_many", "count_documents",
                  "aggregate", "distinct"),
        impact=Severity.HIGH,
        description="Requête NoSQL composée avec une valeur non fiable",
        match_mode="method",
        # `mongo:text` first, and it is what makes the rule possible at all.
        # `find` belongs to every string and list in Python, and the driver
        # is not imported where the query is written — `from app_runtime
        # import mongo_db` is the ordinary shape, the same one that scored
        # the `execute` import gate 0/100. A quoted query operator is
        # written by nothing but a Mongo query.
        needs=("mongo:text", "pymongo", "motor", "mongoengine", "bson"),
    ),
    # The next two carry no patterns and never will: they are recognised by
    # *position*, not by the name of a call. A response header is written as
    # `Response(..., headers={...})` in Django and FastAPI and as the third
    # element of a returned tuple in Flask, and in both the key names the
    # header while the value is the thing that must not be attacker-chosen.
    # `taint/engine.py::_header_targets` finds them; these entries exist so
    # the finding has an impact and a sentence like every other.
    SinkRule(
        id="sink.header",
        patterns=(),
        impact=Severity.MEDIUM,
        description="En-tête de réponse composé avec une valeur non fiable",
    ),
    SinkRule(
        id="sink.cors",
        patterns=(),
        impact=Severity.MEDIUM,
        description="Origine CORS reflétée depuis la requête",
    ),
    # Recognised by position too: what makes a cell dangerous is that a
    # spreadsheet evaluates it, so the rule is about the file being written,
    # not the method doing the writing. `.write` is among the most common
    # method names in Python and a rule on the name alone would fire on every
    # file a program opens.
    SinkRule(
        id="sink.csv",
        patterns=(),
        impact=Severity.MEDIUM,
        description="Cellule de tableur écrite depuis une valeur non fiable",
    ),
    # Also positional, and the name of the file is the whole rule. Writing a
    # request value to a file is what programs do; writing it to one called
    # `secrets.txt` is the finding.
    SinkRule(
        id="sink.cleartext",
        patterns=(),
        impact=Severity.HIGH,
        description="Donnée sensible écrite en clair",
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
                  # `get_data` and `stream` are how Werkzeug hands over a raw
                  # body, and `request.data` does not cover them: the prefix
                  # mode matches `request.data.something`, never a different
                  # method on the same object. 581 reads of it in the flask
                  # corpus went unseen for want of this line.
                  "request.get_data", "request.stream",
                  "request.values", "request.get_json", "request.cookies",
                  "request.headers", "request.files", "request.query_params",
                  "request.body", "request.POST", "request.GET",
                  # Django spells two of its own in capitals, and their
                  # absence did not hide the taint — `request` is a view's
                  # parameter, so everything read off it is untrusted anyway.
                  # What it hid was *which* rule started the path, and for a
                  # travel-sensitive sink that is the whole finding: with no
                  # source attributed, `impact_for` discounts `sink.fs.read`
                  # from medium to low, and low is under the floor a default
                  # report prints. The path was found and nobody saw it.
                  "request.META", "request.COOKIES", "request.FILES"),
        description="Requête HTTP entrante",
        match_mode="prefix",
        remote=True,
    ),
    SourceRule(
        id="source.response",
        patterns=("requests.get", "requests.post", "requests.put",
                  "requests.patch", "requests.delete", "requests.request",
                  "httpx.get", "httpx.post", "urllib.request.urlopen"),
        description="Réponse d'un service tiers",
        remote=True,
    ),
    SourceRule(
        id="source.stored",
        # The DB-API cursor and the `databases` package, which is what an
        # async framework uses. `first` and `scalar_one` were measured with
        # them and earned exactly nothing, so they are not here: `.first()`
        # is SQLAlchemy's idiom and also pandas', and a source rule that
        # cannot tell them apart is a source rule under every groupby.
        patterns=("fetch_one", "fetch_all", "fetch_val", "fetchone",
                  "fetchall", "fetchmany"),
        description="Lecture en base",
        match_mode="method",
        remote=True,
    ),
    SourceRule(
        id="source.orm",
        # The same fact through Django's ORM, which the corpus never writes
        # and half of Python's web code does. Measured at zero here and zero
        # on both shipped trees; it is in because a catalogue that knows
        # `fetchone` and not `objects.get` would be a catalogue about
        # BenchProctor. Qualified on `objects`, so `options.get` and every
        # other `.get` in the language stay what they are.
        patterns=("objects.get", "objects.filter", "objects.all",
                  "objects.values", "objects.values_list"),
        description="Lecture par l'ORM",
        remote=True,
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

    def source(self, rule_id: str) -> SourceRule | None:
        for rule in self.sources:
            if rule.id == rule_id:
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
        # `re.escape` and not `escape`: the bare name was here, and
        # `is_sanitizer` reads the last segment, so it collected
        # `html.escape`, `markupsafe.escape`, `cgi.escape` and
        # `flask.escape` along with it. All four turn five characters into
        # entities. None of them touches `;`, `|`, a backtick or `$(`, and
        # a sanitizer stops the walk outright — so `os.system('ping ' +
        # html.escape(host))` was silenced by a defence that does not
        # defend it. They are all in `HTML_SANITIZERS`, where the proof is
        # keyed to the one destination it covers.
        "re.escape",
        "urllib.parse.quote", "secure_filename",
        "uuid.UUID", "json.dumps",
    }
)


# Neutralisations that hold for HTML and for nothing else. `bleach.clean`
# strips tags and attributes; it leaves `x; rm -rf /` exactly as it found it,
# so treating it as a sanitizer everywhere would silence a shell for the
# benefit of a template. Kept apart and consulted only at `sink.xss` — the
# same reason a resolved-address range check clears an outgoing request and
# not an `os.system`.
HTML_SANITIZERS: frozenset[str] = frozenset(
    {
        "bleach.clean", "bleach.linkify", "nh3.clean",
        # The one in the standard library. `markupsafe.escape` and
        # `bleach.clean` were here and this was not, and it is what a program
        # with no dependency reaches for — 66 times in the corpus.
        "html.escape", "cgi.escape",
        "markupsafe.escape", "django.utils.html.escape",
        "django.utils.html.escapejs", "flask.escape",
        # `from markupsafe import escape` is how it is imported, and the
        # call site then reads `escape(value)` with nothing in front of it.
        "escape", "escapejs",
    }
)


def is_html_sanitizer(call_name: str) -> bool:
    """The last segment counts, exactly as it does for `is_sanitizer`.

    `from django.utils.html import escape` and `import html` are the same
    neutralisation written two ways, and matching only the qualified form
    recognised whichever one the file happened not to use.
    """
    if call_name in HTML_SANITIZERS:
        return True
    return call_name.rsplit(".", 1)[-1] in HTML_SANITIZERS


def is_sanitizer(call_name: str) -> bool:
    """True when a call breaks the taint chain."""
    return active().is_sanitizer(call_name)


# Sinks whose seriousness depends on how far the value travelled to reach
# them. Opening a path somebody named on the command line is the program
# doing what it was told: whoever supplies argv already holds this process's
# filesystem, and the call hands them nothing they did not have. The same
# call reached from a request is arbitrary file access.
#
# Only these. A command built from argv is still a command and a pickle read
# from an environment variable still runs code — the sink is the escalation
# there, not the path.
TRAVEL_SENSITIVE = frozenset({"sink.fs.read", "sink.fs.write", "sink.js.path"})

_ONE_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def impact_for(sink_id: str, source_id: str = "") -> Severity:
    """A sink's impact, given where the value came from.

    An unknown provenance is treated as local. The alternative — assume
    remote until proven otherwise — puts every unattributed file path back
    at the top of the report, which is the flood this exists to end. What it
    costs is stated rather than hidden: a travel-sensitive finding whose
    source the engine could not name is ranked one step low, and `--all`
    shows it.
    """
    base = Severity.MEDIUM
    for rule in active().sinks:
        if rule.id == sink_id:
            base = rule.impact
            break
    if sink_id not in TRAVEL_SENSITIVE:
        return base
    found = active().source(source_id) if source_id else None
    return base if (found is not None and found.remote) else _ONE_DOWN[base]


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
