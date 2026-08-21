"""Declarative catalog of dangerous sinks and untrusted sources."""

from __future__ import annotations

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


@dataclass(frozen=True)
class SourceRule:
    id: str
    patterns: tuple[str, ...]
    description: str


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
        patterns=("eval", "exec", "compile"),
        impact=Severity.CRITICAL,
        description="Évaluation de code arbitraire",
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
    ),
    SourceRule(
        id="source.stdin",
        patterns=("input", "sys.stdin.read", "sys.stdin.readline"),
        description="Entrée standard",
    ),
    SourceRule(
        id="source.http",
        patterns=("request.args", "request.form", "request.json", "request.data",
                  "request.values", "request.get_json"),
        description="Requête HTTP entrante",
    ),
)


def _matches(call_name: str, patterns: tuple[str, ...]) -> bool:
    """Match a call against a pattern.

    A qualified pattern (`os.system`) matches the exact name, any name ending
    in it (`a.b.os.system`), or the bare last segment (`from os import system`).
    A bare pattern (`execute`) matches the name itself or any attribute call
    ending in it (`cursor.execute`, `self.conn.execute`) — that is the only way
    to catch DB-API and ORM methods, whose receiver is never statically known.
    """
    for pattern in patterns:
        if call_name == pattern:
            return True
        if call_name.endswith("." + pattern):
            return True
        if "." in pattern and call_name == pattern.rsplit(".", 1)[-1]:
            return True
    return False


def match_sink(call_name: str) -> SinkRule | None:
    for rule in DEFAULT_SINKS:
        if _matches(call_name, rule.patterns):
            return rule
    return None


def match_source(expression: str) -> SourceRule | None:
    for rule in DEFAULT_SOURCES:
        if _matches(expression, rule.patterns):
            return rule
    return None


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
    if call_name in SANITIZERS:
        return True
    return call_name.rsplit(".", 1)[-1] in SANITIZERS
