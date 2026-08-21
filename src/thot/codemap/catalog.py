"""Declarative catalog of dangerous sinks and untrusted sources."""

from __future__ import annotations

from dataclasses import dataclass

from thot.contracts import Severity


@dataclass(frozen=True)
class SinkRule:
    id: str
    patterns: tuple[str, ...]
    impact: Severity
    description: str


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
    short = call_name.rsplit(".", 1)[-1]
    for pattern in patterns:
        if call_name == pattern:
            return True
        if pattern.rsplit(".", 1)[-1] == short and "." not in call_name:
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
