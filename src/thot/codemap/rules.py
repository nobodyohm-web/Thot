"""Audit rules loaded from disk, merged over the built-in catalog.

The built-in rules know the Python standard library. They cannot know the
wrapper your team wrote around `subprocess`, the queue your service consumes,
or the validator that makes a value safe in your codebase. Without somewhere
to say so, every audit of a real system is wrong in the same three places, and
the only fix is to patch the tool.

Two locations, merged in order:

- ``~/.thot/rules/*.yaml`` — what you know, everywhere you work.
- ``<repo>/.thot/rules/*.yaml`` — what this codebase knows, committed with it.

The same files carry the JavaScript rules, under a ``js:`` key. Keeping them
in one file rather than two is deliberate: a team's shell wrapper usually
exists in both languages, and splitting the declaration is how one half goes
stale.

A rule reusing a built-in id replaces it rather than adding a duplicate, so a
team can downgrade a sink they have deliberately accepted.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from thot.codemap.catalog import (
    DEFAULT_CATALOG,
    Catalog,
    SinkRule,
    SourceRule,
)
from thot.contracts import Severity
from thot.errors import ThotError

RULES_DIRNAME = "rules"
MATCH_MODES = {"qualified", "method", "bare", "prefix"}


class RuleError(ThotError):
    """A rules file could not be understood. Always names the file."""


def user_rules_dir() -> Path:
    from thot.paths import user_dir as thot_user_dir

    return thot_user_dir(RULES_DIRNAME)


def _rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        [*directory.glob("*.yaml"), *directory.glob("*.yml")], key=lambda p: p.name
    )


def _load_document(path: Path) -> dict:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleError(f"{path.name} : illisible ({exc})") from exc
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name} : YAML invalide — {exc}") from exc
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise RuleError(f"{path.name} : la racine doit être un dictionnaire")
    return document


def _require(entry: dict, key: str, path: Path, kind: str) -> object:
    if key not in entry or entry[key] in (None, "", [], ()):
        raise RuleError(f"{path.name} : un {kind} n'a pas de `{key}`")
    return entry[key]


def _patterns(entry: dict, path: Path, kind: str) -> tuple[str, ...]:
    raw = _require(entry, "patterns", path, kind)
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise RuleError(f"{path.name} : `patterns` doit être une liste")
    return tuple(str(item) for item in raw)


def _match_mode(entry: dict, path: Path, default: str) -> str:
    mode = str(entry.get("match_mode", default))
    if mode not in MATCH_MODES:
        raise RuleError(
            f"{path.name} : `match_mode` inconnu « {mode} » "
            f"(attendu : {', '.join(sorted(MATCH_MODES))})"
        )
    return mode


def _severity(entry: dict, path: Path) -> Severity:
    raw = str(_require(entry, "impact", path, "sink")).lower()
    try:
        return Severity(raw)
    except ValueError as exc:
        allowed = ", ".join(s.value for s in Severity)
        raise RuleError(
            f"{path.name} : `impact` inconnu « {raw} » (attendu : {allowed})"
        ) from exc


def _sink(entry: dict, path: Path) -> SinkRule:
    identifier = str(_require(entry, "id", path, "sink"))
    args = entry.get("dangerous_args", (0,))
    if isinstance(args, int):
        args = (args,)
    return SinkRule(
        id=identifier,
        patterns=_patterns(entry, path, "sink"),
        impact=_severity(entry, path),
        description=str(entry.get("description", identifier)),
        dangerous_args=tuple(int(a) for a in args),
        match_mode=_match_mode(entry, path, "qualified"),
    )


def _source(entry: dict, path: Path) -> SourceRule:
    identifier = str(_require(entry, "id", path, "source"))
    return SourceRule(
        id=identifier,
        patterns=_patterns(entry, path, "source"),
        description=str(entry.get("description", identifier)),
        match_mode=_match_mode(entry, path, "qualified"),
    )


def _entries(document: dict, key: str, path: Path) -> list[dict]:
    raw = document.get(key) or []
    if not isinstance(raw, list):
        raise RuleError(f"{path.name} : `{key}` doit être une liste")
    for entry in raw:
        if not isinstance(entry, dict):
            raise RuleError(f"{path.name} : chaque entrée de `{key}` est un dictionnaire")
    return raw


def load_catalog(root: Path, *, user_dir: Path | None = None) -> Catalog:
    """The built-in catalog extended by whatever the user and repo declare."""
    directories = [
        user_dir if user_dir is not None else user_rules_dir(),
        Path(root) / ".thot" / RULES_DIRNAME,
    ]

    sinks = {rule.id: rule for rule in DEFAULT_CATALOG.sinks}
    sources = {rule.id: rule for rule in DEFAULT_CATALOG.sources}
    sanitizers = set(DEFAULT_CATALOG.sanitizers)

    for directory in directories:
        for path in _rule_files(directory):
            document = _load_document(path)
            for entry in _entries(document, "sinks", path):
                rule = _sink(entry, path)
                sinks[rule.id] = rule
            for entry in _entries(document, "sources", path):
                rule = _source(entry, path)
                sources[rule.id] = rule
            extra = document.get("sanitizers") or []
            if not isinstance(extra, list):
                raise RuleError(f"{path.name} : `sanitizers` doit être une liste")
            sanitizers.update(str(item) for item in extra)

    return Catalog(
        sinks=tuple(sinks.values()),
        sources=tuple(sources.values()),
        sanitizers=frozenset(sanitizers),
    )


# -- the same files, for the JavaScript engine -------------------------------


def _js_sink(entry: dict, path: Path):
    from thot.taint.js_catalog import JsSink

    identifier = str(_require(entry, "id", path, "sink js"))
    names = entry.get("names") or entry.get("patterns")
    if isinstance(names, str):
        names = [names]
    if not names:
        raise RuleError(f"{path.name} : un sink js n'a pas de `names`")
    needs = entry.get("needs") or ()
    if isinstance(needs, str):
        needs = [needs]
    args = entry.get("dangerous_args", (0,))
    if isinstance(args, int):
        args = (args,)
    return JsSink(
        id=identifier,
        names=tuple(str(n) for n in names),
        impact=_severity(entry, path),
        description=str(entry.get("description", identifier)),
        needs=tuple(str(n) for n in needs),
        dangerous_args=tuple(int(a) for a in args),
    )


def _js_source(entry: dict, path: Path):
    from thot.taint.js_catalog import JsSource

    identifier = str(_require(entry, "id", path, "source js"))
    return JsSource(
        id=identifier,
        patterns=_patterns(entry, path, "source js"),
        description=str(entry.get("description", identifier)),
    )


def load_js_catalog(root: Path, *, user_dir: Path | None = None):
    """The JavaScript catalog, built-ins plus what the repository declares."""
    from thot.taint.js_catalog import DEFAULT_JS_CATALOG

    catalog = DEFAULT_JS_CATALOG
    directories = [
        user_dir if user_dir is not None else user_rules_dir(),
        Path(root) / ".thot" / RULES_DIRNAME,
    ]
    for directory in directories:
        for file in _rule_files(directory):
            section = _load_document(file).get("js") or {}
            if not isinstance(section, dict):
                raise RuleError(f"{file.name} : `js` doit être un dictionnaire")
            sanitizers = section.get("sanitizers") or []
            if isinstance(sanitizers, str):
                sanitizers = [sanitizers]
            catalog = catalog.merged(
                sinks=tuple(
                    _js_sink(entry, file) for entry in _entries(section, "sinks", file)
                ),
                sources=tuple(
                    _js_source(entry, file)
                    for entry in _entries(section, "sources", file)
                ),
                sanitizers=frozenset(str(s) for s in sanitizers),
            )
    return catalog
