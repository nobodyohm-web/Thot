"""Stable data contracts shared by every phase of the pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

SCHEMA_VERSION = 1


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    REFUTED = "refuted"


@dataclass(frozen=True)
class CodeRef:
    """A location in the audited repository. `path` is always repo-relative."""

    path: str
    line: int
    symbol: str | None = None
    ast_hash: str | None = None
    # Which dangerous call inside the symbol this is. Five `httpx.get` in one
    # function are five findings, and a verdict on one of them must not speak
    # for the other four. The line cannot play this role — identity has to
    # survive a line move — but a discriminator that is only unique within one
    # version of the body is enough, because `ast_hash` already expires every
    # verdict in the function the moment that body changes.
    site: str | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class Symbol:
    """A named, indexable unit of code (function, method, class)."""

    name: str
    path: str
    lineno: int
    end_lineno: int
    ast_hash: str
    kind: str
    calls: tuple[str, ...] = ()
    params: tuple[str, ...] = ()
    # Names this symbol *mentions* without calling: a handler put in a
    # dispatch table, a callback passed to a framework, a decorated view.
    # Not a call edge — but proof the target escaped, which is the
    # difference between "nobody reaches it" and "we cannot see who does".
    references: tuple[str, ...] = ()

    def to_ref(self) -> CodeRef:
        return CodeRef(
            path=self.path,
            line=self.lineno,
            symbol=self.name,
            ast_hash=self.ast_hash,
        )


@dataclass(frozen=True)
class Finding:
    """One audited defect. Identity is stable across line moves."""

    id: str
    rule: str
    severity: Severity
    confidence: Confidence
    location: CodeRef
    taint_path: tuple[CodeRef, ...] = ()
    failure_scenario: str = ""
    repro: object | None = None
    patch: object | None = None
    provenance: dict | None = None
    schema_version: int = SCHEMA_VERSION

    @staticmethod
    def compute_id(rule: str, location: CodeRef) -> str:
        """Stable identity: rule + file + symbol + body hash. Not the line."""
        parts = [rule, location.path, location.symbol or "", location.ast_hash or ""]
        if location.site:
            # Appended, never inserted: a location that cannot name its site
            # keeps the identity it has always had, so adding this did not
            # expire a single verdict already on disk.
            parts.append(location.site)
        material = "|".join(parts)
        return hashlib.sha256(material.encode()).hexdigest()[:16]
