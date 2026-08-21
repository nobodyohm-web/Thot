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
        material = "|".join(
            [rule, location.path, location.symbol or "", location.ast_hash or ""]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]
