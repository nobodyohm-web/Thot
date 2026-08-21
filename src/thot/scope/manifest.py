"""The scope manifest: what will be audited, and how it is run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScopeManifest:
    root: Path
    files: tuple[str, ...]
    languages: dict[str, int]
    entrypoints: tuple[str, ...]
    test_command: str | None = None
