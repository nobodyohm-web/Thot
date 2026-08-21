"""The indexer protocol every language backend implements."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from thot.contracts import Symbol


class Indexer(Protocol):
    """Turns one source file into a flat list of symbols."""

    language: str

    def index_file(self, root: Path, relative: str) -> list[Symbol]: ...
