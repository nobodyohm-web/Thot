"""The scope manifest: what will be audited, and how it is run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScopeManifest:
    root: Path
    #: Source the AST indexers and the taint engine read.
    files: tuple[str, ...]
    languages: dict[str, int]
    entrypoints: tuple[str, ...]
    test_command: str | None = None
    #: Files the pattern sweep reads and nothing else does — workflows,
    #: compose files, shell scripts, `.env`, private keys. They carry
    #: credentials and CI injections, and no indexer will ever parse them,
    #: so keeping them in `files` would hand them to a parser that cannot
    #: read them and count them as code that they are not.
    extra_files: tuple[str, ...] = ()

    @property
    def swept(self) -> tuple[str, ...]:
        """Everything the pattern rules should be offered, in one list."""
        return self.files + self.extra_files
