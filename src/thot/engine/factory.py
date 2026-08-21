"""Pick the execution backend from what the machine actually has.

Order matters: the subscription path comes first because it costs the user
nothing beyond what they already pay for, and it parallelises. An API key is
the fallback, not the default.
"""

from __future__ import annotations

from pathlib import Path

from thot.engine.base import Engine
from thot.engine.claude_cli_engine import ClaudeCliEngine
from thot.engine.direct import DirectEngine
from thot.llm.credentials import Config, build_provider, load_config


class NoEngine(RuntimeError):
    """No backend is reachable — say why, in terms the user can act on."""


def build_engine(
    root: Path, config: Config | None = None, *, max_parallel: int = 4
) -> Engine:
    config = config or load_config()
    if config is None:
        raise NoEngine(
            "Aucun modèle connecté. Lance `thot login`, ou `thot audit` sans "
            "`--deep` pour l'analyse déterministe seule."
        )

    if config.provider == "claude-cli":
        if not ClaudeCliEngine.available():
            raise NoEngine(
                "Le CLI `claude` est introuvable alors que Thot est configuré "
                "pour ton compte. Installe-le : npm install -g @anthropic-ai/claude-code"
            )
        return ClaudeCliEngine(root=Path(root), max_parallel=max_parallel)

    return DirectEngine(provider=build_provider(config), max_parallel=max_parallel)
