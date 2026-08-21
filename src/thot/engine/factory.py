"""Pick the execution backend from what the machine actually has.

Order matters: the subscription paths come first because they cost the user
nothing beyond what they already pay for, and they parallelise. An API key is
the fallback, not the default.

Three of the four backends are agents driven through their own command line —
Claude Code, Hermes, Prime. Thot never imports them and never holds a token:
each one authenticates as itself, on the user's own account.
"""

from __future__ import annotations

import os
from pathlib import Path

from thot.engine.base import Engine
from thot.engine.claude_cli_engine import ClaudeCliEngine
from thot.engine.direct import DirectEngine
from thot.engine.hermes_engine import HermesEngine
from thot.engine.panel import PanelEngine
from thot.engine.prime_engine import PrimeEngine
from thot.llm.credentials import Config, build_provider, load_config

# The name a user types, and the class behind it. `claude` is the default
# because it is the only one that ships with Thot alone.
AGENT_ENGINES = {
    "claude": ClaudeCliEngine,
    "hermes": HermesEngine,
    "prime": PrimeEngine,
}

ENGINE_ENV = "THOT_ENGINE"

_MISSING = {
    "claude": (
        "Le CLI `claude` est introuvable.\n"
        "   Installe-le : npm install -g @anthropic-ai/claude-code"
    ),
    "hermes": (
        "Hermes est introuvable dans cette installation.\n"
        "   `uv sync` à la racine du dépôt, ou pointe THOT_HERMES_ROOT."
    ),
    "prime": (
        "Prime est introuvable ou non compilé.\n"
        "   cd prime && npm install && npm run build"
    ),
}


class NoEngine(RuntimeError):
    """No backend is reachable — say why, in terms the user can act on."""


def available_engines() -> list[str]:
    """The agent backends this machine can actually run, in preference order."""
    return [name for name, engine in AGENT_ENGINES.items() if engine.available()]


def build_panel(
    root: Path, names: list[str] | None = None, *, max_parallel: int = 4
) -> PanelEngine:
    """Every installed agent on the same run, arguing against each other.

    The parallelism budget is shared rather than multiplied: `--parallel 6`
    across three agents means two apiece, not six each. What the panel buys
    is not more concurrency, it is a different agent attacking each scenario.
    """
    names = names or available_engines()
    if not names:
        raise NoEngine(
            "Aucun agent installé. `thot login`, ou installe Hermes ou Prime."
        )
    share = max(1, max_parallel // len(names))
    return PanelEngine(
        members=[
            AGENT_ENGINES[name](root=Path(root), max_parallel=share)
            for name in names
        ]
    )


def build_engine(
    root: Path,
    config: Config | None = None,
    *,
    max_parallel: int = 4,
    prefer: str = "",
) -> Engine:
    """The engine to argue findings with.

    With no preference and more than one agent installed, the answer is a
    panel of all of them — see `build_panel`. `prefer` names one explicitly
    — `thot audit --engine hermes`, or `--engine panel` to force the panel
    on a machine where you also gave a preference. Naming an
    engine that is not installed raises rather than quietly falling back: a
    run that silently used a different agent than the one asked for would
    make its verdicts unattributable, and verdicts are stored under the name
    of whoever decided them.
    """
    prefer = (prefer or os.environ.get(ENGINE_ENV, "")).strip().lower()

    if prefer == "panel":
        return build_panel(root, max_parallel=max_parallel)

    if prefer:
        if prefer not in AGENT_ENGINES:
            known = ", ".join(AGENT_ENGINES)
            raise NoEngine(f"Moteur inconnu : « {prefer} ». Connus : {known}.")
        engine = AGENT_ENGINES[prefer]
        if not engine.available():
            raise NoEngine(_MISSING[prefer])
        return engine(root=Path(root), max_parallel=max_parallel)

    # Nothing was named. When this machine has more than one agent, the run
    # uses all of them: that is the whole point of the three living in one
    # program. `--engine claude` (or THOT_ENGINE) opts back out to a single
    # backend when you want one voice and one bill.
    installed = available_engines()
    if len(installed) >= 2:
        return build_panel(root, installed, max_parallel=max_parallel)

    config = config or load_config()
    if config is None:
        raise NoEngine(
            "Aucun modèle connecté. Lance `thot login`, ou `thot audit` sans "
            "`--deep` pour l'analyse déterministe seule."
        )

    if config.provider == "claude-cli":
        if not ClaudeCliEngine.available():
            others = [name for name in ("hermes", "prime")
                      if AGENT_ENGINES[name].available()]
            hint = (
                f"\n   Ou passe par un agent déjà présent : --engine {others[0]}"
                if others else ""
            )
            raise NoEngine(
                "Le CLI `claude` est introuvable alors que Thot est configuré "
                "pour ton compte. Installe-le : "
                "npm install -g @anthropic-ai/claude-code" + hint
            )
        return ClaudeCliEngine(root=Path(root), max_parallel=max_parallel)

    return DirectEngine(provider=build_provider(config), max_parallel=max_parallel)
