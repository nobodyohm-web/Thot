"""First run: pick a model, connect, done.

The screen is built around what is already on the machine. If a Claude
subscription or a local server is detected, pressing Enter is enough — no key
to paste, no URL to type. Everything else is one short prompt.
"""

from __future__ import annotations

import getpass

from rich.text import Text

from thot.llm.credentials import (
    Config,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_OPENAI_MODEL,
    Detected,
    detect,
    load_config,
    save_config,
)
from thot.llm.openai_compat import LMSTUDIO_BASE_URL, OLLAMA_BASE_URL
from thot.ui import theme


def ensure_configured() -> Config | None:
    """Return a usable config, running the first-run screen when needed."""
    config = load_config()
    if config:
        return config
    config = first_run()
    if config:
        save_config(config)
    return config


def _option(number: int, name: str, detail: str, *, highlight: bool) -> Text:
    line = Text("    ")
    if highlight:
        line.append(f" {number} ", style=f"bold #1c1c1c on {theme.ACCENT}")
    else:
        line.append(f" {number} ", style=f"bold {theme.INK}")
    line.append("  ")
    line.append(name.ljust(9), style="white" if highlight else theme.INK)
    line.append(detail, style=theme.INK)
    return line


def first_run() -> Config | None:
    theme.banner()
    theme.hint("Premier lancement. Un modèle à connecter.")
    theme.console.print()

    found = detect()
    default = _default_choice(found)

    theme.console.print(_option(1, "Claude", _claude_detail(found), highlight=default == 1))
    theme.console.print(_option(2, "OpenAI", _openai_detail(found), highlight=default == 2))
    theme.console.print(_option(3, "Local", _local_detail(found), highlight=default == 3))
    theme.console.print(_option(4, "Autre", "endpoint compatible OpenAI", highlight=False))
    theme.console.print()

    choice = _ask(f"[1-4]", default=str(default))
    theme.console.print()

    if choice == "1":
        return _setup_claude(found)
    if choice == "2":
        return _setup_openai(found)
    if choice == "3":
        return _setup_local(found)
    if choice == "4":
        return _setup_custom()
    return None


def _default_choice(found: Detected) -> int:
    # A detected Claude subscription is deliberately not the default: Anthropic
    # only accepts subscription tokens from its own clients, so it would fail
    # on the first message.
    if found.ollama or found.lmstudio:
        return 3
    if found.openai_key:
        return 2
    return 1


def _claude_detail(found: Detected) -> str:
    return "clé API (sk-ant-…)"


def _openai_detail(found: Detected) -> str:
    return "OPENAI_API_KEY détectée" if found.openai_key else "clé API"


def _local_detail(found: Detected) -> str:
    models = found.ollama or found.lmstudio
    if models:
        server = "Ollama" if found.ollama else "LM Studio"
        preview = ", ".join(models[:2])
        more = f" +{len(models) - 2}" if len(models) > 2 else ""
        return f"{server} — {preview}{more}"
    return "Ollama ou LM Studio (aucun détecté)"


def _ask(label: str, default: str = "") -> str:
    suffix = f" [dim]{label}[/dim]"
    theme.console.print(f"   [{theme.ACCENT}]›[/]{suffix} ", end="")
    try:
        answer = input().strip()
    except (EOFError, KeyboardInterrupt):
        theme.console.print()
        return ""
    return answer or default


# --------------------------------------------------------------------------
# Per-provider setup
# --------------------------------------------------------------------------


def _setup_claude(found: Detected) -> Config | None:
    if found.claude:
        theme.warn("Abonnement Claude détecté, mais Anthropic ne l'accepte que "
                   "depuis ses propres clients. Thot a besoin d'une clé API.")
        theme.console.print()

    theme.hint("console.anthropic.com/settings/keys")
    theme.console.print()
    key = _secret("clé API (sk-ant-…)")
    if not key:
        return None
    model = _ask("modèle", default=DEFAULT_CLAUDE_MODEL)
    return Config(provider="claude", model=model, api_key=key)


def _setup_openai(found: Detected) -> Config | None:
    key = found.openai_key
    if key:
        theme.ok("OPENAI_API_KEY détectée dans l'environnement")
    else:
        key = _secret("clé API OpenAI")
        if not key:
            return None
    model = _ask("modèle", default=DEFAULT_OPENAI_MODEL)
    return Config(provider="openai", model=model, api_key=key)


def _setup_local(found: Detected) -> Config | None:
    models = found.ollama or found.lmstudio
    base_url = OLLAMA_BASE_URL if found.ollama else LMSTUDIO_BASE_URL

    if not models:
        theme.warn("Aucun serveur local détecté.")
        theme.hint("Démarre Ollama (`ollama serve`) ou LM Studio, puis relance Thot.")
        return None

    theme.hint(f"Modèles disponibles : {', '.join(models)}")
    theme.console.print()
    model = _ask("modèle", default=models[0])
    theme.ok(f"{model} — local, hors ligne, gratuit")
    return Config(provider="local", model=model, base_url=base_url)


def _setup_custom() -> Config | None:
    theme.hint("Tout endpoint qui parle le dialecte OpenAI.")
    theme.console.print()
    base_url = _ask("URL de base (…/v1)")
    if not base_url:
        return None
    model = _ask("modèle")
    if not model:
        return None
    key = _secret("clé API (entrée si aucune)")
    return Config(provider="custom", model=model, base_url=base_url, api_key=key)


def _secret(label: str) -> str:
    theme.console.print(f"   [{theme.ACCENT}]›[/] [dim]{label}[/dim] ", end="")
    try:
        return getpass.getpass("").strip()
    except (EOFError, KeyboardInterrupt):
        theme.console.print()
        return ""
