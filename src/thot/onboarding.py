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


def _fused_option() -> tuple[str, str, str] | None:
    """The two agents Thot is made of, when they are here.

    Offered first and pre-selected, because it is not one backend among
    five: it is what the program is. A first-run screen that listed every
    model *except* Hermes and Prime asked the user to configure their way out
    of Thot's own premise — and that is the screen this program shipped with.
    """
    try:
        from thot.engine.factory import available_engines

        found = [name for name in available_engines() if name in ("hermes", "prime")]
    except Exception:
        return None
    if len(found) == 2:
        return ("fusion", "Fusion",
                "hermes + prime — Prime exécute, Hermes raisonne")
    if len(found) == 1:
        only = found[0]
        detail = ("exécution et noyau" if only == "prime"
                  else "raisonnement et contexte long")
        return (only, only.capitalize(), f"le seul des deux installé — {detail}")
    return None


def first_run() -> Config | None:
    theme.banner()
    found = detect()
    fused = _fused_option()

    theme.hint("Premier lancement. Un modèle à connecter."
               if fused is None
               else "Premier lancement. Thot est la fusion de Hermes et Prime.")
    theme.console.print()

    # (provider, label, detail, setup) — the fused entry first when present,
    # so pressing Enter runs Thot as what it is.
    entries: list[tuple[str, str, str, object]] = []
    if fused is not None:
        provider, label, detail = fused
        entries.append((provider, label, detail,
                        lambda p=provider: Config(provider=p, model="")))
    entries += [
        ("claude", "Claude", _claude_detail(found), lambda: _setup_claude(found)),
        ("openai", "OpenAI", _openai_detail(found), lambda: _setup_openai(found)),
        ("local", "Local", _local_detail(found), lambda: _setup_local(found)),
        ("custom", "Autre", "endpoint compatible OpenAI", _setup_custom),
    ]

    default = 1 if fused is not None else _default_choice(found)
    for index, (_, label, detail, _setup) in enumerate(entries, start=1):
        theme.console.print(
            _option(index, label, detail, highlight=default == index)
        )
    theme.console.print()

    choice = _ask(f"[1-{len(entries)}]", default=str(default))
    theme.console.print()

    if not choice:
        choice = str(default)
    if choice.isdigit() and 1 <= int(choice) <= len(entries):
        return entries[int(choice) - 1][3]()
    return None


def _default_choice(found: Detected) -> int:
    if found.claude and found.claude_cli:
        return 1
    if found.ollama or found.lmstudio:
        return 3
    if found.openai_key:
        return 2
    return 1


def _claude_detail(found: Detected) -> str:
    if found.claude and found.claude_cli:
        return "ton compte — abonnement détecté"
    if found.claude_cli:
        return "compte ou clé API"
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


# Everything that means "there is nobody at this keyboard".
#
# `EOFError` is the closed pipe and `KeyboardInterrupt` is the person leaving,
# but a stdin that was never there at all raises `RuntimeError: input(): lost
# sys.stdin` — the shape a `nohup`, a launchd job or a CI runner takes. That
# one was not caught, so the very first screen Thot ever shows ended in a
# traceback. `OSError` joins them for the terminal that goes away mid-prompt.
#
# The catch is deliberately wide because the contract is narrow: this function
# returns what someone typed, or nothing. There is no failure of the keyboard
# for which crashing beats answering "nothing".
_NO_KEYBOARD = (EOFError, KeyboardInterrupt, OSError, RuntimeError)


def _ask(label: str, default: str = "") -> str:
    suffix = f" [dim]{label}[/dim]"
    theme.console.print(f"   [{theme.ACCENT}]›[/]{suffix} ", end="")
    try:
        answer = input().strip()
    except _NO_KEYBOARD:
        theme.console.print()
        return ""
    return answer or default


# --------------------------------------------------------------------------
# Per-provider setup
# --------------------------------------------------------------------------


def _setup_claude(found: Detected) -> Config | None:
    """The account path needs no key: the official CLI already holds the login."""
    if found.claude and found.claude_cli:
        theme.ok("Compte Claude connecté — Thot passe par le CLI officiel")
        theme.hint("Ton abonnement, ton compte, aucun jeton à copier.")
        return Config(provider="claude-cli", model="")

    if found.claude_cli:
        theme.warn("Le CLI `claude` est installé mais aucune session n'est ouverte.")
        theme.hint("Lance `claude` dans un terminal, connecte-toi, puis relance Thot.")
        theme.console.print()
        theme.hint("Ou colle une clé API pour continuer maintenant.")
    else:
        theme.hint("Pour utiliser ton compte : npm install -g @anthropic-ai/claude-code")
        theme.console.print()
        theme.hint("Sinon, une clé API : console.anthropic.com/settings/keys")

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
    except _NO_KEYBOARD:
        theme.console.print()
        return ""
