"""Where credentials come from, and how a provider gets built from them.

One JSON file, mode 0600. Claude subscriptions are detected only so the first
screen can explain why they cannot be used here: Anthropic accepts subscription
tokens from its own clients only, and Thot will not impersonate one.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from thot.llm.anthropic import AnthropicProvider
from thot.llm.base import Provider
from thot.llm.openai_compat import (
    LMSTUDIO_BASE_URL,
    OLLAMA_BASE_URL,
    OPENAI_BASE_URL,
    OpenAICompatProvider,
    list_local_models,
)

CONFIG_PATH = Path.home() / ".thot" / "config.json"
CLAUDE_CREDENTIALS_FILE = Path.home() / ".claude" / ".credentials.json"
KEYCHAIN_SERVICE = "Claude Code-credentials"

DEFAULT_CLAUDE_MODEL = "claude-opus-5"
DEFAULT_OPENAI_MODEL = "gpt-5.1"


@dataclass
class Config:
    """What Thot remembers between runs. Never holds an OAuth access token."""

    provider: str  # "claude-cli" | "claude" | "openai" | "local" | "custom"
    model: str
    api_key: str = ""
    base_url: str = ""

    def label(self) -> str:
        if self.provider == "claude-cli":
            return f"{self.model or 'claude'} · ton compte"
        return self.model


# --------------------------------------------------------------------------
# Config file
# --------------------------------------------------------------------------


def load_config() -> Config | None:
    try:
        raw = json.loads(CONFIG_PATH.read_text())
        return Config(**raw)
    except (OSError, ValueError, TypeError):
        return None


def save_config(config: Config) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(asdict(config), indent=2))
    os.chmod(CONFIG_PATH, 0o600)


def forget() -> None:
    CONFIG_PATH.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Claude subscription credentials, as written by the official CLI
# --------------------------------------------------------------------------


def _from_keychain() -> dict | None:
    if platform.system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _from_file() -> dict | None:
    try:
        return json.loads(CLAUDE_CREDENTIALS_FILE.read_text())
    except (OSError, ValueError):
        return None


def _unwrap(payload: dict | None) -> dict | None:
    if not payload:
        return None
    return payload.get("claudeAiOauth", payload)


def read_claude_credentials() -> dict | None:
    """The freshest Claude credentials available, keychain or file."""
    candidates = [_unwrap(_from_keychain()), _unwrap(_from_file())]
    candidates = [c for c in candidates if c and c.get("accessToken")]
    if not candidates:
        return None
    return max(candidates, key=lambda c: c.get("expiresAt", 0) or 0)


# --------------------------------------------------------------------------
# What is available on this machine, right now
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Detected:
    claude: bool
    claude_cli: bool
    ollama: list[str]
    lmstudio: list[str]
    openai_key: str


def detect() -> Detected:
    """Look around once, so the first screen can offer the obvious choice."""
    import shutil

    return Detected(
        claude=read_claude_credentials() is not None,
        claude_cli=shutil.which("claude") is not None,
        ollama=list_local_models(OLLAMA_BASE_URL),
        lmstudio=list_local_models(LMSTUDIO_BASE_URL),
        openai_key=os.environ.get("OPENAI_API_KEY", "").strip(),
    )


# --------------------------------------------------------------------------
# Config -> Provider
# --------------------------------------------------------------------------


def build_provider(config: Config) -> Provider:
    """Turn stored settings into something that can answer. Raises on failure."""
    from thot.llm.base import ProviderError

    if config.provider == "claude":
        token = config.api_key
        if not token:
            raise ProviderError(
                "Aucune clé API Anthropic. Lance `thot login`.\n"
                "   Un abonnement Claude ne peut pas servir ici : Anthropic ne "
                "l'accepte que depuis ses propres clients."
            )
        return AnthropicProvider(
            model=config.model,
            token=token,
            base_url=config.base_url or "https://api.anthropic.com",
        )

    if config.provider == "openai":
        key = config.api_key or os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise ProviderError("Aucune clé OpenAI. Lance `thot login`.")
        return OpenAICompatProvider(
            model=config.model,
            base_url=config.base_url or OPENAI_BASE_URL,
            api_key=key,
            name="openai",
        )

    # Local servers and private gateways: same dialect, no key required.
    return OpenAICompatProvider(
        model=config.model,
        base_url=config.base_url or OLLAMA_BASE_URL,
        api_key=config.api_key,
        name=config.provider or "local",
    )
