"""One view of the model choice the three programs each make separately.

Thot, Hermes and Prime each record a provider and a model, in three files,
in three formats. They agree today because they were set up on the same
afternoon; nothing keeps them agreeing. A run that argues findings with
`--engine hermes` and a session that talks to Prime would then be using two
different models while the screen says nothing.

Reading is done from the files, which is instant and cannot break anything.
Writing goes through each program's own tool wherever one exists: Hermes has
`hermes config set`, and its `config.yaml` carries comments and migrations
that are not Thot's to rewrite.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from thot.fusion.wiring import hermes_config_path, prime_settings_path

# The Claude CLI decides the model itself unless told otherwise, so an empty
# model on Thot's side is a deferral, not a disagreement.
DEFERRED = ""


@dataclass(frozen=True)
class ModelChoice:
    """What one program will use, and where it says so."""

    program: str
    provider: str
    model: str
    path: Path
    note: str = ""

    def line(self) -> str:
        model = self.model or "— délégué au CLI"
        provider = self.provider or "—"
        note = f"   {self.note}" if self.note else ""
        return f"{self.program:<8} {provider:<12} {model}{note}"


def _thot_choice() -> ModelChoice:
    from thot.llm.credentials import load_config
    from thot.paths import home

    config = load_config()
    if config is None:
        return ModelChoice("thot", "", "", home() / "config.json",
                           note="(aucun modèle connecté — `thot login`)")
    note = "(le CLI officiel choisit)" if config.provider == "claude-cli" and not config.model else ""
    return ModelChoice("thot", config.provider, config.model,
                       home() / "config.json", note=note)


def _hermes_choice() -> ModelChoice:
    import yaml

    path = hermes_config_path()
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        # `yaml.YAMLError` inherits from neither of the other two, so a
        # half-written `config.yaml` came out as a traceback instead of the
        # `(config illisible)` line below. `ValueError` stays: it is what
        # catches `UnicodeDecodeError` on a binary file.
        loaded = None
    section = (loaded or {}).get("model") if isinstance(loaded, dict) else None
    if not isinstance(section, dict):
        return ModelChoice("hermes", "", "", path, note="(config illisible)")
    return ModelChoice("hermes", str(section.get("provider") or ""),
                       str(section.get("default") or ""), path)


def _prime_choice() -> ModelChoice:
    path = prime_settings_path()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}
    return ModelChoice("prime", str(loaded.get("defaultProvider") or ""),
                       str(loaded.get("defaultModel") or ""), path)


def read_all() -> list[ModelChoice]:
    return [_thot_choice(), _hermes_choice(), _prime_choice()]


def divergence(choices: list[ModelChoice] | None = None) -> str:
    """What the three disagree about, in one sentence. Empty when they agree.

    Thot deferring to the Claude CLI is not a disagreement: it is the absence
    of an opinion, and an absent opinion cannot conflict with anything.
    """
    choices = choices or read_all()
    models = {c.model for c in choices if c.model != DEFERRED}
    if len(models) <= 1:
        return ""
    named = ", ".join(f"{c.program} → {c.model or '—'}" for c in choices if c.model)
    return f"Trois choix, pas le même modèle : {named}."


@dataclass(frozen=True)
class Applied:
    program: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        mark = "✓" if self.ok else "✗"
        return f"{mark} {self.program:<8} {self.detail}"


def apply(model: str, provider: str = "") -> list[Applied]:
    """Say it once, write it in the three places each program reads."""
    return [
        _apply_thot(model, provider),
        _apply_hermes(model, provider),
        _apply_prime(model, provider),
    ]


def _apply_thot(model: str, provider: str) -> Applied:
    from thot.llm.credentials import load_config, save_config
    from dataclasses import replace as _replace

    config = load_config()
    if config is None:
        return Applied("thot", False, "aucun modèle connecté — `thot login` d'abord")
    try:
        save_config(_replace(config, model=model))
    except OSError as exc:
        return Applied("thot", False, str(exc))
    return Applied("thot", True, f"model={model}")


def _apply_hermes(model: str, provider: str) -> Applied:
    """Through `hermes config set`, never by rewriting their YAML.

    `config.yaml` holds comments, backups and a migration history. A tool
    that edits another program's config by hand works until the schema moves.
    """
    from thot.fusion.locate import hermes_command

    command = hermes_command()
    if command is None:
        return Applied("hermes", False, "Hermes n'est pas installé")

    pairs = [("model.default", model)]
    if provider:
        pairs.append(("model.provider", provider))
    for key, value in pairs:
        try:
            done = subprocess.run([*command, "config", "set", key, value],
                                  capture_output=True, text=True, timeout=180,
                                  stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return Applied("hermes", False, str(exc))
        if done.returncode != 0:
            detail = (done.stderr or done.stdout or "").strip().splitlines()
            return Applied("hermes", False, detail[-1] if detail else "échec")
    return Applied("hermes", True, f"model.default={model}")


def _apply_prime(model: str, provider: str) -> Applied:
    from thot.fusion.wiring import _read_json, _write_json

    path = prime_settings_path()
    settings = _read_json(path) or {}
    if path.is_file():
        backup = path.with_suffix(".json.thot-backup")
        if not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    settings["defaultModel"] = model
    if provider:
        settings["defaultProvider"] = provider
    try:
        _write_json(path, settings)
    except OSError as exc:
        return Applied("prime", False, str(exc))
    return Applied("prime", True, f"defaultModel={model}")
