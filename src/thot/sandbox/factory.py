"""Choose where commands run, and refuse to pretend.

`~/.thot/sandbox.json`, or `THOT_SANDBOX=docker|local`, or `--sandbox` on
the command line. The default is `local`, because that is what Thot has
always done and silently changing how a user's commands execute would be
worse than the risk it removes.

The one hard rule: an explicitly requested sandbox that cannot be built
raises. Everywhere else in Thot a missing dependency costs its feature and
the work continues; here, continuing on the host is precisely the outcome
the user asked to avoid.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from thot.paths import home
from thot.sandbox.base import Sandbox, SandboxError
from thot.sandbox.docker import DEFAULT_IMAGE, DockerSandbox
from thot.sandbox.local import LocalSandbox

FILENAME = "sandbox.json"
KINDS = ("local", "docker")


def config_file() -> Path:
    return home() / FILENAME


def load_config() -> dict:
    try:
        data = json.loads(config_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    override = os.environ.get("THOT_SANDBOX", "").strip().lower()
    if override:
        data["kind"] = override
    if os.environ.get("THOT_SANDBOX_IMAGE"):
        data["image"] = os.environ["THOT_SANDBOX_IMAGE"]
    return data


def save_config(data: dict) -> Path:
    path = config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def build_sandbox(root: Path | str, *, kind: str = "",
                  config: dict | None = None) -> Sandbox:
    """The sandbox for this repository. Raises rather than downgrading."""
    config = load_config() if config is None else config
    chosen = (kind or str(config.get("kind") or "local")).lower()
    root = Path(root)

    if chosen in {"", "local", "none", "aucun"}:
        return LocalSandbox(root=root)

    if chosen in {"docker", "podman", "conteneur"}:
        sandbox = DockerSandbox(
            root=root,
            image=str(config.get("image") or DEFAULT_IMAGE),
            network=bool(config.get("network", False)),
            writable=bool(config.get("writable", False)),
        )
        usable, reason = sandbox.available()
        if not usable:
            raise SandboxError(reason)
        return sandbox

    raise SandboxError(
        f"Bac à sable inconnu : {chosen}. Connus : {', '.join(KINDS)}."
    )
