"""Authorization gate: Thot refuses to audit code it was not mandated to audit."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path

import yaml

from thot.errors import AuthorizationError

AUTHORIZATION_FILENAME = ".thot/authorization.yaml"


@dataclass(frozen=True)
class Authorization:
    owner: str
    scope: str
    authorized: bool
    date: str


def authorization_path(root: Path) -> Path:
    return Path(root) / AUTHORIZATION_FILENAME


def write_authorization(root: Path, owner: str) -> Path:
    """Create the authorization file for `root`. Used by `thot init`."""
    path = authorization_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "owner": owner,
        "scope": str(Path(root).resolve()),
        "authorized": True,
        "date": _dt.date.today().isoformat(),
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True))
    return path


def load_authorization(root: Path) -> Authorization:
    path = authorization_path(root)
    if not path.exists():
        raise AuthorizationError(
            f"Aucun fichier d'autorisation ({AUTHORIZATION_FILENAME}). "
            f"Lance `thot init {root}` si ce code t'appartient ou si tu es mandaté "
            f"pour l'auditer."
        )
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"Fichier d'autorisation illisible : {exc}") from exc

    if not isinstance(raw, dict):
        raise AuthorizationError("Fichier d'autorisation malformé.")
    if raw.get("authorized") is not True:
        raise AuthorizationError(
            "Le fichier d'autorisation ne déclare pas `authorized: true`."
        )

    declared = Path(str(raw.get("scope", ""))).resolve()
    actual = Path(root).resolve()
    if declared != actual:
        raise AuthorizationError(
            f"Le périmètre déclaré ({declared}) ne correspond pas au dépôt audité "
            f"({actual})."
        )

    return Authorization(
        owner=str(raw.get("owner", "")),
        scope=str(declared),
        authorized=True,
        date=str(raw.get("date", "")),
    )
