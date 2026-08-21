"""Find plugins, load them, and call their hooks without trusting them.

A plugin is a directory with a `plugin.yaml` and an `__init__.py` exposing a
function per declared hook — the shape Hermes Agent uses, so a Hermes plugin's
layout is already familiar here.

Hermes has dozens of hooks because it has a gateway, a kanban board and a
speech pipeline. Thot audits code, so it has five, and each exists because
something shipped uses it. Adding a sixth is a decision, not a convenience.

The property that matters is isolation. A plugin that raises costs its own
feature and nothing else: an audit that dies because a notification hook threw
is worse than an audit with no notifications.
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

MANIFEST = "plugin.yaml"
PLUGINS_DIRNAME = "plugins"

# Every hook, and why it exists. A name absent from here is refused at load
# time rather than silently never fired — a hook that never runs is the
# hardest kind of bug to notice.
VALID_HOOKS: dict[str, str] = {
    "on_finding": (
        "Reçoit chaque finding avant le rapport. Peut l'annoter ou renvoyer "
        "None pour le laisser tel quel. kwargs : finding, root."
    ),
    "post_audit": (
        "Reçoit le résultat complet d'un audit. Pour notifier, exporter, "
        "archiver. kwargs : result, root."
    ),
    "pre_write": (
        "Appelé avant que l'agent écrive un fichier. Renvoie un avertissement "
        "à faire remonter au modèle, ou une chaîne vide. kwargs : path, content."
    ),
    "post_write": (
        "Appelé après une écriture réussie. kwargs : path, content."
    ),
    "on_verdict": (
        "Appelé quand une décision d'audit est enregistrée. kwargs : verdict."
    ),
}


@dataclass
class Plugin:
    name: str
    version: str = ""
    description: str = ""
    author: str = ""
    hooks: tuple[str, ...] = ()
    path: Path | None = None
    callbacks: dict[str, Callable] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _read_manifest(path: Path) -> dict | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def _import_module(folder: Path, name: str):
    """Import a plugin package under a private name, so it cannot shadow ours."""
    module_name = f"thot_plugin_{name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(
        module_name, folder / "__init__.py", submodule_search_locations=[str(folder)]
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"{folder} n'est pas importable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_one(folder: Path) -> Plugin | None:
    manifest = _read_manifest(folder / MANIFEST)
    if manifest is None:
        return None

    name = str(manifest.get("name") or folder.name)
    declared = manifest.get("hooks") or []
    if isinstance(declared, str):
        declared = [declared]
    hooks = tuple(str(h) for h in declared)

    plugin = Plugin(
        name=name,
        version=str(manifest.get("version", "")),
        description=str(manifest.get("description", "")),
        author=str(manifest.get("author", "")),
        hooks=hooks,
        path=folder,
    )

    unknown = [h for h in hooks if h not in VALID_HOOKS]
    if unknown:
        plugin.error = (
            f"hook inconnu : {', '.join(unknown)}. "
            f"Connus : {', '.join(sorted(VALID_HOOKS))}"
        )
        return plugin

    try:
        module = _import_module(folder, name)
    except Exception as exc:
        plugin.error = f"import impossible : {exc}"
        return plugin

    missing = []
    for hook in hooks:
        function = getattr(module, hook, None)
        if callable(function):
            plugin.callbacks[hook] = function
        else:
            missing.append(hook)
    if missing:
        plugin.error = f"hook déclaré mais absent du module : {', '.join(missing)}"
    return plugin


def load_from(directory: Path) -> list[Plugin]:
    directory = Path(directory)
    if not directory.is_dir():
        return []
    plugins: list[Plugin] = []
    for folder in sorted(p for p in directory.iterdir() if p.is_dir()):
        plugin = _load_one(folder)
        if plugin is not None:
            plugins.append(plugin)
    return plugins


def library_dir() -> Path | None:
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / PLUGINS_DIRNAME, here.parent / "library"):
        if candidate.is_dir():
            return candidate
    return None


def user_dir() -> Path:
    from thot.paths import user_dir as thot_user_dir

    return thot_user_dir(PLUGINS_DIRNAME)


def repo_dir(root: Path) -> Path:
    return Path(root) / ".thot" / PLUGINS_DIRNAME


def bundled() -> list[Plugin]:
    directory = library_dir()
    return load_from(directory) if directory else []


def discover(root: Path | None = None) -> list[Plugin]:
    """Shipped, then personal, then repo. Later wins on name."""
    sources = [p for p in (library_dir(), user_dir()) if p is not None]
    if root is not None:
        sources.append(repo_dir(root))

    by_name: dict[str, Plugin] = {}
    for source in sources:
        for plugin in load_from(source):
            by_name[plugin.name] = plugin
    return sorted(by_name.values(), key=lambda p: p.name)


def invoke_hook(plugins: list[Plugin], name: str, **kwargs: Any) -> list[Any]:
    """Call every subscriber, isolated. Failures are dropped, never raised.

    Returns only what subscribers actually returned, so a caller can act on
    the results without filtering out the ones that blew up.
    """
    results: list[Any] = []
    for plugin in plugins:
        callback = plugin.callbacks.get(name)
        if callback is None:
            continue
        try:
            results.append(callback(**kwargs))
        except Exception:
            plugin.error = f"{name} a échoué : {traceback.format_exc(limit=1).strip()}"
    return results
