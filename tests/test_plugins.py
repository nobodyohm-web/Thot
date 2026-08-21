"""Plugin discovery and hook dispatch.

Adapted from Hermes Agent's PluginManager, narrowed hard. Hermes has dozens of
hooks because it has a gateway, a kanban and a speech pipeline. Thot audits
code, so it has five, and each one exists because something ships that uses it.

The property that matters: a broken plugin costs its own feature and nothing
else. An audit that dies because someone's notification hook raised is worse
than an audit with no notifications.
"""

from __future__ import annotations

import pytest

from thot.plugins import loader


def write_plugin(directory, name, hooks="[post_audit]", code=None, manifest=True):
    folder = directory / name
    folder.mkdir(parents=True, exist_ok=True)
    if manifest:
        (folder / "plugin.yaml").write_text(
            f'name: {name}\nversion: "1.0"\ndescription: un plugin\nhooks: {hooks}\n',
            encoding="utf-8",
        )
    (folder / "__init__.py").write_text(
        code if code is not None else "def post_audit(**kw):\n    return 'ok'\n",
        encoding="utf-8",
    )
    return folder


def test_a_plugin_is_discovered(tmp_path):
    write_plugin(tmp_path, "notify")
    found = loader.load_from(tmp_path)
    assert [p.name for p in found] == ["notify"]
    assert found[0].hooks == ("post_audit",)


def test_a_directory_without_a_manifest_is_ignored(tmp_path):
    write_plugin(tmp_path, "pas-un-plugin", manifest=False)
    assert loader.load_from(tmp_path) == []


def test_a_missing_directory_is_empty(tmp_path):
    assert loader.load_from(tmp_path / "absent") == []


def test_a_declared_hook_with_no_function_is_reported(tmp_path):
    write_plugin(tmp_path, "menteur", hooks="[post_audit]", code="x = 1\n")
    plugin = loader.load_from(tmp_path)[0]
    assert plugin.error and "post_audit" in plugin.error


def test_a_plugin_that_fails_to_import_does_not_raise(tmp_path):
    write_plugin(tmp_path, "cassé", code="raise RuntimeError('boum')\n")
    plugin = loader.load_from(tmp_path)[0]
    assert plugin.error and "boum" in plugin.error
    assert plugin.callbacks == {}


def test_a_broken_plugin_does_not_hide_a_working_one(tmp_path):
    write_plugin(tmp_path, "cassé", code="raise RuntimeError('boum')\n")
    write_plugin(tmp_path, "bon")
    names = {p.name for p in loader.load_from(tmp_path)}
    assert names == {"cassé", "bon"}


# -- dispatch ----------------------------------------------------------------


def test_a_hook_receives_its_arguments(tmp_path):
    write_plugin(tmp_path, "echo", code="def post_audit(**kw):\n    return kw['count']\n")
    plugins = loader.load_from(tmp_path)
    assert loader.invoke_hook(plugins, "post_audit", count=7) == [7]


def test_an_unsubscribed_hook_returns_nothing(tmp_path):
    write_plugin(tmp_path, "echo")
    assert loader.invoke_hook(loader.load_from(tmp_path), "pre_write") == []


def test_a_raising_hook_is_isolated(tmp_path):
    write_plugin(tmp_path, "explose", code="def post_audit(**kw):\n    raise ValueError('non')\n")
    write_plugin(tmp_path, "calme", code="def post_audit(**kw):\n    return 'ça va'\n")
    results = loader.invoke_hook(loader.load_from(tmp_path), "post_audit")
    assert results == ["ça va"]


def test_an_unknown_hook_name_is_refused(tmp_path):
    write_plugin(tmp_path, "inventif", hooks="[on_moon_phase]")
    plugin = loader.load_from(tmp_path)[0]
    assert plugin.error and "on_moon_phase" in plugin.error


def test_every_valid_hook_is_documented():
    for name in loader.VALID_HOOKS:
        assert loader.VALID_HOOKS[name], f"{name} n'est pas documenté"


# -- the shipped plugin ------------------------------------------------------


def test_the_bundled_write_guard_ships_and_loads():
    plugins = loader.bundled()
    names = {p.name for p in plugins}
    assert "write-guard" in names
    guard = next(p for p in plugins if p.name == "write-guard")
    assert guard.error is None, guard.error


def test_the_write_guard_warns_about_a_dangerous_write():
    plugins = loader.bundled()
    warnings = loader.invoke_hook(
        plugins, "pre_write", path="app.py", content="import pickle\npickle.loads(x)\n"
    )
    assert any(w for w in warnings)
    assert "pickle" in " ".join(w for w in warnings if w).lower()


def test_the_write_guard_stays_quiet_on_safe_content():
    plugins = loader.bundled()
    warnings = loader.invoke_hook(
        plugins, "pre_write", path="app.py", content="import json\njson.loads(x)\n"
    )
    assert not any(warnings)
