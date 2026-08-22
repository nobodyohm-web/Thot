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

# -- the hooks that ship with Thot -------------------------------------------


def _shipped(name: str):
    """The plugin as Thot really loads it, not as a hand-imported module."""
    from thot.plugins import discover, forget_plugins

    forget_plugins()
    for plugin in discover():
        if plugin.name == name:
            assert plugin.ok, f"{name} ne charge pas : {plugin.error}"
            return plugin
    raise AssertionError(f"plugin {name} absent")


def test_every_declared_hook_has_a_subscriber():
    """A hook nobody fires and nobody uses is a hook that rots."""
    from thot.plugins import discover
    from thot.plugins.loader import VALID_HOOKS

    subscribed = set()
    for plugin in discover():
        assert plugin.ok, f"{plugin.name} ne charge pas : {plugin.error}"
        subscribed |= set(plugin.callbacks)

    assert subscribed == set(VALID_HOOKS)


def test_the_journal_records_an_audit_a_verdict_and_a_write(isolated_home):
    import json

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.memory import Decision, Verdict
    from thot.pipeline import AuditResult
    from thot.scope.manifest import ScopeManifest

    journal = _shipped("audit-log").callbacks
    finding = Finding(
        id="x", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="a.py", line=1, symbol="f", ast_hash="h"),
    )
    manifest = ScopeManifest(
        root="/r", files=("a.py",), languages={"python": 1}, entrypoints=()
    )

    journal["post_audit"](
        result=AuditResult(findings=[finding], manifest=manifest, elapsed=1.0),
        root="/r",
    )
    journal["on_verdict"](verdict=Verdict.of(finding, Decision.REFUTED, "littéral"))
    journal["post_write"](path="a.py", content="une ligne\n")

    lines = [json.loads(line) for line in
             (isolated_home / "journal.jsonl").read_text().splitlines()]
    assert [line["event"] for line in lines] == ["audit", "verdict", "écriture"]
    assert lines[0]["par_gravité"] == {"high": 1}
    assert lines[1]["décision"] == "refuted"
    assert all("at" in line for line in lines)


def test_a_returning_defect_is_promoted_to_critical():
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    on_finding = _shipped("regression-alert").callbacks["on_finding"]
    location = CodeRef(path="a.py", line=1, symbol="f", ast_hash="h")
    returning = Finding(
        id="x", rule="sink.os.system", severity=Severity.MEDIUM,
        confidence=Confidence.PLAUSIBLE, location=location,
        failure_scenario="argv atteint os.system",
        provenance={"régression": True, "décidé le": "2026-01-05T10:00:00"},
    )

    promoted = on_finding(finding=returning)
    assert promoted.severity is Severity.CRITICAL
    assert "RÉGRESSION" in promoted.failure_scenario
    assert "2026-01-05" in promoted.failure_scenario
    assert "argv atteint os.system" in promoted.failure_scenario

    # Idempotent: re-running an audit must not stack annotations.
    assert on_finding(finding=promoted) is None

    ordinary = Finding(id="y", rule="r", severity=Severity.LOW,
                       confidence=Confidence.PLAUSIBLE, location=location)
    assert on_finding(finding=ordinary) is None


def test_writing_a_file_notifies_the_plugins(toy_repo, monkeypatch):
    """post_write was declared before anything fired it; now something does."""
    from thot import agent_tools

    seen = []
    monkeypatch.setattr(
        "thot.plugins.notify_write",
        lambda path, content, root: seen.append((path, content)),
    )
    context = agent_tools.ToolContext(
        root=toy_repo, recon=None, confirm=lambda *a: True, refresh=lambda: None
    )
    agent_tools.write_file(context, path="nouveau.py", content="x = 1\n")

    assert seen == [("nouveau.py", "x = 1\n")]


def test_the_pipeline_lets_plugins_annotate_before_anything_is_stored(monkeypatch):
    from thot.plugins import notify as notify_module

    seen = []

    def spy(findings, root=None):
        seen.append(len(findings))
        return findings

    monkeypatch.setattr("thot.pipeline.annotate_findings", spy)
    from thot.pipeline import run_audit
    from pathlib import Path

    run_audit(Path(__file__).resolve().parents[1], store=None,
              require_authorization=False)
    assert seen, "on_finding doit être proposé à chaque audit"


# -- code the repository under audit supplies ---------------------------------
#
# Skills and commands from a repository are screened because they are prompt
# text. Plugins were not screened at all, and they are the only category that
# *executes*: `thot audit <dépôt>` imported them, module body and all, under
# the account of whoever ran it. These tests hold the line.


def repo_plugin(root, name="pwn", body=None):
    """A plugin dropped in by the repository being audited."""
    marker = root / "executed"
    folder = write_plugin(
        root / ".thot" / "plugins",
        name,
        hooks="[on_finding]",
        code=body or (
            f"from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('oui')\n\n"
            f"def on_finding(**kw):\n    return None\n"
        ),
    )
    return folder, marker


def test_a_repository_plugin_is_not_executed_until_it_is_trusted(tmp_path):
    folder, marker = repo_plugin(tmp_path)

    loaded, refused = loader.discover_report(tmp_path)

    assert not marker.exists(), "le corps du module a été exécuté"
    assert "pwn" not in {p.name for p in loaded}
    assert [r.name for r in refused] == ["pwn"]
    assert refused[0].path == folder


def test_a_refusal_still_names_the_plugin_without_importing_it(tmp_path):
    """The manifest is parsed, never executed — so we can say what was refused."""
    repo_plugin(tmp_path, name="collecte")

    refused = loader.discover_report(tmp_path)[1]
    assert refused[0].name == "collecte"
    assert "trust" in refused[0].reason


def test_an_approved_repository_plugin_loads(tmp_path):
    from thot.plugins import trust

    folder, marker = repo_plugin(tmp_path)
    trust.trust(folder)

    loaded = loader.discover_report(tmp_path)[0]
    assert "pwn" in {p.name for p in loaded}
    assert marker.exists(), "un plugin approuvé doit bel et bien tourner"


def test_approval_lapses_when_the_code_changes(tmp_path):
    """Approving a plugin approves its bytes, not its name."""
    from thot.plugins import trust

    folder, _ = repo_plugin(tmp_path)
    trust.trust(folder)
    (folder / "__init__.py").write_text(
        "def on_finding(**kw):\n    return None\n", encoding="utf-8"
    )

    loaded, refused = loader.discover_report(tmp_path)
    assert "pwn" not in {p.name for p in loaded}
    assert "changé" in refused[0].reason


def test_a_personal_plugin_needs_no_approval(tmp_path, isolated_home):
    """`~/.thot/plugins` is the user's own installation, not a repository's."""
    write_plugin(isolated_home / "plugins", "perso")

    assert "perso" in {p.name for p in loader.discover_report(tmp_path)[0]}


def test_bytecode_next_to_the_source_does_not_revoke_approval(tmp_path):
    """The reason IGNORED_DIRS exists, asserted rather than explained.

    Python writes `__pycache__` beside a module the first time it imports it.
    If that revoked trust, every approved plugin would be refused on its
    second run — the mechanism would revoke itself into disuse.
    """
    from thot.plugins import trust

    folder, _ = repo_plugin(tmp_path)
    trust.trust(folder)
    cache = folder / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "__init__.cpython-311.pyc").write_bytes(b"\x00" * 64)

    assert trust.status(folder) == "trusted"


def test_renaming_a_file_lapses_the_approval(tmp_path):
    """An import reads the whole directory, so the whole directory is approved."""
    from thot.plugins import trust

    folder, _ = repo_plugin(tmp_path)
    (folder / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    trust.trust(folder)

    (folder / "helper.py").rename(folder / "aide.py")

    assert trust.status(folder) == "changed"


def test_moving_a_file_lapses_the_approval_even_with_identical_bytes(tmp_path):
    """Path is hashed alongside content: `sub/a.py` is not `a.py`."""
    from thot.plugins import trust

    folder, _ = repo_plugin(tmp_path)
    (folder / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    trust.trust(folder)

    (folder / "inner").mkdir()
    (folder / "helper.py").rename(folder / "inner" / "helper.py")

    assert trust.status(folder) == "changed"


def test_the_nightly_push_names_the_engine_that_judged(tmp_path, monkeypatch):
    """The plugin has the whole result; it was passing only the findings.

    What the loop pushes is the cascade's product — confirmations and
    contested refutations — and the message said nothing about a panel having
    argued. This is the only place that work reaches someone away from the
    terminal.
    """
    from types import SimpleNamespace

    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.gateway import server
    from thot.plugins import discover, forget_plugins

    sent: list[str] = []
    monkeypatch.setattr(
        server, "broadcast",
        lambda text: sent.append(text) or [],
    )

    forget_plugins()
    notify = next(p for p in discover(tmp_path) if p.name == "gateway-notify")
    finding = Finding(
        id="n1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        location=CodeRef(path="app.py", line=9, symbol="handle", ast_hash="h"),
        failure_scenario="argv atteint os.system",
    )

    notify.callbacks["post_audit"](
        result=SimpleNamespace(engine="panel", findings=[finding]),
        root=tmp_path, new_findings=[finding],
    )

    assert sent, "aucun message poussé"
    assert "panel" in sent[0], sent[0]
