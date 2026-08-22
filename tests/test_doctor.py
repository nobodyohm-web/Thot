"""The self-check. "It works" is a claim; this is the measurement.

What matters most here is that a check which cannot run reports a failure
rather than passing quietly — a green line meaning "not tested" is worse
than a red one, because it is the line people stop reading.
"""

from __future__ import annotations

from pathlib import Path

from thot import doctor


def test_every_check_reports_something_it_measured(tmp_path):
    checks = doctor.run(Path.cwd())

    assert checks, "aucune vérification n'a tourné"
    for check in checks:
        assert check.name
        assert check.detail, f"{check.name} ne dit pas ce qu'il a mesuré"


def test_a_check_that_raises_is_a_failed_check_not_a_crash():
    def explodes():
        raise RuntimeError("le disque a disparu")

    check = doctor._safe("essai", explodes)

    assert check.ok is False
    assert "le disque a disparu" in check.detail


def test_the_taint_check_exercises_both_engines(tmp_path):
    """A silent regression in either engine must turn this red."""
    ok, detail = doctor._taint(tmp_path)

    assert ok
    assert "python 1" in detail and "javascript 1" in detail


def test_the_mcp_check_speaks_the_protocol(tmp_path):
    ok, detail = doctor._mcp(tmp_path)

    assert ok
    assert "outil" in detail


def test_the_indexer_check_covers_both_languages():
    ok, detail = doctor._indexers(Path.cwd())

    assert ok
    assert "python" in detail and "typescript" in detail


def test_a_failed_check_renders_with_a_cross():
    assert doctor.Check("x", False, "cassé").line().startswith("✗")
    assert doctor.Check("x", True, "bon").line().startswith("✓")


def test_the_live_check_believes_only_what_the_agent_answered(monkeypatch):
    """The defect it exists for was invisible to every static inspection.

    Hermes could not open a path relative to its working directory and said
    so in words that read like a refusal. Nothing short of planting a file
    and reading the answer would have caught it.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Blind:
        def __init__(self, root, max_parallel=1):
            self.root = root

        @property
        def capabilities(self):
            return EngineCapabilities(name="aveugle", max_parallel=1)

        def run(self, task):
            return AgentResult(
                task_id=task.id,
                data={"verdict": "je ne peux pas lire ce fichier"},
            )

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._can_read(_Blind)
    assert ok is False
    assert "n'a pas lu" in detail


def test_the_live_check_passes_when_the_content_comes_back():
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Reads:
        def __init__(self, root, max_parallel=1):
            self.root = root

        @property
        def capabilities(self):
            return EngineCapabilities(name="voyant", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id,
                               data={"verdict": doctor.CANARY})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._can_read(_Reads)
    assert ok is True
    assert "chemin absolu" in detail


def test_the_offline_checks_do_not_include_the_live_ones():
    """`thot doctor` on a plane gives the answer it gives at a desk."""
    names = {check.name for check in doctor.run(Path.cwd())}

    assert not any(name.startswith("lecture ·") for name in names)


def test_an_agent_that_writes_when_it_should_not_fails_the_check(tmp_path):
    """Checking the flags would only prove the flags were passed.

    Today's lesson twice over: `-t file` was believed to make Hermes
    read-only and does not. The check asks for the write, then looks on disk.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Writes:
        def __init__(self, root, max_parallel=1):
            self.root = Path(root)

        @property
        def capabilities(self):
            return EngineCapabilities(name="bavard", max_parallel=1)

        def run(self, task):
            (self.root / "ecrit-par-la-sonde.txt").write_text("ECRIT")
            return AgentResult(task_id=task.id, data={"verdict": "fait"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._cannot_write(_Writes)
    assert ok is False
    assert "a pu écrire" in detail


def test_an_agent_that_leaves_the_disk_alone_passes(tmp_path):
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Quiet:
        def __init__(self, root, max_parallel=1):
            self.root = Path(root)

        @property
        def capabilities(self):
            return EngineCapabilities(name="sage", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id, data={"verdict": "refusé"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._cannot_write(_Quiet)
    assert ok is True
    assert "n'a pas écrit" in detail


def test_the_wiring_check_notices_a_plugin_that_was_disabled(monkeypatch):
    """`parts` says the trees are on disk and nothing about the wiring.

    Hermes's `plugins.enabled` and Prime's skills path are files belonging to
    other programs, with their own upgrades and migrations — exactly what
    breaks quietly between two versions.
    """
    from thot.fusion.wiring import Step

    monkeypatch.setattr(
        "thot.fusion.wiring.plan_hermes",
        lambda: [Step(target=Path("a"), action="déjà en place")],
    )
    monkeypatch.setattr("thot.fusion.wiring.plan_prime", lambda: [])
    monkeypatch.setattr("thot.fusion.wiring.hermes_enabled", lambda: False)

    ok, detail = doctor._wiring()

    assert ok is False
    assert "rebrancher" in detail


def test_the_wiring_check_passes_when_everything_is_in_place(monkeypatch):
    from thot.fusion.wiring import Step

    monkeypatch.setattr(
        "thot.fusion.wiring.plan_hermes",
        lambda: [Step(target=Path("a"), action="déjà en place")],
    )
    monkeypatch.setattr(
        "thot.fusion.wiring.plan_prime",
        lambda: [Step(target=Path("b"), action="déjà en place")],
    )
    monkeypatch.setattr("thot.fusion.wiring.hermes_enabled", lambda: True)

    ok, detail = doctor._wiring()

    assert ok is True
    assert "2/2" in detail


def test_the_toolbelt_check_names_what_it_does_not_recognise():
    """The denylist is brittle by construction, so the gap is made visible.

    `--allowed-tools` pre-approves and does not restrict — measured, by
    launching a probe with `Read Glob Grep` allowed and being told it also
    held `Write`, `Bash` and `Workflow`. The next version of the client will
    bring tools this list has never heard of, and this is what says so.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    def engine_listing(names):
        class _Lists:
            def __init__(self, root, max_parallel=1):
                pass

            @property
            def capabilities(self):
                return EngineCapabilities(name="factice", max_parallel=1)

            def run(self, task):
                return AgentResult(task_id=task.id, data={"verdict": names})

            def fan_out(self, tasks):
                return [self.run(t) for t in tasks]

        return _Lists

    ok, detail = doctor._toolbelt(engine_listing("Read, Grep, Glob"))
    assert ok is True
    assert "lecture seule" in detail

    ok, detail = doctor._toolbelt(engine_listing("Read, Grep, CronCreate, Bash"))
    assert ok is False
    assert "CronCreate" in detail and "Bash" in detail


def test_an_empty_answer_is_a_failure_not_a_pass():
    """A probe that says nothing has not been shown to hold nothing."""
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Silent:
        def __init__(self, root, max_parallel=1):
            pass

        @property
        def capabilities(self):
            return EngineCapabilities(name="muet", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id, data={"verdict": ""})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._toolbelt(_Silent)
    assert ok is False
    assert "liste" in detail


def test_the_toolbelt_check_reads_names_and_not_prose():
    """It was measuring how the model writes, not what it holds.

    Asked for a bare list, a probe answered "TaskStop (outils différés,
    ToolSearch (outils chargés) + CronList, appelables uniquement après…" —
    and the comma split turned that into three imaginary tools and a red
    line. A name is CamelCase or an `mcp__` prefix; a French word is neither.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Prose:
        def __init__(self, root, max_parallel=1):
            pass

        @property
        def capabilities(self):
            return EngineCapabilities(name="bavard", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id, data={"verdict": (
                "TaskStop (outils différés, ToolSearch (outils chargés) + "
                "CronList, appelables uniquement après chargement du schéma"
            )})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._toolbelt(_Prose)
    assert ok is True, detail
    assert "lecture seule" in detail


def test_prose_does_not_hide_a_real_surplus():
    """The looser parser must not become a looser check."""
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Mixed:
        def __init__(self, root, max_parallel=1):
            pass

        @property
        def capabilities(self):
            return EngineCapabilities(name="mixte", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id, data={"verdict": (
                "Read et Grep, plus Bash (pour les commandes) et CronCreate"
            )})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    ok, detail = doctor._toolbelt(_Mixed)
    assert ok is False
    assert "Bash" in detail and "CronCreate" in detail


def test_an_unreadable_toolbelt_is_not_a_clean_one():
    """It printed "1 outil, tous en lecture seule" about a Python kernel.

    `ipython` is lowercase, the name pattern knows CamelCase and `mcp__`
    prefixes, so nothing was recognised, nothing was surplus, and the line
    went green about the most capable tool in the fusion. An answer nobody
    could parse is not an answer that everything is fine.
    """
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Kernel:
        def __init__(self, root, max_parallel=1):
            pass

        @property
        def capabilities(self):
            return EngineCapabilities(name="noyau", max_parallel=1)

        def run(self, task):
            return AgentResult(task_id=task.id, data={"verdict": "ipython"})

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    strict_ok, strict_detail = doctor._toolbelt(_Kernel, strict=True)
    assert strict_ok is False
    assert "aucun nom d'outil reconnu" in strict_detail

    shown_ok, shown_detail = doctor._toolbelt(_Kernel, strict=False)
    assert shown_ok is True
    assert shown_detail == "ipython", "montré tel quel, jamais qualifié"


def test_a_unit_whose_path_cannot_find_the_agents_is_a_failure(tmp_path,
                                                               monkeypatch):
    """The failure this exists for is invisible until someone reads a log.

    launchd hands a job `/usr/bin:/bin:/usr/sbin:/sbin`, the agents are not
    there, and a deep pass that finds none of them judges nothing and exits
    0 — a success recorded every night while nothing happens.
    """
    from thot.schedule.jobs import FUSION, Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.schedule.install.LAUNCH_AGENTS", tmp_path)

    unit = tmp_path / "com.thot.improve.plist"
    unit.write_text(
        "<plist><dict><key>EnvironmentVariables</key><dict>"
        "<key>PATH</key><string>/usr/bin:/bin</string>"
        "</dict></dict></plist>",
        encoding="utf-8",
    )
    ok, detail = doctor._loop()
    assert ok is False
    assert "aucun agent dans le PATH" in detail

    unit.write_text(
        "<plist><dict><key>EnvironmentVariables</key><dict>"
        "<key>PATH</key><string>/usr/bin:/bin</string>"
        "</dict></dict></plist>".replace(
            "/usr/bin:/bin", f"{tmp_path}:/usr/bin"
        ),
        encoding="utf-8",
    )
    (tmp_path / "claude").write_text("#!/bin/sh\n")
    (tmp_path / "hermes").write_text("#!/bin/sh\n")
    ok, detail = doctor._loop()
    assert ok is True
    assert "joignables" in detail


def test_a_unit_without_any_path_is_a_failure(tmp_path, monkeypatch):
    from thot.schedule.jobs import FUSION, Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.schedule.install.LAUNCH_AGENTS", tmp_path)
    (tmp_path / "com.thot.improve.plist").write_text(
        "<plist><dict></dict></plist>", encoding="utf-8"
    )

    ok, detail = doctor._loop()
    assert ok is False
    assert "n'a pas de PATH" in detail


# --- une boucle nocturne qui importe depuis un dossier protégé ne part pas --
#
# Mesuré sur cette machine : un LaunchAgent minimal exécutant
# `ls /Users/dev/Desktop/Thot/src` sort en rc=1, tandis que
# `ls ~/.local/share/uv/tools/thot` sort en rc=0. macOS refuse le Bureau à un
# agent launchd, qui n'a aucun consentement TCC et aucune session pour le
# demander. Or l'installation éditable écrit `/Users/dev/Desktop/Thot/src`
# dans `_thot.pth`, donc sur `sys.path` : le job se bloque dans
# `site.execsitecustomize` → `_fill_cache`, à 0,03 s de CPU, indéfiniment,
# sans écrire une ligne dans son journal. `thot doctor` le disait au vert.


def test_an_import_path_under_the_desktop_is_named():
    from thot.doctor import unreachable_from_launchd

    guarded = unreachable_from_launchd(
        ["/Users/dev/Desktop/Thot/src", "/Users/dev/.local/lib/python"],
        home="/Users/dev",
    )

    assert guarded == ["/Users/dev/Desktop/Thot/src"]


def test_documents_and_downloads_are_guarded_too():
    from thot.doctor import unreachable_from_launchd

    guarded = unreachable_from_launchd(
        ["/Users/dev/Documents/a", "/Users/dev/Downloads/b"], home="/Users/dev"
    )

    assert len(guarded) == 2


def test_an_ordinary_install_path_is_left_alone():
    from thot.doctor import unreachable_from_launchd

    assert unreachable_from_launchd(
        ["/Users/dev/.local/share/uv/tools/thot/lib", "/usr/lib/python3"],
        home="/Users/dev",
    ) == []


def test_a_lookalike_directory_is_not_mistaken_for_the_real_one():
    from thot.doctor import unreachable_from_launchd

    # `Desktop` compte comme premier segment sous $HOME, pas ailleurs
    assert unreachable_from_launchd(
        ["/opt/Desktop/thing", "/Users/dev/projets/Desktop_backup"],
        home="/Users/dev",
    ) == []


def test_the_paths_are_read_from_the_job_interpreter_not_from_this_process(tmp_path):
    """The wiring: unit → console script → shebang → its own .pth files.

    Written because the first version of this check asked `sys.path` of
    whatever process ran `thot doctor`, and duly named the checkout's venv
    instead of the path launchd is actually refused.
    """
    from thot.doctor import job_import_paths, unreachable_from_launchd

    tools = tmp_path / "tools" / "thot"
    (tools / "bin").mkdir(parents=True)
    packages = tools / "lib" / "python3.11" / "site-packages"
    packages.mkdir(parents=True)
    interpreter = tools / "bin" / "python3"
    interpreter.write_text("#!/bin/sh\n")
    (packages / "_thot.pth").write_text("/Users/someone/Desktop/Thot/src\n")

    script = tmp_path / "bin" / "thot"
    script.parent.mkdir(parents=True)
    script.write_text(f"#!{interpreter}\nprint('hi')\n")

    unit = tmp_path / "job.plist"
    unit.write_text(f"<string>{script}</string>\n<string>schedule</string>\n")

    paths = job_import_paths(unit)

    assert "/Users/someone/Desktop/Thot/src" in paths
    assert unreachable_from_launchd(paths, home="/Users/someone") == [
        "/Users/someone/Desktop/Thot/src"
    ]


def test_a_unit_pointing_at_nothing_readable_says_nothing(tmp_path):
    from thot.doctor import job_import_paths

    unit = tmp_path / "job.plist"
    unit.write_text("<string>/nowhere/at/all</string>\n")

    assert job_import_paths(unit) == []


def test_the_loop_check_itself_fails_on_a_guarded_import_path(tmp_path, monkeypatch):
    """`_loop` must actually consult the two helpers above.

    Both of them were fully tested while `_loop` ignored them entirely:
    neutering the branch left the suite green. This is the test that goes red.
    """
    from thot.schedule.jobs import FUSION, Job

    home = tmp_path / "home"
    tools = home / ".local" / "tools" / "thot"
    (tools / "bin").mkdir(parents=True)
    packages = tools / "lib" / "python3.11" / "site-packages"
    packages.mkdir(parents=True)
    interpreter = tools / "bin" / "python3"
    interpreter.write_text("#!/bin/sh\n")
    (packages / "_thot.pth").write_text(str(home / "Desktop" / "Thot" / "src") + "\n")

    script = home / "bin" / "thot"
    script.parent.mkdir(parents=True)
    script.write_text(f"#!{interpreter}\n")

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.schedule.install.LAUNCH_AGENTS", tmp_path)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: home))
    (tmp_path / "com.thot.improve.plist").write_text(
        f"<plist><dict><string>{script}</string>"
        "<key>PATH</key><string>/usr/bin</string></dict></plist>",
        encoding="utf-8",
    )

    ok, detail = doctor._loop()

    assert ok is False, detail
    assert "Desktop" in detail
    assert "launchd" in detail
