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
    # Un arbre hors des dossiers protégés : ce test porte sur le PATH, et les
    # arbres réels de cette machine sont sur le Bureau, que le contrôle
    # suivant refuse — à juste titre, mais pas ici.
    monkeypatch.setattr("thot.fusion.audit.parts",
                        lambda: [("thot", tmp_path)])
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

    # Never this machine's launchd: the suite must answer the same on a
    # laptop whose unit has run and on a build box that has none.
    monkeypatch.setattr("thot.schedule.install.launchd_runs",
                        lambda label: 0)
    ok, detail = doctor._loop()

    assert ok is False, detail
    assert "Desktop" in detail
    assert "launchd" in detail


def test_the_loop_check_also_guards_the_trees_it_audits(tmp_path, monkeypatch):
    """An install outside the Desktop that audits a project inside it.

    The import-path check passes there and the job starts — then reads
    nothing, because macOS refuses the tree just as it refuses the source.
    Both are the same failure and both must be named.
    """
    from thot.schedule.jobs import Job

    home = tmp_path / "home"
    (home / "Desktop" / "projet").mkdir(parents=True)
    binaries = home / ".local" / "bin"
    binaries.mkdir(parents=True)
    script = binaries / "thot"
    script.write_text("#!/bin/sh\n")
    for agent in ("claude", "hermes"):
        (binaries / agent).write_text("#!/bin/sh\n")

    from thot.schedule.jobs import FUSION

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.fusion.audit.parts",
                        lambda: [("projet", home / "Desktop" / "projet")])
    monkeypatch.setattr("thot.schedule.install.LAUNCH_AGENTS", tmp_path)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: home))
    (tmp_path / "com.thot.improve.plist").write_text(
        f"<plist><dict><string>{script}</string>"
        f"<key>PATH</key><string>{binaries}</string></dict></plist>",
        encoding="utf-8",
    )

    # Never this machine's launchd: the suite must answer the same on a
    # laptop whose unit has run and on a build box that has none.
    monkeypatch.setattr("thot.schedule.install.launchd_runs",
                        lambda label: 0)
    ok, detail = doctor._loop()

    assert ok is False, detail
    assert "projet" in detail, detail


# --- une tâche qui n'a jamais rien écrit n'a jamais tourné ------------------
#
# Le blocage TCC de cette machine était invisible par tous les signaux :
# launchctl la disait chargée, LastExitStatus valait 0, et le journal était
# *absent* plutôt que faux. launchd crée pourtant son fichier de sortie à
# chaque exécution — un journal qui n'existe pas après l'heure dite est la
# preuve qu'aucune exécution n'a eu lieu, quelle qu'en soit la cause.

HOUR = 3600
DAY = 24 * HOUR


def test_a_job_installed_minutes_ago_is_not_yet_late():
    from thot.doctor import stale_loop

    assert stale_loop(schedule="daily", installed=1000 * DAY,
                      log_exists=False, log_mtime=0, log_size=0,
                      now=1000 * DAY + HOUR) == ""


def test_a_job_past_its_hour_with_no_log_never_ran():
    from thot.doctor import stale_loop

    said = stale_loop(schedule="daily", installed=1000 * DAY,
                      log_exists=False, log_mtime=0, log_size=0,
                      now=1000 * DAY + 3 * DAY)

    assert "jamais" in said, said


def test_a_job_that_ran_last_night_says_nothing():
    from thot.doctor import stale_loop

    now = 1000 * DAY
    assert stale_loop(schedule="daily", installed=now - 30 * DAY,
                      log_exists=True, log_mtime=now - HOUR, log_size=400,
                      now=now) == ""


def test_a_log_that_stopped_growing_is_named():
    from thot.doctor import stale_loop

    now = 1000 * DAY
    said = stale_loop(schedule="daily", installed=now - 30 * DAY,
                      log_exists=True, log_mtime=now - 9 * DAY, log_size=400,
                      now=now)

    assert "9 jour" in said, said


def test_an_empty_log_after_the_hour_is_a_run_that_produced_nothing():
    from thot.doctor import stale_loop

    now = 1000 * DAY
    said = stale_loop(schedule="daily", installed=now - 30 * DAY,
                      log_exists=True, log_mtime=now - 3 * DAY, log_size=0,
                      now=now)

    assert "sans une ligne" in said, said


def test_an_hourly_job_is_judged_on_hours_not_days():
    from thot.doctor import stale_loop

    now = 1000 * DAY
    assert stale_loop(schedule="hourly", installed=now - 30 * DAY,
                      log_exists=True, log_mtime=now - 5 * HOUR, log_size=9,
                      now=now) != ""


def test_the_loop_check_reports_a_job_that_never_wrote(tmp_path, monkeypatch):
    """The wiring: `_loop` must actually consult the log."""
    import os
    import time

    from thot.schedule.jobs import FUSION, Job

    home = tmp_path / "home"
    binaries = home / ".local" / "bin"
    binaries.mkdir(parents=True)
    (binaries / "thot").write_text("#!/bin/sh\n")
    for agent in ("claude", "hermes"):
        (binaries / agent).write_text("#!/bin/sh\n")
    tree = home / "projets" / "app"
    tree.mkdir(parents=True)

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.fusion.audit.parts", lambda: [("app", tree)])
    monkeypatch.setattr("thot.schedule.install.LAUNCH_AGENTS", tmp_path)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: home))
    monkeypatch.setattr("thot.paths.log_file", lambda name: home / "absent.log")

    unit = tmp_path / "com.thot.improve.plist"
    unit.write_text(
        f"<plist><dict><string>{binaries / 'thot'}</string>"
        f"<key>PATH</key><string>{binaries}</string></dict></plist>",
        encoding="utf-8",
    )
    # installée il y a une semaine : son heure est passée plusieurs fois
    old = time.time() - 7 * 86_400
    os.utime(unit, (old, old))

    ok, detail = doctor._loop()

    assert ok is False, detail
    assert "jamais exécutée" in detail, detail


def test_the_readme_shows_every_check_the_doctor_runs(tmp_path):
    """The README's sample drifted to eleven checks while the tool ran twelve.

    Nothing guarded it, and a README that undersells the tool is as wrong as
    one that oversells it. The count is the part a reader trusts without
    verifying, so it is the part worth pinning.
    """
    import re

    from thot.paths import home  # noqa: F401  (kept: home isolation is autouse)

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    claimed = re.search(r"^(\d+)/(\d+) vérification\(s\) passées", readme, re.M)
    assert claimed, "le bloc d'exemple de `thot doctor` a disparu du README"

    checks = doctor.run(tmp_path)

    assert int(claimed.group(2)) == len(checks), (
        f"le README annonce {claimed.group(2)} vérifications, "
        f"`doctor.run` en produit {len(checks)}"
    )

    # Les noms et leur ordre, pas seulement le compte : c'est ainsi que
    # `câblage` a pu être ajouté sans que l'exemple le montre. Les détails de
    # chaque ligne dépendent de la machine (450 décisions, 91 skills) et ne
    # sont pas comparables ; les noms, si.
    block = readme[readme.index("✓ fusion"):claimed.start()]
    listed = [
        line.split(maxsplit=2)[1]
        for line in block.splitlines()
        if line.startswith(("✓ ", "✗ "))
    ]

    assert listed == [c.name for c in checks], (
        f"README : {listed}\n`doctor.run` : {[c.name for c in checks]}"
    )


# -- the scheduler that runs inside the session ---------------------------


def test_a_running_session_scheduler_settles_the_loop(monkeypatch):
    """launchd's troubles stop deciding once something else serves the job.

    On this machine the unit cannot start at all — macOS refuses the tree to
    a launchd agent — so a check that only ever asked about the unit called
    the loop broken while it was running.
    """
    from thot import doctor
    from thot.schedule import daemon
    from thot.schedule.jobs import Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root="fusion", schedule="daily",
                     deep=True, budget=8)],
    )
    monkeypatch.setattr(daemon, "running", lambda: 4242)
    monkeypatch.setattr("thot.schedule.install.launchd_runs", lambda label: 0)

    ok, detail = doctor._loop()
    assert ok
    assert "4242" in detail


def test_without_a_scheduler_the_unit_still_decides(monkeypatch):
    from thot import doctor
    from thot.schedule import daemon
    from thot.schedule.jobs import Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root="fusion", schedule="daily",
                     deep=True, budget=8)],
    )
    monkeypatch.setattr(daemon, "running", lambda: None)
    monkeypatch.setattr("thot.schedule.install.launchd_runs", lambda label: 0)
    monkeypatch.setattr(doctor, "LAUNCH_AGENTS", Path("/nulle/part"),
                        raising=False)

    ok, detail = doctor._loop()
    assert "planificateur de session" not in detail


def test_a_unit_that_has_run_is_not_condemned_by_its_path(monkeypatch):
    """The check called this loop broken on the shape of a path alone.

    TCC grants are per binary: `/bin/sh` under launchd is refused a tree
    that the unit's own interpreter reads without trouble — measured both
    ways, after the job had already run a full audit from the folder this
    check said it could never reach.
    """
    from thot import doctor
    from thot.schedule.jobs import FUSION, Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.schedule.install.launchd_runs", lambda label: 3)

    def never_asked(*args, **kwargs):
        raise AssertionError("le chemin ne doit plus être interrogé")

    monkeypatch.setattr(doctor, "unreachable_from_launchd", never_asked)

    ok, detail = doctor._loop()
    assert "3 passage(s)" in detail


def test_a_session_scheduler_is_not_announced_over_a_working_unit(monkeypatch):
    """Two schedulers on one job doubled the work the first night. The
    honest line is launchd's record, not a second mechanism's pid."""
    from thot import doctor
    from thot.schedule import daemon
    from thot.schedule.jobs import FUSION, Job

    monkeypatch.setattr(
        "thot.schedule.jobs.load",
        lambda: [Job(name="improve", root=FUSION, deep=True, budget=8)],
    )
    monkeypatch.setattr("thot.schedule.install.launchd_runs", lambda label: 1)
    monkeypatch.setattr(daemon, "running", lambda: 4242)

    _, detail = doctor._loop()
    assert "4242" not in detail
    assert "1 passage(s)" in detail
