"""Scheduled audits, and the only thing that makes them bearable: silence.

A nightly audit that mails the same 300 findings every night is an unsubscribe
waiting to happen. The job of this module is to run the audit and then say
nothing at all unless something is genuinely new since last time.
"""

from __future__ import annotations

import json

import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.schedule import jobs
from thot.schedule.runner import new_since_last_run


def make_finding(identifier="a", severity=Severity.HIGH):
    location = CodeRef(path=f"{identifier}.py", line=1, symbol="f", ast_hash=identifier)
    return Finding(
        id=Finding.compute_id("sink.os.system", location),
        rule="sink.os.system",
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
    )


# -- job persistence ---------------------------------------------------------


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "schedule.json"
    monkeypatch.setattr(jobs, "REGISTRY_PATH", path)
    return path


def test_a_job_round_trips(registry):
    jobs.add(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    loaded = jobs.load()
    assert len(loaded) == 1
    assert loaded[0].root == "/repo"
    assert loaded[0].schedule == "daily"


def test_adding_the_same_name_replaces_it(registry):
    jobs.add(jobs.Job(name="nuit", root="/a", schedule="daily"))
    jobs.add(jobs.Job(name="nuit", root="/b", schedule="weekly"))
    loaded = jobs.load()
    assert len(loaded) == 1
    assert loaded[0].root == "/b"


def test_removing_a_job(registry):
    jobs.add(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    assert jobs.remove("nuit") is True
    assert jobs.load() == []
    assert jobs.remove("nuit") is False


def test_no_registry_means_no_jobs(registry):
    assert jobs.load() == []


def test_a_corrupt_registry_is_not_fatal(registry):
    registry.write_text("{ pas du json")
    assert jobs.load() == []


def test_an_unknown_schedule_is_refused(registry):
    with pytest.raises(ValueError, match="fréquence"):
        jobs.add(jobs.Job(name="x", root="/r", schedule="parfois"))


def test_schedules_map_to_cron_expressions():
    assert jobs.cron_expression("daily")
    assert jobs.cron_expression("hourly")
    assert jobs.cron_expression("weekly")


# -- the silence rule --------------------------------------------------------


def test_everything_is_new_on_a_first_run():
    current = [make_finding("a"), make_finding("b")]
    assert len(new_since_last_run(current, previous_ids=set())) == 2


def test_nothing_is_new_when_nothing_changed():
    current = [make_finding("a"), make_finding("b")]
    known = {f.id for f in current}
    assert new_since_last_run(current, previous_ids=known) == []


def test_only_the_newcomer_is_reported():
    old = make_finding("a")
    new = make_finding("b")
    fresh = new_since_last_run([old, new], previous_ids={old.id})
    assert [f.location.path for f in fresh] == ["b.py"]


def test_refuted_findings_are_never_news():
    from dataclasses import replace

    refuted = replace(make_finding("a"), confidence=Confidence.REFUTED)
    assert new_since_last_run([refuted], previous_ids=set()) == []


def test_a_threshold_filters_the_noise():
    low = make_finding("a", Severity.LOW)
    high = make_finding("b", Severity.HIGH)
    fresh = new_since_last_run(
        [low, high], previous_ids=set(), threshold=Severity.HIGH
    )
    assert [f.location.path for f in fresh] == ["b.py"]


# -- the diff comes from the store -------------------------------------------


def test_the_store_knows_nothing_before_the_first_run(tmp_path, toy_repo):
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        assert store.previous_finding_ids(str(toy_repo)) == set()
    finally:
        store.close()


def test_the_store_reports_the_last_stored_run(tmp_path, toy_repo):
    """Queried before the next run starts, so the newest row is the baseline."""
    from thot.pipeline import run_audit
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        first = run_audit(toy_repo, store=store, require_authorization=False)
        known = store.previous_finding_ids(str(toy_repo))
        assert known == {f.id for f in first.findings}
    finally:
        store.close()


def test_a_scheduled_run_is_silent_the_second_time(tmp_path, toy_repo):
    from thot.schedule.runner import run_job
    from thot.store.db import Store

    store = Store.open(tmp_path / "s.db")
    try:
        job = jobs.Job(name="t", root=str(toy_repo), schedule="daily",
                       threshold=Severity.LOW.value)
        first, total = run_job(job, store=store)
        assert first and total
        second, _ = run_job(job, store=store)
        assert second == []
    finally:
        store.close()


# -- handing the job to the system -------------------------------------------


def test_a_launchd_plist_names_the_job_and_the_command():
    from thot.schedule.install import label, launchd_plist

    job = jobs.Job(name="nuit", root="/repo", schedule="daily")
    plist = launchd_plist(job)
    assert label(job) in plist
    assert "<string>schedule</string>" in plist
    assert "<string>nuit</string>" in plist
    assert "<key>Hour</key><integer>3</integer>" in plist


def test_an_hourly_job_has_no_fixed_hour():
    from thot.schedule.install import launchd_plist

    plist = launchd_plist(jobs.Job(name="h", root="/r", schedule="hourly"))
    assert "<key>Hour</key>" not in plist


def test_a_weekly_job_pins_a_weekday():
    from thot.schedule.install import launchd_plist

    plist = launchd_plist(jobs.Job(name="w", root="/r", schedule="weekly"))
    assert "<key>Weekday</key><integer>1</integer>" in plist


def test_the_crontab_line_is_runnable():
    from thot.schedule.install import crontab_line

    line = crontab_line(jobs.Job(name="nuit", root="/repo", schedule="daily"))
    assert line.startswith("0 3 * * *")
    assert "schedule run nuit" in line


# -- a deep job has to actually be deep ---------------------------------------


def _toy(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os, sys\n\ndef run():\n    os.system('ls ' + sys.argv[1])\n"
    )
    return tmp_path


def _scripted(verdict="refuted"):
    from thot.engine.base import AgentResult, EngineCapabilities

    class _Engine:
        ran = 0

        @property
        def capabilities(self):
            return EngineCapabilities(name="scripted", max_parallel=2)

        def run(self, task):
            type(self).ran += 1
            return AgentResult(
                task_id=task.id,
                data={"verdict": verdict, "scenario": "entrée constante"},
            )

        def fan_out(self, tasks):
            return [self.run(task) for task in tasks]

    return _Engine


def test_a_deep_job_argues_instead_of_only_sweeping(tmp_path, monkeypatch):
    """`deep: true` was written to the registry and never read.

    The flag existed, `thot schedule add --deep` set it, and the nightly run
    was a plain deterministic sweep — a promise the job never kept.
    """
    from thot.schedule.jobs import Job
    from thot.schedule.runner import run_job

    engine = _scripted()
    monkeypatch.setattr(
        "thot.engine.factory.build_engine", lambda *a, **kw: engine()
    )

    job = Job(name="nuit", root=str(_toy(tmp_path)), deep=True, budget=5)
    run_job(job)

    assert engine.ran > 0, "aucun agent n'a été sollicité"


def test_a_shallow_job_never_builds_an_engine(tmp_path, monkeypatch):
    from thot.schedule.jobs import Job
    from thot.schedule.runner import run_job

    def _forbidden(*a, **kw):
        raise AssertionError("un job non-deep ne doit rien faire tourner")

    monkeypatch.setattr("thot.engine.factory.build_engine", _forbidden)
    run_job(Job(name="jour", root=str(_toy(tmp_path))))


def test_a_fusion_job_audits_every_tree(tmp_path, monkeypatch):
    """One unit, one log, the whole program."""
    from thot.schedule.jobs import FUSION, Job
    from thot.schedule.runner import run_job

    first, second = tmp_path / "un", tmp_path / "deux"
    for root in (first, second):
        root.mkdir()
        _toy(root)
    monkeypatch.setattr(
        "thot.fusion.audit.parts", lambda: [("un", first), ("deux", second)]
    )

    fresh, total = run_job(Job(name="tout", root=FUSION, threshold="info"))

    assert total > 0
    assert {f.location.path for f in fresh} == {"app.py"}
    assert len(fresh) >= 2, "les deux arbres doivent avoir été audités"


def test_a_nightly_deep_job_reports_what_it_confirmed(tmp_path, monkeypatch):
    """Its product is what it decided, not what appeared.

    `new_since_last_run` answers "what is new above the threshold", which is
    right for a sweep and wrong for a judgement: confirming a MEDIUM already
    in the report is exactly what the loop exists for, and it would have gone
    to nobody.
    """
    from thot.schedule.jobs import Job
    from thot.schedule.runner import run_job

    class _Confirms:
        @property
        def capabilities(self):
            from thot.engine.base import EngineCapabilities

            return EngineCapabilities(name="scripted", max_parallel=1)

        def run(self, task):
            from thot.engine.base import AgentResult

            return AgentResult(
                task_id=task.id,
                data={"verdict": "confirmed", "scenario": "argv atteint le shell",
                      "severity": "medium"},
            )

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    monkeypatch.setattr(
        "thot.engine.factory.build_engine", lambda *a, **kw: _Confirms()
    )
    job = Job(name="nuit", root=str(_toy(tmp_path)), deep=True, budget=2,
              threshold="critical")

    fresh, total = run_job(job)

    assert total > 0
    assert fresh, "une confirmation doit remonter même sous le seuil"
    assert any("app.py" in f.location.path for f in fresh)


def test_a_whole_program_job_uses_each_tree_s_own_memory(tmp_path, monkeypatch):
    """Committed verdicts are not interchangeable between repositories.

    The caller builds one memory from `job.root` — which for this job is the
    word "fusion", not a path — so the verdicts a team committed under
    `hermes/.thot/` were never read.
    """
    from thot.schedule.jobs import FUSION, Job
    from thot.schedule.runner import run_job

    first, second = tmp_path / "un", tmp_path / "deux"
    for root in (first, second):
        root.mkdir()
        _toy(root)
    monkeypatch.setattr(
        "thot.fusion.audit.parts", lambda: [("un", first), ("deux", second)]
    )

    asked: list[str] = []
    real = __import__("thot.memory", fromlist=["build_memory"]).build_memory

    def spy(root=None, **kwargs):
        asked.append(str(root))
        return real(root, **kwargs)

    monkeypatch.setattr("thot.memory.build_memory", spy)
    run_job(Job(name="tout", root=FUSION, threshold="info"))

    assert str(first) in asked and str(second) in asked


def test_a_night_where_everything_failed_says_so(tmp_path, monkeypatch, capsys):
    """A loop that fails every night and says nothing looks like one that runs."""
    from thot.schedule.jobs import Job
    from thot.schedule.runner import run_job

    class _Fails:
        @property
        def capabilities(self):
            from thot.engine.base import EngineCapabilities

            return EngineCapabilities(name="scripted", max_parallel=1)

        def run(self, task):
            from thot.engine.base import AgentResult

            return AgentResult(task_id=task.id, error="limite d'usage atteinte")

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    monkeypatch.setattr(
        "thot.engine.factory.build_engine", lambda *a, **kw: _Fails()
    )
    run_job(Job(name="nuit", root=str(_toy(tmp_path)), deep=True, budget=2))

    assert "aucun verdict" in capsys.readouterr().err


# -- what a daemon's environment does not contain -----------------------------


def test_the_unit_carries_a_path_that_can_find_the_agents():
    """launchd hands a job `/usr/bin:/bin:/usr/sbin:/sbin`; cron gives less.

    `claude`, `hermes` and `node` live in none of those — on the machine this
    was found on they are in `~/.local/bin`. So the nightly deep audit built
    no engine, judged nothing, and exited 0. Every night, silently, for ever.
    """
    import shutil

    from thot.schedule.install import agent_path, crontab_line, launchd_plist
    from thot.schedule.jobs import FUSION, Job

    path = agent_path()
    assert "/usr/bin" in path, "les chemins du système restent"

    located = shutil.which("claude") or shutil.which("node")
    if located:
        from pathlib import Path as _Path

        assert str(_Path(located).resolve().parent) in path, (
            "le dossier de l'agent doit être dans le PATH de l'unité"
        )

    job = Job(name="improve", root=FUSION, deep=True)
    plist = launchd_plist(job)
    assert "<key>EnvironmentVariables</key>" in plist
    assert "<key>PATH</key>" in plist
    assert f"PATH={path}" in crontab_line(job)


def test_a_deep_job_without_an_agent_is_recorded_as_such(tmp_path, monkeypatch):
    """Exit 0 on a run that judged nothing is a lie told to the daemon."""
    from thot.engine.factory import NoEngine
    from thot.schedule.jobs import Job
    from thot.schedule.runner import MISSING_ENGINE, run_job

    MISSING_ENGINE.clear()

    def _absent(*args, **kwargs):
        raise NoEngine("aucun agent installé")

    monkeypatch.setattr("thot.engine.factory.build_engine", _absent)
    run_job(Job(name="nuit", root=str(_toy(tmp_path)), deep=True, budget=2))

    assert "nuit" in MISSING_ENGINE


def test_a_shallow_job_without_an_agent_is_not_a_failure(tmp_path, monkeypatch):
    """It never wanted one."""
    from thot.schedule.jobs import Job
    from thot.schedule.runner import MISSING_ENGINE, run_job

    MISSING_ENGINE.clear()
    run_job(Job(name="jour", root=str(_toy(tmp_path))))

    assert MISSING_ENGINE == set()
