"""Hand a job to the system scheduler.

Thot writes the unit file and tells you the one command that activates it,
rather than editing your crontab or loading agents behind your back. A tool
that silently installs background jobs is a tool you stop trusting, and the
one-line copy-paste costs the user nothing.
"""

from __future__ import annotations

import platform
import shlex
import shutil
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from thot.schedule.jobs import Job, cron_expression

from thot.paths import log_file

LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"


def thot_command() -> list[str]:
    """The argv that actually runs Thot — a list, never a string to be split.

    `-m thot`, not `-m thot.cli`. `cli.py` has no `if __name__ == "__main__"`
    block, so `python -m thot.cli` imports the module, defines `main`, and
    exits 0 having done nothing at all. That is the worst shape for an
    unattended job: launchd sees a clean exit every night and nothing is
    ever audited. `thot/__main__.py` is what makes `-m thot` the entry point
    it looks like, and this is the fallback that has to use it.

    A list because a path may contain a space. `str.split()` turns
    `/Users/dev/My Tools/bin/thot` into two arguments, and the unit then
    names a binary that does not exist.
    """
    found = shutil.which("thot")
    return [found] if found else [sys.executable, "-m", "thot"]


def agent_path() -> str:
    """A PATH that can still find the agents when nobody is logged in.

    launchd hands a job `/usr/bin:/bin:/usr/sbin:/sbin` and cron gives even
    less. `claude`, `hermes` and `node` live in none of those — on this
    machine they are in `~/.local/bin` — so a nightly deep audit built no
    engine, judged nothing, and exited 0. Every night, silently, for ever:
    the worst shape an unattended job can take.

    The directories of the binaries that exist right now are prepended, so
    the unit carries the answer rather than hoping the daemon's environment
    resembles a shell's.
    """
    wanted = ("claude", "hermes", "node", "thot", "uv")
    found: list[str] = []
    for name in wanted:
        located = shutil.which(name)
        if not located:
            continue
        directory = str(Path(located).resolve().parent)
        if directory not in found:
            found.append(directory)
    for fallback in ("/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin",
                     "/usr/sbin", "/sbin"):
        if fallback not in found:
            found.append(fallback)
    return ":".join(found)


def label(job: Job) -> str:
    return f"com.thot.{job.name}"


def _launchd_calendar(schedule: str) -> str:
    minute, hour, _, _, weekday = cron_expression(schedule).split()
    lines = [f"    <key>Minute</key><integer>{minute}</integer>"]
    if hour != "*":
        lines.append(f"    <key>Hour</key><integer>{hour}</integer>")
    if weekday != "*":
        lines.append(f"    <key>Weekday</key><integer>{weekday}</integer>")
    return "\n".join(lines)


def launchd_plist(job: Job) -> str:
    arguments = "".join(
        f"\n    <string>{escape(part)}</string>"
        for part in [*thot_command(), "schedule", "run", job.name]
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{escape(label(job))}</string>
  <key>ProgramArguments</key>
  <array>{arguments}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
{_launchd_calendar(job.schedule)}
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>{escape(agent_path())}</string>
    <key>HOME</key><string>{escape(str(Path.home()))}</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
    <key>PYTHONFAULTHANDLER</key><string>1</string>
  </dict>
  <key>StandardOutPath</key><string>{escape(str(log_file(job.name)))}</string>
  <key>StandardErrorPath</key><string>{escape(str(log_file(job.name)))}</string>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
"""


def crontab_line(job: Job) -> str:
    # The PATH rides in the line: cron's default is shorter than launchd's,
    # and a deep job with no agent on the path judges nothing and says so
    # only in a log nobody opens.
    # `shlex.join`, because cron hands the line to a shell: a binary living
    # under a path with a space would otherwise become two words.
    command = shlex.join([*thot_command(), "schedule", "run", job.name])
    return (
        f"{cron_expression(job.schedule)} PATH={agent_path()} "
        f"{command} "
        f">> {log_file(job.name)} 2>&1"
    )


def install(job: Job) -> tuple[Path | None, str]:
    """Write what the platform needs. Returns (file written, next step)."""
    if platform.system() == "Darwin":
        LAUNCH_AGENTS.mkdir(parents=True, exist_ok=True)
        target = LAUNCH_AGENTS / f"{label(job)}.plist"
        target.write_text(launchd_plist(job), encoding="utf-8")
        return target, f"launchctl load {target}" + _cannot_start(target)

    return None, (
        "Ajoute cette ligne à ta crontab (`crontab -e`) :\n"
        f"  {crontab_line(job)}"
    )


def _cannot_start(unit: Path) -> str:
    """A warning when the job will block before running a line of Thot.

    Deferred import: `thot.doctor` reads this module, so the dependency only
    goes that way inside the call.
    """
    from thot.doctor import job_import_paths, unreachable_from_launchd

    guarded = unreachable_from_launchd(job_import_paths(unit), home=Path.home())
    if not guarded:
        return ""
    return (
        f"\n\n⚠ Cette tâche ne démarrera pas : elle importe depuis "
        f"{guarded[0]}, que macOS refuse à un agent launchd. Le job se bloque "
        "au démarrage de l'interpréteur, sans écrire une ligne dans son "
        "journal. Installe Thot hors de Desktop/Documents/Downloads, ou donne "
        "l'accès complet au disque à l'interpréteur qui l'exécute."
    )


def uninstall_hint(job: Job) -> str:
    if platform.system() == "Darwin":
        target = LAUNCH_AGENTS / f"{label(job)}.plist"
        return f"launchctl unload {target} && rm {target}"
    return "Retire la ligne correspondante de `crontab -e`."


def parse_runs(text: str) -> int | None:
    """How many times launchd has actually executed a unit, from its print.

    `launchctl print` reports `runs = N` for a unit it knows. None means the
    question could not be answered — the unit is not loaded, or launchctl
    said something this does not recognise — and that is different from
    zero, which means loaded and never executed.
    """
    for line in text.splitlines():
        key, _, value = line.strip().partition("=")
        if key.strip() == "runs":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def launchd_runs(unit_label: str) -> int | None:
    """Ask launchd how many times it has run this unit."""
    import os
    import subprocess

    try:
        done = subprocess.run(
            ["launchctl", "print", f"gui/{os.getuid()}/{unit_label}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return parse_runs(done.stdout)


def already_served(job) -> bool:
    """Whether launchd is already running this job, demonstrably.

    Not "is a unit installed" — this one was loaded and aborted at
    interpreter start, leaving no run behind, and completed the following
    night. The question is whether launchd has ever executed it, which
    launchd itself answers. A second scheduler serving the same job would
    double the work and the tokens it spends, which is exactly what happened
    the first night both existed.
    """
    return (launchd_runs(label(job)) or 0) >= 1
