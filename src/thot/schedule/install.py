"""Hand a job to the system scheduler.

Thot writes the unit file and tells you the one command that activates it,
rather than editing your crontab or loading agents behind your back. A tool
that silently installs background jobs is a tool you stop trusting, and the
one-line copy-paste costs the user nothing.
"""

from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

from thot.schedule.jobs import Job, cron_expression

from thot.paths import log_file

LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"


def _thot_binary() -> str:
    return shutil.which("thot") or f"{sys.executable} -m thot.cli"


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
    binary = _thot_binary()
    arguments = "".join(
        f"\n    <string>{part}</string>"
        for part in [*binary.split(), "schedule", "run", job.name]
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label(job)}</string>
  <key>ProgramArguments</key>
  <array>{arguments}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
{_launchd_calendar(job.schedule)}
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>{agent_path()}</string>
    <key>HOME</key><string>{Path.home()}</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
    <key>PYTHONFAULTHANDLER</key><string>1</string>
  </dict>
  <key>StandardOutPath</key><string>{log_file(job.name)}</string>
  <key>StandardErrorPath</key><string>{log_file(job.name)}</string>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
"""


def crontab_line(job: Job) -> str:
    # The PATH rides in the line: cron's default is shorter than launchd's,
    # and a deep job with no agent on the path judges nothing and says so
    # only in a log nobody opens.
    return (
        f"{cron_expression(job.schedule)} PATH={agent_path()} "
        f"{_thot_binary()} schedule run {job.name} "
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
