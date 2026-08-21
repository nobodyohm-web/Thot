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

LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"


def _thot_binary() -> str:
    return shutil.which("thot") or f"{sys.executable} -m thot.cli"


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
  <key>StandardOutPath</key><string>{Path.home()}/.thot/{job.name}.log</string>
  <key>StandardErrorPath</key><string>{Path.home()}/.thot/{job.name}.log</string>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
"""


def crontab_line(job: Job) -> str:
    return (
        f"{cron_expression(job.schedule)} {_thot_binary()} schedule run {job.name} "
        f">> {Path.home()}/.thot/{job.name}.log 2>&1"
    )


def install(job: Job) -> tuple[Path | None, str]:
    """Write what the platform needs. Returns (file written, next step)."""
    if platform.system() == "Darwin":
        LAUNCH_AGENTS.mkdir(parents=True, exist_ok=True)
        target = LAUNCH_AGENTS / f"{label(job)}.plist"
        target.write_text(launchd_plist(job), encoding="utf-8")
        return target, f"launchctl load {target}"

    return None, (
        "Ajoute cette ligne à ta crontab (`crontab -e`) :\n"
        f"  {crontab_line(job)}"
    )


def uninstall_hint(job: Job) -> str:
    if platform.system() == "Darwin":
        target = LAUNCH_AGENTS / f"{label(job)}.plist"
        return f"launchctl unload {target} && rm {target}"
    return "Retire la ligne correspondante de `crontab -e`."
