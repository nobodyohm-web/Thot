"""Which repositories get audited on their own, and how often.

One JSON file. Adapted from the shape of Hermes Agent's cron jobs (MIT),
minus everything an auditor does not need: no blueprints, no suggestions, no
execution history — the run store already holds that.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from thot.contracts import Severity

from thot.paths import schedule_file

REGISTRY_PATH = schedule_file()

# Deliberately not a raw cron expression. Someone reading `daily` in a config
# knows what it means; nobody reads `17 3 * * *` and feels the same.
SCHEDULES: dict[str, str] = {
    "hourly": "0 * * * *",
    "daily": "0 3 * * *",
    "weekly": "0 3 * * 1",
}


@dataclass
class Job:
    name: str
    root: str
    schedule: str = "daily"
    threshold: str = Severity.HIGH.value
    deep: bool = False

    def validate(self) -> None:
        if self.schedule not in SCHEDULES:
            raise ValueError(
                f"fréquence inconnue « {self.schedule} » "
                f"(attendu : {', '.join(SCHEDULES)})"
            )
        Severity(self.threshold)  # raises on a bad value


def cron_expression(schedule: str) -> str:
    return SCHEDULES[schedule]


def load() -> list[Job]:
    try:
        raw = json.loads(Path(REGISTRY_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []

    out: list[Job] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            job = Job(**entry)
            job.validate()
        except (TypeError, ValueError):
            continue  # one bad entry must not cost the others
        out.append(job)
    return out


def save(all_jobs: list[Job]) -> None:
    path = Path(REGISTRY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([asdict(job) for job in all_jobs], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def add(job: Job) -> None:
    job.validate()
    kept = [existing for existing in load() if existing.name != job.name]
    save(kept + [job])


def remove(name: str) -> bool:
    existing = load()
    kept = [job for job in existing if job.name != name]
    if len(kept) == len(existing):
        return False
    save(kept)
    return True
