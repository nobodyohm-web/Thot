"""Find and parse SKILL.md files.

Three sources, merged in order, later wins:

1. the library shipped with Thot (ported from Hermes Agent),
2. ``~/.thot/skills/`` — what you know, everywhere you work,
3. ``<repo>/.thot/skills/`` — what this codebase knows, committed with it.

Both layouts are accepted: a flat directory of skills (Prime Agent) and one
grouped into categories (Hermes Agent). Detection is by where SKILL.md sits,
not by configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

SKILL_FILE = "SKILL.md"
SKILLS_DIRNAME = "skills"

# Long enough to say what a skill is for, short enough that a catalogue of
# fifty still fits in a briefing.
SUMMARY_CHARS = 180


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    body: str
    path: Path
    category: str = ""
    metadata: dict = field(default_factory=dict)

    def summary(self) -> str:
        """One catalogue line: enough to choose, not enough to cost."""
        text = " ".join(self.description.split())
        if len(text) > SUMMARY_CHARS:
            text = text[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…"
        label = f"{self.category}/{self.name}" if self.category else self.name
        return f"{label} — {text}"


def _split_frontmatter(text: str) -> tuple[dict, str] | None:
    """Return (frontmatter, body), or None when there is no frontmatter."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    raw = text[3:end]
    body = text[end + 4 :].lstrip("-").lstrip("\n")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data, body


def _read_skill(path: Path, category: str) -> Skill | None:
    """Parse one SKILL.md. A broken skill is skipped, never fatal.

    One unparseable file in a shared library must not cost the user every
    other skill they have.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    split = _split_frontmatter(text)
    if split is None:
        return None
    data, body = split

    name = str(data.get("name") or path.parent.name).strip()
    if not name:
        return None
    return Skill(
        name=name,
        description=str(data.get("description") or "").strip(),
        body=body.strip(),
        path=path,
        category=category,
        metadata={k: v for k, v in data.items() if k not in {"name", "description"}},
    )


def load_from(directory: Path) -> list[Skill]:
    """Every skill under one directory, flat or grouped into categories."""
    directory = Path(directory)
    if not directory.is_dir():
        return []

    skills: list[Skill] = []
    for candidate in sorted(directory.rglob(SKILL_FILE)):
        relative = candidate.parent.relative_to(directory)
        parts = relative.parts
        category = parts[0] if len(parts) > 1 else ""
        skill = _read_skill(candidate, category)
        if skill is not None:
            skills.append(skill)
    return skills


def library_dir() -> Path | None:
    """Where the shipped skills live, editable install or wheel."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / SKILLS_DIRNAME,  # repository root / editable install
        here.parent / "library",           # packaged alongside the loader
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def user_dir() -> Path:
    return Path.home() / ".thot" / SKILLS_DIRNAME


def repo_dir(root: Path) -> Path:
    return Path(root) / ".thot" / SKILLS_DIRNAME


def bundled() -> list[Skill]:
    directory = library_dir()
    return load_from(directory) if directory else []


def discover(root: Path | None = None, *, sources: list[Path] | None = None) -> list[Skill]:
    """Everything available here, personal and repo skills overriding shipped ones."""
    if sources is None:
        directory = library_dir()
        sources = [p for p in (directory, user_dir()) if p is not None]
        if root is not None:
            sources.append(repo_dir(root))

    by_name: dict[str, Skill] = {}
    for source in sources:
        for skill in load_from(source):
            by_name[skill.name] = skill
    return sorted(by_name.values(), key=lambda s: (s.category, s.name))
