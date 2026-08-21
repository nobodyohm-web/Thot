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

# The rest of the Hermes library: real skills, kept out of the default
# catalogue so a session's briefing stays short. `thot skills install`
# moves one across; nothing is downloaded.
OPTIONAL_DIRNAME = "optional-skills"

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

    def tags(self) -> tuple[str, ...]:
        """Keywords declared by the skill, whatever dialect wrote them.

        Hermes nests them under `metadata.hermes.tags`, Prime and the Agent
        Skills standard put them at the top level. Searching one dialect
        would silently miss two thirds of the library.
        """
        found: list[str] = []
        pools = [self.metadata]
        nested = self.metadata.get("metadata")
        if isinstance(nested, dict):
            pools.append(nested)
            for value in nested.values():
                if isinstance(value, dict):
                    pools.append(value)
        for pool in pools:
            raw = pool.get("tags")
            if isinstance(raw, (list, tuple)):
                found.extend(str(tag) for tag in raw)
        return tuple(dict.fromkeys(found))

    def matches(self, needle: str) -> bool:
        needle = needle.lower()
        return (
            needle in self.name.lower()
            or needle in self.description.lower()
            or needle in self.category.lower()
            or any(needle in tag.lower() for tag in self.tags())
        )

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
    from thot.paths import user_dir as thot_user_dir

    return thot_user_dir(SKILLS_DIRNAME)


def optional_dir() -> Path | None:
    """The uninstalled half of the library, shipped but not loaded."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / OPTIONAL_DIRNAME,
                      here.parent / OPTIONAL_DIRNAME):
        if candidate.is_dir():
            return candidate
    return None


def optional() -> list[Skill]:
    directory = optional_dir()
    return load_from(directory) if directory else []


def install(name: str) -> Path:
    """Copy one optional skill into the personal library, and load it there.

    Into ``~/.thot/skills`` rather than into the shipped tree: an install
    must survive `pip install --upgrade thot`, and must be removable by
    deleting a directory the user owns.
    """
    import shutil

    matches = [s for s in optional() if s.name == name]
    if not matches:
        matches = [s for s in optional() if name.lower() in s.name.lower()]
    if not matches:
        raise KeyError(name)

    chosen = matches[0]
    target = user_dir() / chosen.name
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(chosen.path.parent, target)
    return target


def uninstall(name: str) -> bool:
    """Remove a personally installed skill. Shipped ones are never touched."""
    import shutil

    target = user_dir() / name
    if not target.is_dir():
        return False
    shutil.rmtree(target)
    return True


def repo_dir(root: Path) -> Path:
    return Path(root) / ".thot" / SKILLS_DIRNAME


def bundled() -> list[Skill]:
    directory = library_dir()
    return load_from(directory) if directory else []


@dataclass(frozen=True)
class Rejected:
    """A skill that was found and refused, and why."""

    name: str
    path: Path
    verdict: str
    reasons: tuple[str, ...] = ()

    def summary(self) -> str:
        """Why it was refused. The name is the caller's to print."""
        return "; ".join(self.reasons[:3]) or self.verdict


def digest(skill: Skill) -> str:
    """The bytes of a skill's SKILL.md. Identity, not similarity."""
    import hashlib

    try:
        return hashlib.sha256(skill.path.read_bytes()).hexdigest()
    except OSError:
        return ""


def screen(
    skills: list[Skill], *, known: set[str] | None = None
) -> tuple[list[Skill], list[Rejected]]:
    """Refuse skills a repository supplied that the guard calls dangerous.

    The threat is specific to what Thot does. A skill is text handed to a
    model as instructions, and the repositories Thot reads are exactly the
    ones nobody has vouched for. A hostile repo dropping a SKILL.md into
    `.thot/skills/` would otherwise be writing part of the briefing.

    `known` holds the digests of skills Thot already ships. A file whose
    bytes match one of them *is* that file — Hermes's library holds 73 exact
    copies of Thot's — and flagging your own shipped skill as a community
    threat is a false positive that teaches people to ignore the real ones.
    """
    from thot.guard.skill_guard import scan_skill, should_allow_install

    known = known or set()
    kept: list[Skill] = []
    refused: list[Rejected] = []
    for skill in skills:
        if known and digest(skill) in known:
            kept.append(skill)
            continue
        try:
            result = scan_skill(skill.path.parent, source="community")
            allowed, reason = should_allow_install(result)
        except (OSError, ValueError):
            kept.append(skill)  # a scanner that cannot run must not censor
            continue
        if allowed:
            kept.append(skill)
        else:
            refused.append(
                Rejected(
                    name=skill.name,
                    path=skill.path,
                    verdict=result.verdict,
                    reasons=tuple(
                        dict.fromkeys(f.description for f in result.findings)
                    )[:3],
                )
            )
    return kept, refused


def discover_report(
    root: Path | None = None, *, sources: list[Path] | None = None
) -> tuple[list[Skill], list[Rejected]]:
    """Everything available here, plus what was refused and why."""
    refused: list[Rejected] = []
    if sources is None:
        directory = library_dir()
        sources = [p for p in (directory, user_dir()) if p is not None]
        trusted = len(sources)
        # What the other two programs have installed for this user. Screened,
        # not trusted: they come from public registries, which is the exact
        # case the guard exists for. Thot vouches for its own shipped
        # library and for nothing else.
        sources.extend(_agent_dirs())
        if root is not None:
            sources.append(repo_dir(root))
    else:
        trusted = len(sources)  # explicit sources are the caller's own choice

    by_name: dict[str, Skill] = {}
    vouched: set[str] = set()
    for index, source in enumerate(sources):
        found = load_from(source)
        if index >= trusted:  # supplied by another program, or by the repo
            found, rejected = screen(found, known=vouched)
            refused.extend(rejected)
        else:
            vouched.update(digest(skill) for skill in found)
        for skill in found:
            by_name[skill.name] = skill
    return sorted(by_name.values(), key=lambda s: (s.category, s.name)), refused


def _agent_dirs() -> list[Path]:
    """Hermes's and Prime's libraries. Empty when neither is installed."""
    try:
        from thot.fusion.skills import screened_dirs

        return screened_dirs()
    except Exception:
        return []


def discover(root: Path | None = None, *, sources: list[Path] | None = None) -> list[Skill]:
    """Everything available here, personal and repo skills overriding shipped ones."""
    return discover_report(root, sources=sources)[0]
