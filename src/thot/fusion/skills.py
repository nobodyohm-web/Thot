"""One skill catalogue across the three programs.

They already agree on the format — `SKILL.md` with YAML frontmatter, one
directory per skill — which is the only reason this is possible at all. What
differs is where each looks:

    thot    la bibliothèque livrée + `~/.thot/skills`
    hermes  la sienne livrée + `~/.hermes/skills`
    prime   la sienne livrée + les chemins de `settings.skills`

So the merge is not a copy. Copies drift, and a skill installed twice is a
skill patched once. Each program is pointed at the others' directories, and
the files stay where their owner put them.

One asymmetry is deliberate. Skills that Hermes installs come from public
registries — skills.sh, GitHub, ClawHub — so Thot reads them *screened* by
its own guard, in the same rank as a skill found in an audited repository.
Its own shipped library is the only one it vouches for.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from thot.fusion.wiring import hermes_home, prime_settings_path

SKILLS_DIRNAME = "skills"


def hermes_user_skills() -> Path:
    return hermes_home() / SKILLS_DIRNAME


def hermes_bundled_skills() -> Path | None:
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        return None
    directory = root / SKILLS_DIRNAME
    return directory if directory.is_dir() else None


def prime_bundled_skills() -> Path | None:
    from thot.fusion.locate import prime_root

    root = prime_root()
    if root is None:
        return None
    directory = root / "packages" / "coding-agent" / SKILLS_DIRNAME
    return directory if directory.is_dir() else None


def thot_shipped_skills() -> Path | None:
    from thot.skills.loader import library_dir

    return library_dir()


def thot_user_skills() -> Path:
    from thot.skills.loader import user_dir

    return user_dir()


def screened_dirs() -> list[Path]:
    """The other programs' libraries that Thot can actually run, under guard.

    Two exclusions, both deliberate.

    Hermes's *bundled* library is left out because Thot ships that same
    library already: reading it twice adds a second name for every entry and
    nothing else.

    Prime's bundled skills are left out because they document Prime's own
    IPython kernel — `edit(old_str, new_str)`, `refine()`. Thot ported that
    kernel but not those functions, so loading them would have the model
    call something that does not exist. They stay in the catalogue, where
    knowing they exist is useful, and out of discovery, where believing in
    them is not.
    """
    found = [hermes_user_skills()]
    return [path for path in found if path is not None and path.is_dir()]


def not_portable() -> list[str]:
    """Catalogued but never loaded into Thot, and why it is one list."""
    return sorted(_names(prime_bundled_skills()))


# -- what exists -------------------------------------------------------------


@dataclass(frozen=True)
class Library:
    program: str
    kind: str  # "livrée" | "installée"
    path: Path
    count: int

    def line(self) -> str:
        return f"{self.program:<8} {self.kind:<10} {self.count:>4}  {self.path}"


def _count(path: Path | None) -> int:
    if path is None or not path.is_dir():
        return 0
    return sum(1 for _ in path.rglob("SKILL.md"))


def libraries() -> list[Library]:
    entries = [
        ("thot", "livrée", thot_shipped_skills()),
        ("thot", "installée", thot_user_skills()),
        ("hermes", "livrée", hermes_bundled_skills()),
        ("hermes", "installée", hermes_user_skills()),
        ("prime", "livrée", prime_bundled_skills()),
    ]
    return [
        Library(program, kind, path, _count(path))
        for program, kind, path in entries
        if path is not None
    ]


@dataclass(frozen=True)
class Entry:
    """One skill, and which of the three can reach it today."""

    name: str
    programs: tuple[str, ...]

    @property
    def shared(self) -> bool:
        return len(self.programs) > 1

    def line(self) -> str:
        return f"{self.name:<34} {', '.join(self.programs)}"


def _names(path: Path | None) -> set[str]:
    if path is None or not path.is_dir():
        return set()
    return {found.parent.name for found in path.rglob("SKILL.md")}


def catalogue() -> list[Entry]:
    """Every skill any of the three can see, and who sees it."""
    by_program = {
        "thot": _names(thot_shipped_skills()) | _names(thot_user_skills()),
        "hermes": _names(hermes_bundled_skills()) | _names(hermes_user_skills()),
        "prime": _names(prime_bundled_skills()),
    }
    for path in _prime_extra_paths():
        by_program["prime"] |= _names(path)

    everything: dict[str, list[str]] = {}
    for program, names in by_program.items():
        for name in names:
            everything.setdefault(name, []).append(program)
    return [
        Entry(name, tuple(sorted(programs)))
        for name, programs in sorted(everything.items())
    ]


def only_in(program: str) -> list[str]:
    """Skills nobody else can reach — what sharing would actually add."""
    return [e.name for e in catalogue() if e.programs == (program,)]


# -- pointing each program at the others -------------------------------------


def _prime_extra_paths() -> list[Path]:
    from thot.fusion.wiring import _read_json

    settings = _read_json(prime_settings_path()) or {}
    listed = settings.get("skills")
    if not isinstance(listed, list):
        return []
    return [Path(str(item)).expanduser() for item in listed if isinstance(item, str)]


def shared_with_prime() -> list[Path]:
    """The directories Thot hands to Prime — the superset, not both copies.

    Measured, not assumed. Pointing Prime at Thot's library alone works;
    at Hermes's alone works; at both, the model refuses to answer at all.
    Thot's 90 and Hermes's 83 overlap by 73 byte-identical files, so the
    pair loads the same skill twice and buys one name — `polymarket` — for
    a doubled system prompt.

    Prime takes directories, not names, so there is no partial answer. The
    unique Hermes skills stay with Hermes until `thot skills install` puts
    them in Thot's own library, which is shared.
    """
    found = [thot_shipped_skills(), thot_user_skills()]
    return [path for path in found if path is not None and path.is_dir()]


@dataclass(frozen=True)
class Step:
    target: Path
    action: str
    detail: str = ""

    def line(self) -> str:
        detail = f" — {self.detail}" if self.detail else ""
        return f"{self.action:<14} {self.target}{detail}"

    @property
    def changes(self) -> bool:
        return self.action != "déjà en place"


def plan_share() -> list[Step]:
    wanted = {str(path) for path in shared_with_prime()}
    current = {str(path) for path in _prime_extra_paths()}
    missing = wanted - current
    if not missing:
        return [Step(prime_settings_path(), "déjà en place",
                     f"{len(wanted)} chemin(s) partagé(s)")]
    return [Step(prime_settings_path(), "mettre à jour",
                 f"ajoute {len(missing)} chemin(s) à settings.skills")]


def share() -> list[Step]:
    """Add Thot's and Hermes's libraries to Prime's own search paths.

    Only Prime needs writing to. Thot reads the other two through
    `screened_dirs()`, and Hermes resolves every skill path against its own
    directory and refuses anything that escapes it — so a symlink out to a
    shared tree would be rejected, and a copy is exactly the drift this
    module exists to avoid.
    """
    from thot.fusion.wiring import _read_json, _write_json

    steps = plan_share()
    if not steps[0].changes:
        return steps

    path = prime_settings_path()
    settings = _read_json(path) or {}
    if path.is_file():
        backup = path.with_suffix(".json.thot-backup")
        if not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    listed = settings.get("skills")
    existing = [item for item in listed if isinstance(item, str)] if isinstance(listed, list) else []
    for directory in shared_with_prime():
        if str(directory) not in existing:
            existing.append(str(directory))
    settings["skills"] = existing
    _write_json(path, settings)
    return steps
