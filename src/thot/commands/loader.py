"""A markdown file is a slash command.

Ported from Prime Agent's `core/prompt-templates.ts`, keeping its
substitution grammar exactly — `$1`, `$@`, `$ARGUMENTS`, `${@:2}`,
`${@:2:3}` — because it is the same grammar Claude Code, Codex and
OpenCode use, and a user who already writes these should not have to
learn a fourth dialect.

Drop `audit-diff.md` into `.thot/commands/` and `/audit-diff HEAD~3`
becomes a thing you can type. The repository's own commands are screened
the way its skills are: a command file is prompt text, and a repository
under audit does not get to write the prompt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

COMMANDS_DIRNAME = "commands"
SUFFIX = ".md"

# Enough for a one-line hint next to the command name.
DESCRIPTION_CHARS = 72

_POSITIONAL = re.compile(r"\$(\d+)")
_SLICE = re.compile(r"\$\{@:(\d+)(?::(\d+))?\}")


@dataclass(frozen=True)
class Command:
    name: str
    description: str
    body: str
    path: Path
    argument_hint: str = ""
    trusted: bool = True

    def render(self, argument: str) -> str:
        return substitute(self.body, parse_args(argument))

    def usage(self) -> str:
        hint = f" {self.argument_hint}" if self.argument_hint else ""
        return f"/{self.name}{hint}"


def parse_args(text: str) -> list[str]:
    """Split on whitespace, but keep quoted runs together, as a shell would."""
    args: list[str] = []
    current = ""
    quote: str | None = None

    for char in text or "":
        if quote:
            if char == quote:
                quote = None
            else:
                current += char
        elif char in {'"', "'"}:
            quote = char
        elif char.isspace():
            if current:
                args.append(current)
                current = ""
        else:
            current += char
    if current:
        args.append(current)
    return args


def substitute(body: str, args: list[str]) -> str:
    """Fill the placeholders. Positionals first, so a value containing `$@`
    is never re-expanded — an argument is data, not template."""
    result = _POSITIONAL.sub(
        lambda match: args[int(match.group(1)) - 1]
        if 0 < int(match.group(1)) <= len(args) else "",
        body,
    )

    def slice_args(match: re.Match) -> str:
        start = max(0, int(match.group(1)) - 1)
        if match.group(2):
            return " ".join(args[start : start + int(match.group(2))])
        return " ".join(args[start:])

    result = _SLICE.sub(slice_args, result)
    joined = " ".join(args)
    return result.replace("$ARGUMENTS", joined).replace("$@", joined)


def _split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    try:
        data = yaml.safe_load(text[3:end])
    except yaml.YAMLError:
        return {}, text
    body = text[end + 4 :].lstrip("-").lstrip("\n")
    return (data if isinstance(data, dict) else {}), body


def _read(path: Path, *, trusted: bool) -> Command | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None

    data, body = _split_frontmatter(raw)
    description = str(data.get("description") or "").strip()
    if not description:
        first = next((line for line in body.splitlines() if line.strip()), "")
        description = first.strip("# ").strip()[:DESCRIPTION_CHARS]

    return Command(
        name=path.stem.strip().lower(),
        description=description,
        body=body.strip(),
        path=path,
        argument_hint=str(data.get("argument-hint") or data.get("argument_hint") or ""),
        trusted=trusted,
    )


def library_dir() -> Path | None:
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / COMMANDS_DIRNAME,
                      here.parent / "library"):
        if candidate.is_dir():
            return candidate
    return None


def user_dir() -> Path:
    from thot.paths import user_dir as thot_user_dir

    return thot_user_dir(COMMANDS_DIRNAME)


def repo_dir(root: Path) -> Path:
    return Path(root) / ".thot" / COMMANDS_DIRNAME


def load_from(directory: Path | None, *, trusted: bool = True) -> list[Command]:
    if directory is None or not directory.is_dir():
        return []
    found = [_read(path, trusted=trusted)
             for path in sorted(directory.glob(f"*{SUFFIX}"))]
    return [command for command in found if command is not None]


def _screen(commands: list[Command]) -> list[Command]:
    """Refuse a repository's command file when the guard calls it dangerous."""
    from thot.guard.skill_guard import scan_skill, should_allow_install

    kept = []
    for command in commands:
        try:
            allowed = should_allow_install(
                scan_skill(command.path, source="community")
            )[0]
        except (OSError, ValueError):
            allowed = True  # a scanner that cannot run must not censor
        if allowed:
            kept.append(command)
    return kept


def discover(root: Path | None = None) -> list[Command]:
    """Shipped, personal, then this repository's — later wins by name."""
    by_name: dict[str, Command] = {}
    for command in load_from(library_dir()) + load_from(user_dir()):
        by_name[command.name] = command
    if root is not None:
        for command in _screen(load_from(repo_dir(root), trusted=False)):
            by_name[command.name] = command
    return sorted(by_name.values(), key=lambda c: c.name)
