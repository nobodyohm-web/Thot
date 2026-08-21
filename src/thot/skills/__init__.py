"""Skills: reusable method, written down once.

The format is the one Hermes Agent and Prime Agent share — a `SKILL.md` with
YAML frontmatter — so a skill written for either loads here unmodified, and a
skill written here works there.
"""

from thot.skills.loader import Skill, bundled, discover, load_from

__all__ = ["Skill", "bundled", "discover", "load_from"]
