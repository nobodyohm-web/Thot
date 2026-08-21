"""The seam between Thot, Hermes and Prime.

Three programs share this repository. Nothing here reimplements any of them:
this module finds them, runs them, and plugs each one's strength into the
others. Thot knows the code without asking a model; Hermes and Prime act.
"""

from thot.fusion.locate import (
    Part,
    hermes_root,
    parts,
    prime_root,
    repo_root,
)

__all__ = ["Part", "hermes_root", "prime_root", "repo_root", "parts"]
