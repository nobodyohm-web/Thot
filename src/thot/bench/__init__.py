"""Measuring Thot against code whose answers are already known.

The one part of this program that is not Thot judging Thot. See
`corpus.py` for why that distinction is the whole point.
"""

from thot.bench.corpus import Case, NotACorpus, Suite, load, load_all, verified
from thot.bench.run import DEFAULT_CORPUS, measure, measure_all
from thot.bench.score import Score, Tally, combine, score

__all__ = [
    "Case", "DEFAULT_CORPUS", "NotACorpus", "Score", "Suite", "Tally",
    "combine", "load", "load_all", "measure", "measure_all", "score",
    "verified",
]
