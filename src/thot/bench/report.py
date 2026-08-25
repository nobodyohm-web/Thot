"""A bench score, on a terminal — and what the number on it means.

`J = TPR − FPR`, Youden's J: of the vulnerable cases, the share Thot named,
minus, of the safe ones, the share it flagged anyway. The corpus is balanced
half and half, which fixes the scale: **0 is a coin flip** — flag every file
and you score TPR 100 %, FPR 100 %, J 0 — and **J is signed, so a negative
one is a rule that is inverted**. It fires on the safe half and walks past
the vulnerable half, and it is costing points rather than failing to earn
them. That is not a hypothetical: `xml_unsafe_parse` measured −100 % over a
hundred cases for as long as it existed, and precision/recall showed it as a
blank cell, because a rule with no true positives has undefined precision
and a blank reads as *no data*. No J is printed here without its sign unless
it is exactly zero, where the sign would be the one thing it cannot mean.

One count is deliberately not left to the sort: the categories where `tp`
and `fp` are both zero. Thot produces **nothing at all** on those — no right
answer and no wrong one — and they land at J exactly 0, which on this scale
reads as a coin flip and is not one. **54 of the 61 categories are in that
state**, on all three suites, at the default floor. It is the actionable
number on this screen, because it says *a rule is missing* and not *a
threshold is off*, and a table ordered by J alone buries every one of them
in an indistinguishable middle.

Three of those fifty-four are a different fault and worth separating: at
`--floor info` the count is 51, so Thot does compute something for them and
the display threshold eats all of it. That is a rule which fires and is
scored `medium`-and-below, not a rule that does not exist.
"""

from __future__ import annotations

from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from thot.bench.score import Score, Tally, already_claimed, misnamed
from thot.ui import theme

# J is the one number here that carries a sign, so it is the one that gets a
# colour. Red is not "bad": it is *inverted*, which is a different repair
# from a low score and a cheaper one.
GOOD = "#7BB661"
BAD = "#D06B5C"


def silent(score: Score) -> list[str]:
    """Categories Thot said nothing about — neither right nor wrong."""
    return sorted(name for name, tally in score.by_category.items()
                  if tally.tp == 0 and tally.fp == 0)


def percent(value: float, *, sign: bool = False, digits: int = 1) -> str:
    """A rate, in the register the rest of the program prints in.

    A space before the `%`, French typography, and no `+` on an exact zero:
    a `+0 %` in every second row of the table is the sign meaning nothing in
    the one place it has nothing to say.
    """
    mark = "+" if sign and value > 0 else ""
    return f"{mark}{value * 100:.{digits}f} %"


def _style(youden: float) -> str:
    if youden > 0:
        return GOOD
    return BAD if youden < 0 else theme.INK


def _state(tally: Tally, claimed: bool = False, seen: int = 0) -> tuple[str, str]:
    """The one-word reading of a row, and how to colour it.

    Silence has three causes and they are three different jobs.

    `seen` counts the vulnerable cases Thot flagged under some *other*
    class, and it is checked first because it is the only one of the three
    that is not work: the rule fires on exactly the right file and names the
    weakness differently. Nine of BenchProctor's thirty-seven silent
    categories are in this state — each was instructed as a mapping to add
    and each was refused on the taxonomy, because the corpus writes
    different CWEs on code Thot cannot tell apart (the same
    `JsonResponse(..., repr(locals()))` is labelled CWE-200, CWE-209 and
    CWE-489 in three different categories). Reporting them as "aucune règle"
    sent a reader to write a rule that already exists and already works.

    `claimed` then says a rule is mapped to this class and never matches the
    code — a pattern to widen. Without either there is no rule at all, and
    something has to be written from nothing.
    """
    if tally.youden < 0:
        return "inversée", BAD
    if tally.tp == 0 and tally.fp == 0:
        if seen:
            return "mal nommée", theme.ACCENT
        if claimed:
            return "règle muette", theme.ACCENT
        return "aucune règle", theme.ACCENT
    return "", theme.INK


def _headline(score: Score) -> Text:
    """One suite as one line: three numbers and what they cost in time."""
    text = theme.entry(score.suite, "", width=12)
    # Right-aligned: `9.6 %` and `10.1 %` differ by a character, and left as
    # they came the three suites' J columns did not line up under each other,
    # which is the one comparison these lines exist to make.
    text.append(f"TPR {percent(score.tpr):>7}   FPR {percent(score.fpr):>7}   ",
                style="white")
    text.append(f"J {percent(score.youden, sign=True):>7}",
                style=_style(score.youden))
    text.append(f"   {score.seconds:.1f} s", style=theme.INK)
    return text


def _table(score: Score, limit: int) -> Table:
    """The worst categories, worst first.

    Ratios and not just rates: `0/150` says how much evidence is behind the
    percentage, and a category wrong on four cases should not read like a
    category wrong on a hundred and fifty.
    """
    table = Table(show_lines=False, header_style="bold",
                  border_style=theme.LAPIS)
    table.add_column("Catégorie", no_wrap=True, style=theme.ACCENT)
    table.add_column("CWE", justify="right", no_wrap=True)
    table.add_column("J", justify="right", no_wrap=True)
    table.add_column("détectés", justify="right", no_wrap=True)
    table.add_column("inventés", justify="right", no_wrap=True)
    table.add_column("état", no_wrap=True)

    # Ranked exactly as `thot evolve --from-bench` ranks its goals, and for
    # the same reason: 54 of the 61 categories sit at J = 0, so without a
    # tie-break the twelve rows shown are twelve alphabetical accidents. The
    # ones worth reading first are those where a rule already claims the
    # class and never fires — a table that hides them under `argument_
    # injection` is a table nobody can act on.
    claims = already_claimed(score)
    seen = misnamed(score)
    # A category Thot already fires on is *not* the cheap repair the ranking
    # is looking for — it is the one that cannot be repaired honestly at all.
    # Preferring it on `claims` alone put `directory_listing_exposure` at the
    # top of the table, which is the one row on it nobody should start with.
    for name, tally in score.worst(limit,
                                   prefer=lambda n: claims(n) and not seen(n)):
        state, colour = _state(tally, claims(name), score.seen.get(name, 0))
        table.add_row(
            name,
            str(score.cwe.get(name, 0) or "—"),
            Text(percent(tally.youden, sign=True, digits=0),
                 style=_style(tally.youden)),
            f"{tally.tp}/{tally.positives}",
            f"{tally.fp}/{tally.negatives}",
            Text(state, style=colour),
        )
    return table


def render(scores: list[Score], total: Score, *, limit: int = 12) -> None:
    """Print the measurement: suites, worst categories, then the headline.

    The headline comes last on purpose. A single J is the number that gets
    quoted and the number that decides nothing — what to do next is in the
    two lines above it, and a reader who stops at the first bold percentage
    has read the only part of this screen that is not actionable.
    """
    theme.console.print()
    if len(scores) > 1:
        for one in sorted(scores, key=lambda s: s.youden):
            theme.console.print(_headline(one))
        theme.console.print()

    if not total.by_category:
        theme.warn("Aucune catégorie mesurée : la suite n'a produit aucun cas.")
        return

    # Indented to the column every other line in this program starts at; a
    # table flush against the left margin reads as belonging to another
    # program's output.
    theme.console.print(Padding(_table(total, limit), (0, 0, 0, 3)))
    measured = len(total.by_category)
    if measured > limit:
        shown = f"{limit} catégorie{'s' if limit > 1 else ''}"
        theme.hint(f"{shown} sur {measured} — les pires d'abord "
                   f"(`--limit` pour en voir plus).")
    theme.console.print()

    quiet = silent(total)
    if quiet:
        # Agreement written out rather than papered over with `(s)`: these two
        # lines are the only ones on the screen that say what to *do*, and
        # «1 catégories sont inversées» is how a reader learns to skim them.
        head = (f"1 catégorie sur {measured} ne produit rien du tout"
                if len(quiet) == 1 else
                f"{len(quiet)} catégories sur {measured} ne produisent rien "
                f"du tout")
        theme.warn(f"{head} : ni vrai positif, ni faux positif.")
        # Split, because the two halves are different work and the cheaper
        # half is the one worth naming. A rule already mapped to the class
        # exists and never matches — a pattern to widen. The rest have to be
        # written from nothing. Lumping them together as "il manque une
        # règle" was wrong about the seven the table now lists first.
        claims = already_claimed(total)
        misnamed = [name for name in quiet if total.seen.get(name, 0)]
        rest = [name for name in quiet if not total.seen.get(name, 0)]
        mute = [name for name in rest if claims(name)]
        absent = [name for name in rest if not claims(name)]
        if misnamed:
            theme.hint(f"vue mais mal nommée — Thot tire déjà sur ces cas et "
                       f"annonce une autre classe ({len(misnamed)}) : "
                       + ", ".join(misnamed[:10])
                       + (" …" if len(misnamed) > 10 else ""))
        if mute:
            theme.hint(f"règle muette — elle existe et ne matche jamais "
                       f"({len(mute)}) : " + ", ".join(mute[:10])
                       + (" …" if len(mute) > 10 else ""))
        if absent:
            theme.hint(f"aucune règle pour la classe ({len(absent)}) : "
                       + ", ".join(absent[:10])
                       + (" …" if len(absent) > 10 else ""))
    inverted = sorted(name for name, t in total.by_category.items()
                      if t.youden < 0)
    if inverted:
        head = ("1 catégorie est *inversée* — elle signale"
                if len(inverted) == 1 else
                f"{len(inverted)} catégories sont *inversées* — elles signalent")
        named = ", ".join(inverted[:6]) + (" …" if len(inverted) > 6 else "")
        theme.error(f"{head} le code sain : {named}")
    theme.console.print()

    flat = total.flat
    theme.console.print(theme.field("TPR", percent(total.tpr)))
    theme.console.print(theme.field("FPR", percent(total.fpr)))
    theme.console.print(theme.field("J", percent(total.youden, sign=True)))
    theme.console.print(theme.field(
        "cas", f"tp={flat.tp}  fp={flat.fp}  fn={flat.fn}  tn={flat.tn}"))
    theme.console.print(theme.field("temps", f"{total.seconds:.1f} s"))
    theme.console.print()
    # Said every time, because the sign is the whole reading and a reader who
    # takes J for a percentage of anything will read −100 % as "nearly none".
    theme.hint("J = TPR − FPR : 0 = pile ou face, négatif = règle inversée.")
    theme.console.print()
