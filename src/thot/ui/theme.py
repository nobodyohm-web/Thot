"""Visual identity: palette, wordmark, and the few helpers that draw them.

Thot is the Egyptian scribe god, so the palette is gold on lapis. Everything
here is presentation only — no module in this package makes a decision.
"""

from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group
from rich.padding import Padding
from rich.text import Text

console = Console()

# Gold, light to deep. Applied across the wordmark as a vertical gradient.
GOLD = ["#FFE9A8", "#FFD479", "#F0B34E", "#D98E2B"]

LAPIS = "#4A7FC1"
INK = "#8A8578"
ACCENT = "#E8B44A"

WORDMARK = [
    "╔╦╗╦ ╦╔═╗╔╦╗",
    " ║ ╠═╣║ ║ ║ ",
    " ╩ ╩ ╩╚═╝ ╩ ",
]


def wordmark(subtitle: str = "") -> Group:
    """The wordmark as a gold gradient, subtitle set beside its middle line."""
    lines = []
    for index, line in enumerate(WORDMARK):
        colour = GOLD[min(index + 1, len(GOLD) - 1)]
        text = Text(line, style=f"bold {colour}")
        if subtitle and index == 1:
            text.append("   ")
            text.append(subtitle, style=ACCENT)
        lines.append(text)
    return Group(*lines)


def banner(subtitle: str = "", *, centred: bool = False) -> None:
    """Print the wordmark. Centred only on the first-run screen."""
    console.print()
    mark = wordmark(subtitle)
    console.print(Align.center(mark) if centred else _indent(mark))
    console.print()


def _indent(group: Group, spaces: int = 3) -> Group:
    pad = " " * spaces
    padded = []
    for item in group.renderables:
        text = item.copy() if isinstance(item, Text) else Text(str(item))
        padded.append(Text(pad) + text)
    return Group(*padded)


def rule(label: str = "") -> None:
    console.rule(Text(label, style=INK) if label else "", style=LAPIS)


FIELD_WIDTH = 9


def field(label: str, value: str, *, bullet: str = "▪") -> Text:
    """One `▪ label   value` line, values aligned on a fixed column.

    A label longer than the column keeps its own space rather than running
    into the value — the alignment is worth less than being able to read
    the line ("bac à sablelocal" is how this was found).
    """
    text = Text("   ")
    text.append(f"{bullet} ", style=LAPIS)
    text.append(label.ljust(FIELD_WIDTH) if len(label) < FIELD_WIDTH
                else f"{label}  ", style=INK)
    text.append(value, style="white")
    return text


def entry(name: str, detail: str, *, width: int = 24) -> Text:
    """A `name   detail` row whose detail column survives a long name.

    `field` aligns on a fixed narrow column, which is right for a handful of
    known labels and wrong for a catalogue: a name longer than the column ate
    the space and ran into its own description.
    """
    text = Text("   ")
    text.append(f"{name}  ", style=ACCENT)
    if len(name) + 2 < width:
        text.append(" " * (width - len(name) - 2))
    text.append(detail, style=INK)
    return text


def _notice(symbol: str, symbol_style: str, message: str, body_style: str) -> None:
    """Print an indented notice whose wrapped lines stay aligned.

    Padding is what keeps a long sentence from starting at column zero on its
    second line — the detail that separates a tidy terminal from a sloppy one.
    """
    text = Text()
    if symbol:
        text.append(f"{symbol} ", style=symbol_style)
    text.append(message, style=body_style)
    console.print(Padding(text, (0, 0, 0, 3)))


def hint(message: str) -> None:
    _notice("", "", message, INK)


def ok(message: str) -> None:
    _notice("✓", "#7BB661", message, "white")


def warn(message: str) -> None:
    _notice("▲", ACCENT, message, "white")


def error(message: str) -> None:
    _notice("✗", "#D06B5C", message, "white")
