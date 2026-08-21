"""Visual identity: palette, wordmark, and the few helpers that draw them.

Thot is the Egyptian scribe god, so the palette is gold on lapis. Everything
here is presentation only — no module in this package makes a decision.
"""

from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group
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


FIELD_WIDTH = 7


def field(label: str, value: str, *, bullet: str = "▪") -> Text:
    """One `▪ label   value` line, values aligned on a fixed column."""
    text = Text("   ")
    text.append(f"{bullet} ", style=LAPIS)
    text.append(label.ljust(FIELD_WIDTH), style=INK)
    text.append(value, style="white")
    return text


def hint(message: str) -> None:
    console.print(Text(f"   {message}", style=INK))


def ok(message: str) -> None:
    text = Text("   ")
    text.append("✓ ", style="#7BB661")
    text.append(message, style="white")
    console.print(text)


def warn(message: str) -> None:
    text = Text("   ")
    text.append("▲ ", style=ACCENT)
    text.append(message, style="white")
    console.print(text)


def error(message: str) -> None:
    text = Text("   ")
    text.append("✗ ", style="#D06B5C")
    text.append(message, style="white")
    console.print(text)
