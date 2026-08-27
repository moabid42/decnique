"""One place for every colour, glyph, and three-valued rendering the UI uses.

The whole tool speaks *three-valued*: yes / no / don't-know.  Keeping the palette and the
glyphs here means every table, every reasoning line, and every summary agree on what green,
what amber, and what "◆" mean — so a reader learns the vocabulary once.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# --- palette ------------------------------------------------------------------------------

THEME = Theme(
    {
        # verdicts (the three-valued core)
        "yes": "bold green",
        "no": "dim",
        "unknown": "bold yellow",
        # status / provenance
        "exact": "green",
        "approx": "yellow",
        "gap": "bold red",
        "safe": "green",
        # structure
        "brand": "bold cyan",
        "title": "bold",
        "muted": "grey58",
        "rule": "grey42",
        "key": "cyan",
        "accent": "magenta",
        "ok": "green",
        "warn": "yellow",
        "err": "bold red",
        # reasoning log
        "step.ok": "green",
        "step.no": "grey58",
        "step.work": "cyan",
        "step.math": "magenta",
        "step.hit": "bold red",
        "formula": "italic magenta",
    }
)

console = Console(theme=THEME, highlight=False)

# --- glyphs -------------------------------------------------------------------------------

# A calm, consistent set.  Colour carries the meaning; the glyph reinforces it.
CHECK = "✓"
CROSS = "✗"
DOT = "•"
DIAMOND = "◆"
ARROW = "↳"
BULLET = "▸"
GEAR = "⚙"
SIGMA = "Σ"


def tri(value: object) -> str:
    """A three-valued verdict as inline rich markup: yes / no / unknown."""
    if value is True:
        return f"[yes]{CHECK} yes[/yes]"
    if value is False:
        return f"[no]{DOT} no[/no]"
    return f"[unknown]? unknown[/unknown]"


def tri_word(value: object) -> tuple[str, str]:
    """(text, style) for a bare three-valued cell inside a table."""
    if value is True:
        return (f"{CHECK} yes", "yes")
    if value is False:
        return (f"{DOT} no", "no")
    return ("? unknown", "unknown")


def approx_word(approximate: bool) -> tuple[str, str]:
    """(text, style) for the exact/approximate provenance tag."""
    return ("~approx", "approx") if approximate else ("exact", "exact")
