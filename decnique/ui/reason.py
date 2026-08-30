"""The reasoning log — the tool *thinking out loud*.

Every `ask` verb (`ask blindspots`, `ask stealth`, `ask chains`) runs a small proof.  Rather than print a
verdict from nowhere, the :class:`Reasoner` narrates the actual checks as they happen: the
reachability/logging pre-conditions, the exact SMT formula being solved, whether it came back
SAT or UNSAT, and — the honest heart of it — the *replay-verification* where each proposed
witness is pushed back through the concrete oracle to confirm no rule fires.

Nothing here computes an answer; it only *reports* the checks the engine already performs, at
the granularity of the engine's own public calls.  When the terminal is a TTY, a transient
spinner marks the work in flight; when it is piped, the spinner is silently skipped and only
the step lines remain, so logs stay clean in a file.
"""

from __future__ import annotations

from contextlib import contextmanager

from rich.panel import Panel
from rich.text import Text

from .theme import ARROW, BULLET, CHECK, CROSS, DIAMOND, DOT, console

_PAD = "  "  # one indent level


class Reasoner:
    """Emits indented, glyph-led reasoning steps to the shared console."""

    def __init__(self) -> None:
        self._depth = 1

    # -- framing ---------------------------------------------------------------------------

    def header(self, title: str, formula: str | None = None, subtitle: str | None = None) -> None:
        """Open a verb with its name and the formula it is about to discharge."""
        body = Text()
        if formula:
            body.append(formula, style="formula")
        if subtitle:
            if formula:
                body.append("\n")
            body.append(subtitle, style="muted")
        console.print(
            Panel(
                body if (formula or subtitle) else Text(title, style="brand"),
                title=Text(title, style="brand"),
                title_align="left",
                border_style="rule",
                padding=(0, 1),
            )
        )

    def section(self, label: str, note: str | None = None) -> None:
        """A ▸ heading for one probed item (a permission, a technique, a hop)."""
        line = Text(f"{BULLET} ", style="accent")
        line.append(label, style="title")
        if note:
            line.append(f"   {note}", style="muted")
        console.print(line)
        self._depth = 2

    # -- step lines ------------------------------------------------------------------------

    def _line(self, glyph: str, glyph_style: str, text: str, text_style: str = "") -> None:
        t = Text(_PAD * self._depth)
        t.append(f"{glyph} ", style=glyph_style)
        t.append(text, style=text_style)
        console.print(t)

    def ok(self, text: str) -> None:
        self._line(CHECK, "step.ok", text)

    def no(self, text: str) -> None:
        self._line(CROSS, "step.no", text, "muted")

    def work(self, text: str) -> None:
        self._line("⟳", "step.work", text)

    def math(self, text: str) -> None:
        self._line("Σ", "step.math", text)

    def note(self, text: str) -> None:
        self._line(ARROW, "muted", text, "muted")

    def replay(self, text: str, sound: bool = True) -> None:
        """The soundness line — a witness pushed back through the concrete oracle."""
        self._line(ARROW, "step.ok" if sound else "warn", text, "" if sound else "warn")

    def verdict_gap(self, text: str) -> None:
        self._line(DIAMOND, "gap", text, "gap")

    def verdict_safe(self, text: str) -> None:
        self._line(DOT, "safe", text, "safe")

    def verdict_muted(self, text: str) -> None:
        self._line(DOT, "muted", text, "muted")

    def blank(self) -> None:
        console.print()

    # -- work in flight --------------------------------------------------------------------

    fast: bool = False  # set by a verb that runs thousands of steps: no spinners

    @contextmanager
    def thinking(self, label: str):
        """Show a transient spinner while a blocking engine call runs (no-op when piped)."""
        if self.fast:
            yield
            return
        with console.status(Text(label, style="muted"), spinner="dots"):
            yield
