"""The interactive shell: a prompt_toolkit input line over a rich-rendered body.

The input line carries the affordances that make a REPL feel alive — command and path
completion, history with ghost-text suggestions, and a bottom toolbar that always shows what
the session is holding (rules / candidates / account / events).  All *output* is rendered by
:mod:`decnique.ui.render` through the shared rich console, so the two layers stay cleanly split.

If prompt_toolkit is unavailable the shell degrades to plain :func:`input`, so the tool still
runs everywhere.
"""

from __future__ import annotations

import json
import shlex
import sys

from decnique.dsl.parser import DslError

from . import render
from .session import Session
from .theme import BULLET, console

# --- command catalogue --------------------------------------------------------------------

# verb -> (argument hint, one-line help).  Single source for completion, help, and dispatch.
COMMANDS: dict[str, tuple[str, str]] = {
    "load": ("[--all] [--deprecated] <paths…>", "load detections + candidates (default: GCP only, skips _deprecated)"),
    "account": ("<file.json>", "load the GCP account model (Reach / Log constraints)"),
    "events": ("<file.json>", "load an ordered event trace into the session"),
    "rules": ("[substr]", "list loaded detections (~ = approximate)"),
    "candidates": ("", "list loaded techniques and their footprints"),
    "show": ("<id>", "print canonical DSL for a detection or candidate"),
    "admits": ("<method>", "which detections could involve a method"),
    "summary": ("", "corpus statistics"),
    "event": ("<file.json>", "single event: which detections observe it"),
    "trace": ("[all]", "run every detection over the loaded trace (three-valued)"),
    "footprint": ("[id]", "match candidate footprint(s) against the loaded trace"),
    "blindspots": ("[perm…]", "reachable+logged events no rule observes  (SMT · M2)"),
    "stealth": ("[id]", "can a technique evade every rule?  (SMT · M3)"),
    "chains": ("[goal]", "stealthy privilege-escalation paths  (graph+SMT · M4)"),
    "config": ("[key [value|reset]]", "show or change settings (e.g. blindspots.explain rules|formula|both)"),
    "help": ("", "show this command list"),
    "quit": ("", "leave the shell"),
}

_PATH_CMDS = {"load", "account", "events", "event"}
_MATH_CMDS = {"blindspots", "stealth", "chains"}


# --- dispatch -----------------------------------------------------------------------------


def dispatch(s: Session, line: str) -> bool:
    """Run one command line. Returns False to exit the REPL."""
    try:
        parts = shlex.split(line)
    except ValueError as e:
        console.print(f"[err]parse error:[/err] {e}")
        return True
    if not parts:
        return True
    cmd, args = parts[0], parts[1:]
    try:
        if cmd in ("quit", "exit", "q"):
            return False
        elif cmd in ("help", "?"):
            print_help()
        elif cmd == "config":
            render.config(s, args)
        elif cmd == "load":
            s.load(args)
        elif cmd == "account":
            s.account_load(args[0]) if args else console.print("[muted]usage:[/muted] account <file.json>")
        elif cmd == "events":
            s.events_load(args[0]) if args else console.print("[muted]usage:[/muted] events <file.json>")
        elif cmd == "rules":
            render.rules(s, args[0] if args else None)
        elif cmd == "candidates":
            render.candidates(s)
        elif cmd == "show":
            render.show(s, args[0] if args else None)
        elif cmd == "admits":
            render.admits(s, args[0] if args else None)
        elif cmd == "summary":
            render.summary(s)
        elif cmd == "event":
            render.event(s, args[0] if args else None)
        elif cmd == "trace":
            render.trace(s, show_all=bool(args) and args[0] == "all")
        elif cmd == "footprint":
            render.footprint(s, args[0] if args else None)
        elif cmd == "blindspots":
            render.blindspots(s, args)
        elif cmd == "stealth":
            render.stealth(s, args[0] if args else None)
        elif cmd == "chains":
            render.chains(s, args[0] if args else None)
        else:
            console.print(f"[warn]unknown command {cmd!r}[/warn] — type [key]help[/key]")
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[err]input error:[/err] {e}")
    except DslError as e:
        console.print(f"[err]dsl error:[/err] {e}")
    except KeyError as e:
        console.print(f"[err]not found:[/err] {e}")
    return True


# --- banner + help ------------------------------------------------------------------------


def print_banner() -> None:
    from rich.panel import Panel
    from rich.text import Text

    body = Text()
    body.append("A DSL where a defender's ", style="")
    body.append("detections", style="key")
    body.append(" and an attacker's ", style="")
    body.append("techniques", style="accent")
    body.append(" meet on one event model —\nso you can ask what the rules ")
    body.append("miss", style="gap")
    body.append(".  Every answer is three-valued:\n")
    body.append("✓ yes", style="yes")
    body.append(" / ", style="muted")
    body.append("• no", style="no")
    body.append(" / ", style="muted")
    body.append("? don't-know", style="unknown")
    body.append("  — never a forced verdict.\n\n", style="muted")
    body.append("start:  ", style="muted")
    body.append("load <rules/>", style="key")
    body.append("  →  ", style="muted")
    body.append("account <a.json>", style="key")
    body.append("  →  ", style="muted")
    body.append("blindspots", style="key")
    body.append("      ·  ", style="muted")
    body.append("help", style="key")
    body.append(" for everything", style="muted")
    console.print(
        Panel(body, title=Text("decnique", style="brand"), title_align="left",
              border_style="rule", padding=(1, 2))
    )


def print_help() -> None:
    from rich.table import Table
    from rich.text import Text

    groups = [
        ("load state", ["load", "account", "events"]),
        ("inspect", ["rules", "candidates", "show", "admits", "summary"]),
        ("run over a trace", ["event", "trace", "footprint"]),
        ("coverage — the math", ["blindspots", "stealth", "chains"]),
        ("shell", ["config", "help", "quit"]),
    ]
    for heading, verbs in groups:
        t = Table(box=None, padding=(0, 2, 0, 0), show_header=False, pad_edge=False)
        t.add_column(style="key", no_wrap=True)
        t.add_column(style="muted", no_wrap=True)
        t.add_column()
        for v in verbs:
            hint, desc = COMMANDS[v]
            t.add_row(v, hint, desc)
        console.print(Text(f"{BULLET} {heading}", style="title"))
        console.print(t)


# --- prompt_toolkit front (with a plain fallback) -----------------------------------------


def _term_width(default: int = 80) -> int:
    import shutil

    return max(24, shutil.get_terminal_size((default, 24)).columns)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _status_chips(s: Session) -> str:
    """The `rules · candidates · account · events` chips for the bottom status line."""

    def chip(label: str, value: str, on: bool) -> str:
        cls = "tb.on" if on else "tb.off"
        return f"<{cls}>{label}</{cls}> <tb.val>{_esc(value)}</tb.val>"

    rules = str(len(s.lib.detections)) if s.lib else "—"
    cands = str(len(s.lib.bundle.candidates)) if s.lib else "—"
    acct = s.account.name if s.account else "—"
    evs = str(len(s.events)) if s.events else "—"
    return "   ·   ".join([
        chip("rules", rules, bool(s.lib)),
        chip("candidates", cands, bool(s.lib)),
        chip("account", acct, bool(s.account)),
        chip("events", evs, bool(s.events)),
    ])


def _make_completer():
    from prompt_toolkit.completion import Completer, Completion, PathCompleter
    from prompt_toolkit.document import Document

    path_completer = PathCompleter(expanduser=True)

    class DecCompleter(Completer):
        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            stripped = text.lstrip()
            if " " not in stripped:  # completing the verb
                word = document.get_word_before_cursor(WORD=True)
                for name, (hint, desc) in COMMANDS.items():
                    if name.startswith(word):
                        yield Completion(name, start_position=-len(word),
                                         display=name, display_meta=desc)
                return
            cmd = stripped.split()[0]
            if cmd in _PATH_CMDS:  # completing a filesystem path
                token = text[text.rfind(" ") + 1:]
                sub = Document(token, len(token))
                yield from path_completer.get_completions(sub, complete_event)

    return DecCompleter()


def _repl_ptk(s: Session) -> int:
    import os

    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.styles import Style

    style = Style.from_dict({
        "frame": "#6c6c6c",           # the rounded input box
        "prompt": "bold cyan",        # the ›
        "bottom-toolbar": "noreverse",  # the status line under the box — no filled bar
        "placeholder": "#585858 italic",
        "tb.on": "cyan",
        "tb.off": "#6c6c6c",
        "tb.val": "#bcbcbc",
    })

    def message() -> HTML:
        """Top border of the box, then the input line's left edge:  ╭───╮ / │ › ."""
        w = _term_width()
        top = "╭" + "─" * (w - 2) + "╮"
        return HTML(f"<frame>{top}</frame>\n<frame>│</frame> <prompt>›</prompt> ")

    def rprompt() -> HTML:
        """Close the input line's right edge."""
        return HTML("<frame>│</frame>")

    def bottom_toolbar() -> HTML:
        """Bottom border of the box, then the status chips under it."""
        w = _term_width()
        base = "╰" + "─" * (w - 2) + "╯"
        return HTML(f"<frame>{base}</frame>\n  {_status_chips(s)}")

    history_path = os.path.join(os.path.expanduser("~"), ".decnique_history")
    session: PromptSession = PromptSession(
        message=message,
        rprompt=rprompt,
        bottom_toolbar=bottom_toolbar,
        placeholder=HTML('<placeholder>type a command — try "blindspots", "rules", or "help"</placeholder>'),
        history=FileHistory(history_path),
        auto_suggest=AutoSuggestFromHistory(),
        completer=_make_completer(),
        complete_while_typing=True,
        reserve_space_for_menu=0,  # the box hugs the input; the completion menu expands it on demand
        erase_when_done=True,  # the box lives only around the active input; scrollback stays clean
        style=style,
    )
    while True:
        try:
            line = session.prompt()
        except EOFError:
            break
        except KeyboardInterrupt:
            continue
        if line.strip():  # echo the submitted command cleanly above its output (Claude-Code style)
            console.print(f"[brand]›[/brand] {line.strip()}")
        if not dispatch(s, line):
            break
    console.print("[muted]bye[/muted]")
    return 0


def _repl_plain(s: Session) -> int:
    while True:
        try:
            line = input("decnique > ")
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        if not dispatch(s, line):
            break
    return 0


def repl(s: Session) -> int:
    print_banner()
    if not sys.stdin.isatty():  # piped input → a plain reader that honours EOF
        return _repl_plain(s)
    try:
        import prompt_toolkit  # noqa: F401
    except ImportError:
        return _repl_plain(s)
    return _repl_ptk(s)


# --- entry point --------------------------------------------------------------------------

_DELEGATED = {"parse", "fmt", "import", "event", "trace", "coverage", "admits", "show"}
_DELEGATED_FLAGS = {"-e", "-o", "-a", "--account", "--yaml", "--permission"}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    s = Session()
    if not argv:
        return repl(s)
    # richer flag forms belong to the batch CLI
    if argv[0] in _DELEGATED and _DELEGATED_FLAGS & set(argv):
        from decnique.cli import main as cli_main

        return cli_main(argv)
    # otherwise run one command and exit (one-shot)
    dispatch(s, " ".join(shlex.quote(a) for a in argv))
    return 0
