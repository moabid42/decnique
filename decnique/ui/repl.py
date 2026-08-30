"""The interactive shell: a prompt_toolkit input line over a rich-rendered body.

The input line carries the affordances that make a REPL feel alive — object / verb / path
completion, history with ghost-text suggestions, and a bottom toolbar that always shows what
the session is holding (rules / candidates / account / events).  All *output* is rendered by
:mod:`decnique.ui.render` through the shared rich console, so the two layers stay cleanly split.

If prompt_toolkit is unavailable the shell degrades to plain :func:`input`, so the tool still
runs everywhere.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from decnique.dsl.parser import DslError

from .commands import OBJECTS, SHELL, Obj, Verb, settings_prefix
from .session import Session
from .theme import BULLET, console

# --- command catalogue --------------------------------------------------------------------
# The grammar is `<object> <verb> [args…]`; :mod:`commands` holds every object and verb.

# a line starting with one of these opens a DSL block, read until its braces close
DSL_KEYWORDS = ("detection", "candidate", "check", "ruleset")


def is_dsl(line: str) -> bool:
    """True when the line begins a DSL item — `check foo {` — rather than the `check` verb."""
    words = line.split()
    return len(words) >= 2 and words[0] in DSL_KEYWORDS and "{" in line


def block_open(text: str) -> bool:
    """True while a DSL block still has an unclosed `{` (strings and // comments skipped)."""
    depth, i, n = 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return depth > 0


def read_block(first: str, more) -> str:
    """Keep reading lines through `more()` until the block's braces balance (interpreter style)."""
    text = first
    while block_open(text):
        line = more()
        if line is None:
            break
        text += "\n" + line
    return text


# --- dispatch -----------------------------------------------------------------------------


def resolve(words: list[str]) -> tuple[Obj, Verb, list[str]] | str:
    """`<object> [verb] [args…]` → (object, verb, args), or a message when it does not parse."""
    obj = OBJECTS.get(words[0])
    if obj is None:
        return f"unknown command {words[0]!r} — type [key]help[/key]"
    if len(words) == 1:
        if obj.default is None:
            return f"[key]{obj.name}[/key] needs a verb: " + ", ".join(obj.verbs) + f"   (help {obj.name})"
        return obj, obj.verbs[obj.default], []
    verb = obj.verb(words[1])
    if verb is None:
        if obj.default is not None:  # `rules ~foo` → the default verb with the rest as arguments
            return obj, obj.verbs[obj.default], words[1:]
        return f"[key]{obj.name}[/key] has no verb {words[1]!r}: " + ", ".join(obj.verbs) + f"   (help {obj.name})"
    return obj, verb, words[2:]


def dispatch(s: Session, line: str) -> bool:
    """Run one command line (or a whole DSL block). Returns False to exit the REPL."""
    if is_dsl(line):
        try:
            s.define(line)
        except DslError as e:
            console.print(f"[err]dsl error:[/err] {e}")
        return True
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
            print_help(s, args)
        elif cmd == "config":
            if args and (args[0] in OBJECTS or args[0] in SHELL):
                print_help(s, args)
            else:
                from . import render

                render.config(s, args)
        elif cmd in ("clear", "cls"):
            console.clear()
        else:
            hit = resolve(parts)
            if isinstance(hit, str):
                console.print(f"[warn]{hit}[/warn]")
            else:
                obj, verb, rest = hit
                verb.run(s, rest)
    except (OSError, json.JSONDecodeError, ValueError) as e:  # ValueError: bad account / schema
        console.print(f"[err]input error:[/err] {e}")
    except DslError as e:
        console.print(f"[err]dsl error:[/err] {e}")
    except KeyError as e:
        console.print(f"[err]not found:[/err] {e}")
    except KeyboardInterrupt:
        console.print("[warn]interrupted[/warn] — the session is intact")
    except Exception as e:  # noqa: BLE001 — a bug in a verb must not take the session with it
        console.print(f"[err]{type(e).__name__}:[/err] {e}   (the session is intact; please report this)")
        if os.environ.get("DECNIQUE_DEBUG"):
            raise
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
    body.append("rules load <rules/>", style="key")
    body.append("  →  ", style="muted")
    body.append("account load <a.json>", style="key")
    body.append("  →  ", style="muted")
    body.append("ask blindspots", style="key")
    body.append("      ·  ", style="muted")
    body.append("help", style="key")
    body.append(" for everything", style="muted")
    console.print(
        Panel(body, title=Text("decnique", style="brand"), title_align="left",
              border_style="rule", padding=(1, 2))
    )


def _rows(pairs, style_first: str = "key"):  # type: ignore[no-untyped-def]
    from rich.table import Table

    t = Table(box=None, padding=(0, 2, 0, 0), show_header=False, pad_edge=False)
    t.add_column(style=style_first, no_wrap=True)
    t.add_column(style="muted", no_wrap=True)
    t.add_column()
    from rich.text import Text

    for row in pairs:
        t.add_row(*(Text(c) for c in row))  # Text: a hint like `[~][substr]` is not markup
    return t


def print_help(s: Session, args: list[str] | None = None) -> None:
    """`help` — objects and their verbs; `help <object>` — one object; `help <object> <verb>`."""
    from rich.text import Text

    args = args or []
    if not args:
        console.print(Text(f"{BULLET} objects — `<object> <verb> [args…]`; `help <object>` for its verbs", style="title"))
        console.print(_rows((o.name, " · ".join(o.verbs), o.help) for o in OBJECTS.values()))
        console.print(Text(f"{BULLET} shell", style="title"))
        console.print(_rows((name, hint, one) for name, (hint, one, _) in SHELL.items()))
        console.print("[muted]a line like `detection d { … }` / `candidate c { … }` / `check q { … }` defines a block in place[/muted]")
        return
    name = args[0]
    if name in SHELL:
        hint, one, detail = SHELL[name]
        _panel(name, one, detail)
        return
    obj = OBJECTS.get(name)
    if obj is None:
        console.print(f"[warn]unknown object {name!r}[/warn] — type [key]help[/key]")
        return
    if len(args) == 1:
        console.print(Text(f"{BULLET} {obj.name} — {obj.help}", style="title"))
        console.print(_rows((f"{obj.name} {v.name}", v.hint, v.help) for v in obj.verbs.values()))
        if obj.default:
            console.print(f"[muted]`{obj.name}` alone runs `{obj.name} {obj.default}`  ·  help {obj.name} <verb> for detail[/muted]")
        _settings(s, settings_prefix(obj, None))
        return
    verb = obj.verb(args[1])
    if verb is None:
        console.print(f"[warn]{obj.name} has no verb {args[1]!r}[/warn] — " + ", ".join(obj.verbs))
        return
    _panel(f"{obj.name} {verb.name}", verb.help, verb.detail or f"{obj.name} {verb.name} {verb.hint}")
    _settings(s, settings_prefix(obj, verb))


def _panel(title: str, one: str, detail: str) -> None:
    from rich.panel import Panel
    from rich.text import Text

    body = Text(one + "\n\n", style="muted")
    body.append(detail)
    console.print(Panel(body, title=Text(title, style="brand"), title_align="left", border_style="rule", padding=(0, 1)))


def _settings(s: Session, prefix: str) -> None:
    from rich.table import Table

    if not prefix:
        return
    rows = [r for r in s.settings.rows() if r[0].startswith(prefix)]
    if not rows:
        return
    t = Table(box=None, padding=(0, 2, 0, 0), show_header=True, pad_edge=False, header_style="muted")
    for col in ("SETTING", "VALUE", "ALLOWED", "WHAT IT DOES"):
        t.add_column(col, style="key" if col == "SETTING" else "")
    for key, val, allowed, help_ in rows:
        t.add_row(key, val, allowed, help_)
    console.print(t)
    console.print("[muted]change one with: config <key> <value>[/muted]")


# --- prompt_toolkit front (with a plain fallback) -----------------------------------------


def _term_width(default: int = 80) -> int:
    import shutil

    return max(24, shutil.get_terminal_size((default, 24)).columns)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _status_chips(s: Session) -> str:
    """The `rules · candidates · checks · account · events` chips for the bottom status line."""

    def chip(label: str, value: str, on: bool) -> str:
        cls = "tb.on" if on else "tb.off"
        return f"<{cls}>{label}</{cls}> <tb.val>{_esc(value)}</tb.val>"

    rules = str(len(s.lib.detections)) if s.lib is not None else "—"
    cands = str(len(s.lib.bundle.candidates)) if s.lib is not None else "—"
    checks = str(len(s.lib.bundle.checks)) if s.lib is not None else "—"
    acct = s.account.name if s.account else "—"
    evs = str(len(s.events)) if s.events else "—"
    return "   ·   ".join([
        chip("rules", rules, bool(s.lib)),
        chip("candidates", cands, bool(s.lib)),
        chip("checks", checks, bool(s.lib)),
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
            words = text.split()
            at_word = bool(words) and not text.endswith(" ")
            n = len(words) - (1 if at_word else 0)  # words already complete before the cursor
            word = words[-1] if at_word else ""
            if n == 0:  # the object (or a shell word)
                for name, o in OBJECTS.items():
                    if name.startswith(word):
                        yield Completion(name, start_position=-len(word), display=name, display_meta=o.help)
                for name, (_, one, _) in SHELL.items():
                    if name.startswith(word):
                        yield Completion(name, start_position=-len(word), display=name, display_meta=one)
                return
            obj = OBJECTS.get(words[0])
            if obj is None:
                if words[0] in ("help", "config"):
                    for name in OBJECTS:
                        if name.startswith(word):
                            yield Completion(name, start_position=-len(word), display=name)
                return
            if n == 1:  # the verb
                for name, v in obj.verbs.items():
                    if name.startswith(word):
                        yield Completion(name, start_position=-len(word), display=name, display_meta=v.help)
                return
            verb = obj.verb(words[1])
            if verb is not None and verb.paths:  # a filesystem path
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
        placeholder=HTML('<placeholder>type a command — try "ask blindspots", "rules list", or "help"</placeholder>'),
        history=FileHistory(history_path),
        auto_suggest=AutoSuggestFromHistory(),
        completer=_make_completer(),
        complete_while_typing=True,
        reserve_space_for_menu=0,  # the box hugs the input; the completion menu expands it on demand
        erase_when_done=True,  # the box lives only around the active input; scrollback stays clean
        style=style,
    )
    def more() -> str | None:
        try:
            return session.prompt(HTML("<frame>│</frame> <prompt>…</prompt> "), rprompt=rprompt,
                                  bottom_toolbar=None, completer=None, placeholder="")
        except (EOFError, KeyboardInterrupt):
            return None

    while True:
        try:
            line = session.prompt()
        except EOFError:
            break
        except KeyboardInterrupt:
            continue
        if is_dsl(line):  # a DSL block: keep reading until the braces close
            line = read_block(line, more)
        if line.strip():  # echo the submitted command cleanly above its output (Claude-Code style)
            console.print("[brand]›[/brand] " + line.strip().replace("\n", "\n  "))
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
        if is_dsl(line):
            line = read_block(line, lambda: _plain_more())
        if not dispatch(s, line):
            break
    return 0


def _plain_more() -> str | None:
    try:
        return input("      ... ")
    except (EOFError, KeyboardInterrupt):
        return None


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

# what a finding is, per verb, for --fail-on
_FINDING = {"blindspots": ("gap",), "stealth": ("evasive",), "chains": ("stealthy",), "check": ("fail",)}
_INCONCLUSIVE = ("exhausted", "unknown", "inconclusive")

EXIT_CLEAN, EXIT_FINDING, EXIT_INPUT, EXIT_INCONCLUSIVE = 0, 2, 3, 4


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decnique",
        description="decnique — no arguments: the interactive shell.  With a command (`ask blindspots …`): "
                    "run it once and exit (batch / CI mode).  A script (`-f file`, or `-f -` for stdin) runs one shell line per "
                    "line.",
        epilog="exit codes: 0 clean · 2 a finding (gap / evasive / stealthy path / failed check) with "
               "--fail-on · 3 input error · 4 inconclusive with --fail-on unknown",
    )
    p.add_argument("--rules", "-r", nargs="+", metavar="PATH", help="rule dirs / .decn files to load first")
    p.add_argument("--all", action="store_true", help="load every platform, not only GCP rules")
    p.add_argument("--account", "-a", metavar="FILE", help="account model or raw gcloud export")
    p.add_argument("--resource", default="*", metavar="RES", help="scope of a plain IAM policy (projects/x)")
    p.add_argument("--json", action="store_true", help="print the run's findings as JSON on stdout")
    p.add_argument("--report", metavar="DIR", help="save the run to DIR (like `config report.save on`)")
    p.add_argument("--format", choices=("md", "json", "yaml"), help="report format (default md)")
    p.add_argument("--fail-on", choices=("finding", "unknown"), help="exit 2 on a finding; 4 on inconclusive too")
    p.add_argument("--file", "-f", metavar="SCRIPT", help="run shell lines from a file (`-` = stdin)")
    p.add_argument("verb", nargs="*", help="a shell command: <object> <verb> [args…]")
    return p


def _outcome(s: Session, verb: str, fail_on: str | None) -> int:
    rep = s.last_report
    if rep is None or not fail_on:
        return EXIT_CLEAN
    verdicts = [it["verdict"] for it in rep.items]
    if rep.verb == "chains" and rep.summary.get("found"):
        verdicts.append("stealthy")
    if any(v in _FINDING.get(rep.verb, ()) for v in verdicts):
        return EXIT_FINDING
    if fail_on == "unknown" and (any(v in _INCONCLUSIVE for v in verdicts) or rep.summary.get("inconclusive")):
        return EXIT_INCONCLUSIVE
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    s = Session()
    if not argv:
        return repl(s)
    # richer flag forms belong to the batch CLI
    if argv[0] in _DELEGATED and _DELEGATED_FLAGS & set(argv):
        from decnique.cli import main as cli_main

        return cli_main(argv)
    ns = _parser().parse_args(argv)
    if ns.report:
        s.settings.set("report.save", "on", persist=False)
        s.settings.set("report.dir", ns.report, persist=False)
    if ns.format:
        s.settings.set("report.format", ns.format, persist=False)
    try:
        if ns.rules:
            s.load((["--all"] if ns.all else []) + list(ns.rules))
            if s.lib is None:
                return EXIT_INPUT
        if ns.account:
            s.account_load(ns.account, ns.resource)
    except (OSError, ValueError, DslError) as e:
        console.print(f"[err]input error:[/err] {e}")
        return EXIT_INPUT
    worst = EXIT_CLEAN
    lines: list[str] = []
    if ns.file:
        text = sys.stdin.read() if ns.file == "-" else Path(ns.file).read_text(encoding="utf-8")
        lines += [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if ns.verb:
        lines.append(" ".join(shlex.quote(a) for a in ns.verb))
    if not lines:
        _parser().print_usage()
        return EXIT_INPUT
    for line in lines:
        s.last_report = None
        if not dispatch(s, line):
            break
        if s.last_report is not None and ns.json:
            from .report import to_json

            print(to_json(s.last_report))
        worst = max(worst, _outcome(s, line.split()[0], ns.fail_on))
    return worst
