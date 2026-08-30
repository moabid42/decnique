"""The interactive shell: a prompt_toolkit input line over a rich-rendered body.

The input line carries the affordances that make a REPL feel alive — command and path
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

from . import render
from .session import Session
from .theme import BULLET, console

# --- command catalogue --------------------------------------------------------------------

# verb -> (argument hint, one-line help).  Single source for completion, help, and dispatch.
COMMANDS: dict[str, tuple[str, str]] = {
    "load": ("[--all] [--deprecated] <paths…>", "load detections + candidates (default: GCP only, skips _deprecated)"),
    "account": ("<file.json> [resource]", "load the account model, or a raw gcloud IAM policy / asset export"),
    "events": ("<file.json>", "load an ordered event trace into the session"),
    "rules": ("[~][substr]", "list loaded detections (~ = only approximate ones)"),
    "candidates": ("", "list loaded techniques and their footprints"),
    "show": ("<id>", "print canonical DSL for a detection or candidate"),
    "admits": ("<method>", "which detections could involve a method"),
    "summary": ("", "corpus statistics"),
    "event": ("<file.json>", "single event: which detections observe it"),
    "trace": ("[all]", "run every detection over the loaded trace (three-valued)"),
    "footprint": ("[id]", "match candidate footprint(s) against the loaded trace"),
    "checks": ("", "list loaded check blocks and the question each asks"),
    "check": ("[id… | file.decn…]", "run check blocks (all loaded, by id, or from files)  (SMT)"),
    "blindspots": ("[perm…]", "reachable+logged events no rule observes  (SMT · M2)"),
    "stealth": ("[id]", "can a technique evade every rule?  (SMT · M3)"),
    "chains": ("[goal] [--from p] [--start p1,p2]", "stealthy privilege-escalation paths  (graph+SMT · M4)"),
    "config": ("[verb | key [value|reset]]", "show or change settings; `config <verb>` explains a verb and its settings"),
    "reports": ("", "list saved report files (config report.save on)"),
    "export": ("<file.json> [n]", "write the last run's witnesses as Cloud Audit Log JSON (replay in the SIEM)"),
    "suggest": ("<perm…> [define]", "DSL detections that would close a permission's blind spot"),
    "report": ("<file> | diff <a> <b>", "reopen a saved run: its summary and findings"),
    "clear": ("", "clear the screen (session state is kept)"),
    "help": ("[verb]", "show this command list, or everything about one verb"),
    "quit": ("", "leave the shell"),
}

_PATH_CMDS = {"load", "account", "events", "event", "check", "report", "export"}
_MATH_CMDS = {"blindspots", "stealth", "chains", "check"}

# plain-language detail for `help <verb>` / `config <verb>`: arguments, sub-words, what to expect
DETAILS: dict[str, str] = {
    "load": "load [--all] [--deprecated] <path…>\n"
            "  paths: directories or files of native rules (.yaral, .toml, .yml) or DSL (.decn)\n"
            "  --all         keep every platform (default keeps only GCP-relevant rules)\n"
            "  --deprecated  also load rules under _deprecated/\n"
            "  What you get: detections, candidates (techniques) and checks, merged into the session.",
    "account": "account <file.json> [resource]\n"
               "  The GCP account model: who holds which permission on which resource (Reach), and\n"
               "  which audit logs are on (Log). Optional `attack` block for `chains`.\n"
               "  Also accepts a raw export, converted on load:\n"
               "    gcloud projects get-iam-policy PROJECT --format=json > policy.json\n"
               "      → account policy.json projects/PROJECT     (bindings + Data Access audit config)\n"
               "    gcloud asset search-all-iam-policies --scope=projects/PROJECT --format=json > cai.json\n"
               "      → account cai.json                          (grants scoped per resource)\n"
               "  Predefined roles expand from the built-in catalog; conditional bindings are kept\n"
               "  unconditionally and listed as notes.",
    "events": "events <file.json>\n  An ordered trace of audit-log events (raw protoPayload or the flat event form).",
    "rules": "rules [~][substr]\n"
             "  List loaded detections; `~` in STATUS marks a rule with an untranslatable part (approximate).\n"
             "  `rules ~` lists only those — the rules a verdict can lean on as don't-know; `show <id>` says why.",
    "candidates": "candidates\n  List the loaded techniques: required permissions and the footprint they leave.",
    "show": "show <id>\n  Print a detection, candidate, or check in canonical DSL, plus what could not be translated.",
    "admits": "admits <method>\n  Which detections could involve an event with this method (a syntactic pre-filter).",
    "summary": "summary\n  Corpus statistics: rules per platform, approximate rules, checks.",
    "event": "event <file.json>\n  One concrete event: which detections observe it (yes / no / don't-know).",
    "trace": "trace [all]\n  Run every detection over the loaded trace; `all` also lists the ones that do not fire.",
    "footprint": "footprint [id]\n  Does the loaded trace realize a technique's footprint?",
    "checks": "checks\n  List loaded `check` blocks and the question each asks.",
    "check": "check [id… | file.decn…]\n"
             "  Run check blocks: all loaded ones, the named ones, or those in the given files.\n"
             "  Types: coverage, candidate, compare, dead_rules, redundant_rules, boundary,\n"
             "         require_coverage, attempt_coverage, public_access.\n"
             "  Every answer is pass / fail / unknown; a fail shows a witness replayed through the oracle.\n"
             "  You can also type a block at the prompt:  check q { type candidate for <technique> }",
    "blindspots": "blindspots [perm…]\n"
                  "  QUESTION: for each permission, is there ANY logged action using it that no rule catches?\n"
                  "  Per permission you see:\n"
                  "    Reach        who can exercise it          Log   which methods are audit-logged\n"
                  "    example      the simplest event nobody catches (replayed through the oracle)\n"
                  "    watched:     a kind of change some rule catches — and by which rule\n"
                  "    UNWATCHED:   a kind of change no rule catches — and the nearest rule's missing condition\n"
                  "    the attack…  the verdict of `stealth` for techniques needing this permission\n"
                  "  Verdicts: BLIND SPOT / covered (proof) / inconclusive (refinement bound).\n"
                  "  exact vs ~approx: approx means an untranslatable rule part was involved.\n"
                  "  Settings: blindspots.explain (rules | formula | both | words), blindspots.raw (off | on).",
    "stealth": "stealth [id]\n"
               "  QUESTION: can THIS technique be run so that no rule fires?\n"
               "  Verdicts: evasive (a concrete schedule, replayed) / always_detected (proof) /\n"
               "            not_feasible (no principal holds the permissions) / exhausted.",
    "chains": "chains [goal] [--from <principal>] [--start <p1,p2,…>]\n"
              "  Stealthy privilege-escalation paths: every hop is a technique that evades every rule,\n"
              "  and the whole path is replayed so a correlation rule across hops still catches it.\n"
              "  Techniques advance the chain via their `gains { … }` clause.  The start defaults to the\n"
              "  account's most capable principal and what they already hold; override with the flags or\n"
              "  an `attack` block (principal, initial_state, goal, effects) in the account file.",
    "config": "config                      list every setting\n"
              "config <verb>               this help page for a verb, with its settings\n"
              "config <key>                show one value\n"
              "config <key> <value>        set (persisted)      config <key> reset   back to default",
    "reports": "reports\n  List the files in report.dir with the verb, time, and summary of each run.",
    "report": "report <file>            reopen a saved run (md / json / yaml): loaded, summary, findings\n"
              "report diff <a> <b>      what changed between two runs of the same verb: findings that\n"
              "                         appeared (new), closed (gone) or changed verdict — the before/after\n"
              "                         of a rule edit or a corpus update\n"
              "  Settings: report.save (off | on), report.format (md | json | yaml), report.dir.",
    "export": "export <file.json> [n]\n"
              "  Write the last run's witness events (or only finding n) as Cloud Audit Log entries\n"
              "  (protoPayload form, one list) — replay them in the SIEM to confirm the gap for real.\n"
              "  Each entry carries `_decnique` (finding number, label, verdict).",
    "suggest": "suggest <permission> [permission …] [define]\n"
               "  For a permission with a blind spot: DSL `detection` blocks that would close it — one per\n"
               "  unwatched kind of change (built from the rules' own tests) and one catch-all over every\n"
               "  logged method.  `define` adds them to the session; then `blindspots <permission>` or a\n"
               "  `check` shows the gap closed.  Suggestions are starting points, not tuned rules.",
    "clear": "clear\n  Clear the screen; nothing loaded is lost.",
    "help": "help [verb]\n  The command list, or everything about one verb (same as `config <verb>`).",
    "quit": "quit\n  Leave the shell.",
}

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
            print_verb_help(s, args[0]) if args else print_help()
        elif cmd == "config":
            if args and args[0] in COMMANDS:
                print_verb_help(s, args[0])
            else:
                render.config(s, args)
        elif cmd in ("clear", "cls"):
            console.clear()
        elif cmd == "load":
            s.load(args)
        elif cmd == "account":
            if args:
                s.account_load(args[0], args[1] if len(args) > 1 else "*")
            else:
                console.print("[muted]usage:[/muted] account <file.json> [resource]")
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
        elif cmd == "checks":
            render.checks(s)
        elif cmd == "reports":
            render.reports(s)
        elif cmd == "report":
            render.report(s, args[0] if args else None, *args[1:])
        elif cmd == "export":
            render.export(s, args)
        elif cmd == "suggest":
            render.suggest(s, args)
        elif cmd == "check":
            render.check(s, args)
        elif cmd == "blindspots":
            render.blindspots(s, args)
        elif cmd == "stealth":
            render.stealth(s, args[0] if args else None)
        elif cmd == "chains":
            render.chains(s, args)
        else:
            console.print(f"[warn]unknown command {cmd!r}[/warn] — type [key]help[/key]")
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
        ("coverage — the math", ["blindspots", "stealth", "chains", "check", "checks", "suggest"]),
        ("saved runs", ["reports", "report", "export"]),
        ("shell", ["config", "clear", "help", "quit"]),
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


def print_verb_help(s: Session, verb: str) -> None:
    """Everything about one verb: usage, what each word on screen means, and its settings."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if verb not in COMMANDS:
        console.print(f"[warn]unknown verb {verb!r}[/warn] — type [key]help[/key]")
        return
    hint, desc = COMMANDS[verb]
    body = Text(desc + "\n\n", style="muted")
    body.append(DETAILS.get(verb, f"{verb} {hint}"))
    console.print(Panel(body, title=Text(verb, style="brand"), title_align="left", border_style="rule", padding=(0, 1)))
    prefix = "report." if verb in ("reports", "report") else f"{verb}."
    rows = [r for r in s.settings.rows() if r[0].startswith(prefix)]
    if rows:
        t = Table(box=None, padding=(0, 2, 0, 0), show_header=True, pad_edge=False, header_style="muted")
        for col in ("SETTING", "VALUE", "ALLOWED", "WHAT IT DOES"):
            t.add_column(col, style="key" if col == "SETTING" else "")
        for key, val, allowed, help_ in rows:
            t.add_row(key, val, allowed, help_)
        console.print(t)
        console.print(f"[muted]change one with: config <key> <value>[/muted]")


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
        description="decnique — no arguments: the interactive shell.  With a verb: run it once and exit "
                    "(batch / CI mode).  A script (`-f file`, or `-f -` for stdin) runs one shell line per "
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
    p.add_argument("verb", nargs="*", help="a shell command and its arguments")
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
