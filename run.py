#!/usr/bin/env python3
"""decnique — interactive front door.

    python3 run.py                       start the REPL
    python3 run.py load rules/ ...        one-shot: run a single command and exit
    python3 run.py trace -e events.json rules/    (delegates to decnique.cli)

The REPL holds a *session*: a loaded library of detections + candidates, and an
ordered event trace.  It answers three-valued (yes / no / don't know) using the
real engine — `decnique.eval` (M0) and `decnique.detections` — never a reimpl.

As later milestones land (M1 account model, M2 single-event SMT, M3 stealth,
M4 chains) their verbs (`blindspots`, `stealth`, `chains`) light up here; today
they explain what they need.  Type `help` for the command list.
"""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path

from decnique.detections import DetectionLibrary, event_from_audit_log
from decnique.dsl import format as fmt
from decnique.dsl.loader import LoadOptions
from decnique.dsl.parser import DslError
from decnique.eval import fires, matches_footprint

# --- three-valued rendering ---------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _tri(t: object) -> str:
    if t is True:
        return _c("32", "yes")
    if t is False:
        return _c("90", "no")
    return _c("33", "unknown")


def _events_from(raw: object) -> list[dict]:
    entries = raw if isinstance(raw, list) else [raw]
    return [event_from_audit_log(e) if "protoPayload" in e else e for e in entries]


# --- table rendering ----------------------------------------------------------------------

# A cell is either a plain string, or (text, color_code) for a coloured cell.
Cell = "str | tuple[str, str]"


def _term_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def _truncate(s: str, w: int) -> str:
    return s if len(s) <= w else (s[: max(0, w - 1)] + "…" if w > 0 else "")


def _cell_text(cell) -> tuple[str, str | None]:
    if isinstance(cell, tuple):
        return str(cell[0]), cell[1]
    return str(cell), None


def _render_table(headers, rows, *, aligns=None, gap: int = 2) -> str:
    """Render an aligned, coloured, terminal-width-aware table.  The last column is the flexible
    one that shrinks first when the terminal is narrow."""
    cols = len(headers)
    aligns = aligns or ["<"] * cols
    widths = [len(h) for h in headers]
    plain_rows = [[_cell_text(c) for c in r] for r in rows]
    for r in plain_rows:
        for i, (text, _) in enumerate(r):
            widths[i] = max(widths[i], len(text))

    budget = _term_width()
    total = sum(widths) + gap * (cols - 1)
    if total > budget:  # shrink the flexible (last) column, then the widest, down to a floor
        shrink = total - budget
        for i in sorted(range(cols), key=lambda k: widths[k], reverse=True):
            if shrink <= 0:
                break
            room = widths[i] - max(8, len(headers[i]))
            take = min(room, shrink)
            widths[i] -= take
            shrink -= take

    sep = " " * gap

    def pad(text: str, color: str | None, i: int) -> str:
        cell = f"{_truncate(text, widths[i]):{aligns[i]}{widths[i]}}"
        return _c(color, cell) if color else cell

    lines = [_c("1;36", sep.join(pad(h, None, i) for i, h in enumerate(headers)))]
    lines.append(_c("90", sep.join("─" * widths[i] for i in range(cols))))
    for r in plain_rows:
        lines.append(sep.join(pad(text, color, i) for i, (text, color) in enumerate(r)))
    return "\n".join(lines)


def _window_str(spec) -> str:
    w = spec.window
    if w is None:
        return "-"
    return f"{w.seconds}s" if w.side == "around" else f"{w.seconds}s/{w.side}"


def _cond_str(c) -> str:
    from decnique.model.trace import AggCmp, CAnd, CNot, COr, Count, CTrue

    if isinstance(c, CTrue):
        return "always"
    if isinstance(c, Count):
        return f"#{c.var}{c.op}{c.n}"
    if isinstance(c, AggCmp):
        return f"{c.name}{c.op}{c.n}"
    if isinstance(c, CAnd):
        return " & ".join(_cond_str(x) for x in c.children)
    if isinstance(c, COr):
        return " | ".join(_cond_str(x) for x in c.children)
    if isinstance(c, CNot):
        return f"!({_cond_str(c.child)})"
    return "?"


def _footprint_str(fp) -> str:
    parts = []
    for s in fp.steps:
        tag = s.id + (f"×{s.repeat}" if s.repeat and s.repeat != 1 else "")
        extras = []
        if s.within_seconds is not None:
            extras.append(f"within {s.within_seconds}s")
        if s.distinct:
            extras.append("distinct " + ",".join(q[1] for q in s.distinct))
        if extras:
            tag += f" ({'; '.join(extras)})"
        parts.append(tag)
    return ", ".join(parts)


# --- session ------------------------------------------------------------------------------


class Session:
    """Mutable REPL state: the loaded library and the current event trace."""

    def __init__(self) -> None:
        self.lib: DetectionLibrary | None = None
        self.paths: list[str] = []
        self.events: list[dict] = []
        self.events_src: str = ""
        self.options = LoadOptions()
        self.account = None
        self.account_doc: dict = {}

    # -- loading ---------------------------------------------------------------------------

    def load(self, paths: list[str]) -> None:
        if not paths:
            print("usage: load <path> [path ...]   (dirs or .decn/native rule files)")
            return
        self.lib = DetectionLibrary.load(*paths, options=self.options)
        self.paths = paths
        b = self.lib.bundle
        errs = sum(1 for i in b.issues if i.severity == "error")
        print(
            f"loaded {len(b.detections)} detections, {len(b.candidates)} candidates"
            + (f", {_c('31', str(errs) + ' errors')}" if errs else "")
        )
        for i in b.issues:
            if i.severity == "error":
                print(f"  {_c('31', 'error')}: {i.file}: {i.message}")

    def events_load(self, file: str) -> None:
        raw = json.loads(Path(file).read_text(encoding="utf-8"))
        self.events = _events_from(raw)
        self.events_src = file
        print(f"loaded {len(self.events)} events from {file}")

    def account_load(self, file: str) -> None:
        from decnique.env import account_from_dict

        self.account_doc = json.loads(Path(file).read_text(encoding="utf-8"))
        self.account = account_from_dict(self.account_doc)
        principals = len(self.account.bindings)
        print(f"loaded account {self.account.name!r}: {principals} principals")

    # -- guards ----------------------------------------------------------------------------

    def _need_lib(self) -> bool:
        if self.lib is None:
            print("no rules loaded — run: load <paths...>")
            return False
        return True

    def _need_events(self) -> bool:
        if not self.events:
            print("no events loaded — run: events <file.json>")
            return False
        return True

    def _need_account(self) -> bool:
        if self.account is None:
            print("no account loaded — run: account <file.json>")
            return False
        return True

    # -- queries ---------------------------------------------------------------------------

    def rules(self, filt: str | None) -> None:
        if not self._need_lib():
            return
        shown = [d for d in self.lib.detections if not filt or filt in d.id]
        if not shown:
            print(f"   no detections match {filt!r}" if filt else "   no detections loaded")
            return
        rows = []
        approx = 0
        for d in shown:
            approx += bool(d.approximate)
            status = ("~approx", "33") if d.approximate else ("exact", "90")
            rows.append([
                d.id,
                d.source.frontend if d.source else "dsl",
                d.paradigm,
                str(len(d.spec.events)),
                _window_str(d.spec),
                _cond_str(d.spec.condition),
                status,
            ])
        title = f"detections ({len(shown)}" + (f" of {len(self.lib.detections)}" if filt else "")
        print(_c("1", f"{title}, {approx} approximate)"))
        print(_render_table(
            ["ID", "SOURCE", "TYPE", "#EV", "WINDOW", "CONDITION", "STATUS"],
            rows,
            aligns=["<", "<", "<", ">", "<", "<", "<"],
        ))
        print(_c("90",
                 "  SOURCE=front-end · TYPE=event(single)/correlation(multi) · #EV=event vars · "
                 "WINDOW=correlation span · STATUS=~approx has Unknown atoms"))

    def candidates(self) -> None:
        if not self._need_lib():
            return
        cands = self.lib.bundle.candidates
        if not cands:
            print("   no candidates loaded — techniques come from .decn `candidate {…}` blocks")
            return
        rows = []
        for c in cands:
            reqs = ", ".join(r.permission for r in c.required) or "-"
            fp = c.footprint
            rows.append([
                c.id,
                reqs,
                _footprint_str(fp) if fp else "-",
                " < ".join(fp.order) if fp and fp.order else "-",
                f"{fp.span_seconds}s" if fp and fp.span_seconds is not None else "-",
            ])
        print(_c("1", f"candidates ({len(cands)})"))
        print(_render_table(
            ["ID", "REQUIRES", "FOOTPRINT", "ORDER", "SPAN"],
            rows,
            aligns=["<", "<", "<", "<", ">"],
        ))
        print(_c("90",
                 "  REQUIRES=permissions the actor must hold · FOOTPRINT=step×repeat (guards) · "
                 "ORDER=step sequence · SPAN=max duration · full detail: show <id>"))

    def show(self, ident: str | None) -> None:
        if not self._need_lib() or not ident:
            print("usage: show <detection-or-candidate-id>")
            return
        for d in self.lib.detections:
            if d.id == ident:
                print(fmt.detection(d))
                return
        for c in self.lib.bundle.candidates:
            if c.id == ident:
                print(fmt.candidate(c))
                return
        print(f"no detection or candidate named {ident!r}")

    def summary(self) -> None:
        if not self._need_lib():
            return
        print(json.dumps(self.lib.summary(), indent=2))

    def admits(self, method: str | None) -> None:
        if not self._need_lib() or not method:
            print("usage: admits <method>")
            return
        hits = list(self.lib.admitting(method))
        for d in hits:
            print(f" {_c('33', '~') if d.approximate else ' '} {d.id}")
        print(f"   {len(hits)} detections could involve {method!r}")

    def event(self, file: str | None) -> None:
        if not self._need_lib() or not file:
            print("usage: event <file.json>   (single audit-log entry or event dict)")
            return
        raw = json.loads(Path(file).read_text(encoding="utf-8"))
        ev = _events_from(raw)[0]
        obs = self.lib.observing(ev)
        print(f"observed_by : {', '.join(obs.observed_by) or '(none)'}")
        print(f"fires_single: {', '.join(obs.fires_single) or '(none)'}")
        print(f"unknown     : {', '.join(obs.unknown) or '(none)'}")
        print(f"approximate : {_tri(obs.approximate)}")

    def trace(self, show_all: bool) -> None:
        if not self._need_lib() or not self._need_events():
            return
        rows = []
        for d in self.lib.detections:
            t = fires(d.spec, self.events, ref_lists=self.lib.ref_lists)
            if t is not False or show_all:
                rows.append((d.id, t, d.approximate))
        for rid, t, approx in rows:
            flag = _c("33", "~") if approx else " "
            print(f" {flag} {_tri(t):18} {rid}")
        fired = sum(1 for _, t, _ in rows if t is True)
        unk = sum(1 for _, t, _ in rows if t is None)
        print(f"   {fired} fire, {unk} unknown, over {len(self.events)} events")

    def footprint(self, ident: str | None) -> None:
        if not self._need_lib() or not self._need_events():
            return
        for c in self.lib.bundle.candidates:
            if ident and c.id != ident:
                continue
            if not c.footprint:
                continue
            t = matches_footprint(c.footprint, self.events, ref_lists=self.lib.ref_lists)
            print(f" {_tri(t):18} {c.id}")

    # -- coverage engine (M2 / M3 / M4) ----------------------------------------------------

    def blindspots(self, perms: list[str]) -> None:
        if not self._need_lib() or not self._need_account():
            return
        from decnique.report import blindspots_report

        rep = blindspots_report(self.lib, self.account, tuple(perms) or None)
        print(json.dumps(rep["summary"]))
        for g in rep["gaps"]:
            flag = _c("33", "~") if g["tag"] == "approximate" else " "
            ev = g["event"]
            print(f" {flag} GAP  {g['permission']:45} method={ev.get('method')}")
        for p in rep["unlogged"]:
            print(f"   UNLOGGED {p}  (methods not written to audit logs)")
        if not rep["gaps"] and not rep["unlogged"]:
            print("   no blind spots for the probed permissions")

    def stealth(self, ident: str | None) -> None:
        if not self._need_lib() or not self._need_account():
            return
        from decnique.smt.stealth import Evasive, stealth_feasible

        for c in self.lib.bundle.candidates:
            if ident and c.id != ident:
                continue
            r = stealth_feasible(c, self.lib, self.account)
            if isinstance(r, Evasive):
                tag = _c("33", "~approx") if r.approximate else _c("32", "evasive")
                print(f" {tag:16} {c.id}  ({len(r.schedule)} events as {r.principal})")
            else:
                print(f" {_c('90', r.verdict):16} {c.id}")

    def chains(self, goal: str | None) -> None:
        if not self._need_lib() or not self._need_account():
            return
        attack = dict(self.account_doc.get("attack", {}))
        if goal:
            attack["goal"] = goal
        if "goal" not in attack or "principal" not in attack:
            print("chains: the account file needs an `attack` block "
                  "(principal, initial_state, goal, effects) — or pass a goal permission.")
            return
        from decnique.report import chains_report

        rep = chains_report(self.lib, self.account, attack)
        if rep["found"]:
            tag = _c("33", "~approx") if rep["tag"] == "approximate" else _c("32", "stealthy")
            print(f" {tag} path to {rep['goal']}:")
            for h in rep["hops"]:
                print(f"   → {h['technique']:20} gains {', '.join(h['gains'])}")
        else:
            print(f" {_c('90', 'no stealthy path')} to {rep['goal']} "
                  f"({rep['reason']}, {rep['states_explored']} states explored)")


# --- dispatch -----------------------------------------------------------------------------

_HELP = """commands:
  load <paths...>          load detections + candidates into the session
  rules [substr]           list loaded detections (~ = approximate, 1ev/trace)
  candidates               list loaded techniques and their footprint steps
  show <id>                print canonical DSL for a detection or candidate
  admits <method>          which detections could involve a method
  summary                  corpus statistics (exact vs approximate, paradigms)
  events <file.json>       load an ordered event trace into the session
  event <file.json>        single event: which detections observe it
  trace [all]              run every detection over the loaded trace (three-valued)
  footprint [id]           match candidate footprint(s) against the loaded trace
  account <file.json>      load the GCP account model (Reach / Log constraints)
  blindspots [perm...]     reachable+logged events no rule observes (M2)
  stealth [id]             can a technique evade every rule? evasive schedule (M3)
  chains [goal]            stealthy privilege-escalation paths (M4; needs `attack` block)
  help                     this list
  quit / exit              leave
"""


def dispatch(s: Session, line: str) -> bool:
    """Run one command line. Returns False to exit the REPL."""
    parts = shlex.split(line)
    if not parts:
        return True
    cmd, args = parts[0], parts[1:]
    try:
        if cmd in ("quit", "exit", "q"):
            return False
        elif cmd in ("help", "?"):
            print(_HELP)
        elif cmd == "load":
            s.load(args)
        elif cmd == "rules":
            s.rules(args[0] if args else None)
        elif cmd == "candidates":
            s.candidates()
        elif cmd == "show":
            s.show(args[0] if args else None)
        elif cmd == "summary":
            s.summary()
        elif cmd == "admits":
            s.admits(args[0] if args else None)
        elif cmd == "events":
            s.events_load(args[0]) if args else print("usage: events <file.json>")
        elif cmd == "event":
            s.event(args[0] if args else None)
        elif cmd == "account":
            s.account_load(args[0]) if args else print("usage: account <file.json>")
        elif cmd == "trace":
            s.trace(show_all=bool(args) and args[0] == "all")
        elif cmd == "footprint":
            s.footprint(args[0] if args else None)
        elif cmd == "blindspots":
            s.blindspots(args)
        elif cmd == "stealth":
            s.stealth(args[0] if args else None)
        elif cmd == "chains":
            s.chains(args[0] if args else None)
        else:
            print(f"unknown command {cmd!r} — type `help`")
    except (OSError, json.JSONDecodeError) as e:
        print(f"input error: {e}")
    except DslError as e:
        print(f"dsl error: {e}")
    except KeyError as e:
        print(f"not found: {e}")
    return True


_COMMANDS = [
    "load", "rules", "candidates", "show", "summary", "admits", "events", "event",
    "account", "trace", "footprint", "blindspots", "stealth", "chains", "help", "quit", "exit",
]


def _install_readline() -> None:
    """Enable history + Tab completion (command names, then filesystem paths).

    On macOS, Python's ``readline`` is usually libedit, which binds Tab differently from GNU
    readline — hence the ``__doc__`` check.  Completer delimiters are narrowed to whitespace so a
    path token (which contains ``/``, ``.``, ``-`` …) completes as a whole."""
    try:
        import readline
    except ImportError:
        return
    import glob
    import os

    def _paths(text: str) -> list[str]:
        try:
            matches = glob.glob(os.path.expanduser(text) + "*")
        except OSError:
            return []
        return sorted(m + ("/" if os.path.isdir(m) else " ") for m in matches)

    def completer(text: str, state: int) -> str | None:
        stripped = readline.get_line_buffer().lstrip()
        if " " not in stripped:  # still typing the command word
            opts = sorted(c + " " for c in _COMMANDS if c.startswith(text))
        else:  # an argument → complete filesystem paths
            opts = _paths(text)
        return opts[state] if state < len(opts) else None

    readline.set_completer_delims(" \t\n")
    readline.set_completer(completer)
    if "libedit" in (readline.__doc__ or ""):
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


def repl(s: Session) -> int:
    _install_readline()
    print("decnique — interactive coverage shell.  type `help`, `quit` to leave.")
    while True:
        try:
            line = input(_c("36", "decnique> "))
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        if not dispatch(s, line):
            break
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    s = Session()
    if not argv:
        return repl(s)
    # one-shot: a bare `load ...` etc., or delegate richer forms to decnique.cli
    delegated = {"parse", "fmt", "import", "event", "trace", "coverage", "admits", "show"}
    if argv[0] in delegated and (
        {"-e", "-o", "-a", "--account", "--yaml", "--permission"} & set(argv)
    ):
        from decnique.cli import main as cli_main

        return cli_main(argv)
    dispatch(s, " ".join(shlex.quote(a) for a in argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
