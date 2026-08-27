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


# --- session ------------------------------------------------------------------------------


class Session:
    """Mutable REPL state: the loaded library and the current event trace."""

    def __init__(self) -> None:
        self.lib: DetectionLibrary | None = None
        self.paths: list[str] = []
        self.events: list[dict] = []
        self.events_src: str = ""
        self.options = LoadOptions()

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

    # -- queries ---------------------------------------------------------------------------

    def rules(self, filt: str | None) -> None:
        if not self._need_lib():
            return
        for d in self.lib.detections:
            if filt and filt not in d.id:
                continue
            kind = "1ev" if d.spec.is_single_event else "trace"
            flag = _c("33", "~") if d.approximate else " "
            fe = d.source.frontend if d.source else "dsl"
            print(f" {flag} {fe:8} {d.paradigm:11} {kind:5} {d.id}")
        print(f"   {len(self.lib.detections)} detections")

    def candidates(self) -> None:
        if not self._need_lib():
            return
        for c in self.lib.bundle.candidates:
            steps = ", ".join(s.id for s in c.footprint.steps) if c.footprint else "-"
            print(f"   {c.id:30} steps: {steps}")
        print(f"   {len(self.lib.bundle.candidates)} candidates")

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

    # -- forward-looking (need later milestones) -------------------------------------------

    def not_yet(self, verb: str, needs: str) -> None:
        print(f"{verb}: not available yet — needs {needs}.")
        print("  (M0 concrete evaluator is live: try `trace` and `footprint`.)")


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
  blindspots               [needs M1+M2] reachable+logged events no rule observes
  stealth <id>             [needs M3]     can this technique evade every rule
  chains                   [needs M4]     stealthy privilege-escalation paths
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
        elif cmd == "trace":
            s.trace(show_all=bool(args) and args[0] == "all")
        elif cmd == "footprint":
            s.footprint(args[0] if args else None)
        elif cmd == "blindspots":
            s.not_yet("blindspots", "the M1 account model + M2 single-event SMT")
        elif cmd == "stealth":
            s.not_yet("stealth", "the M3 symbolic stealth solver")
        elif cmd == "chains":
            s.not_yet("chains", "the M4 attack-graph search")
        else:
            print(f"unknown command {cmd!r} — type `help`")
    except (OSError, json.JSONDecodeError) as e:
        print(f"input error: {e}")
    except DslError as e:
        print(f"dsl error: {e}")
    except KeyError as e:
        print(f"not found: {e}")
    return True


def repl(s: Session) -> int:
    try:
        import readline  # noqa: F401  (enables history/editing where available)
    except ImportError:
        pass
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
    if argv[0] in {"parse", "fmt", "import", "load", "event", "trace", "admits", "show"} and (
        "-e" in argv or "-o" in argv or "--yaml" in argv
    ):
        from decnique.cli import main as cli_main

        return cli_main(argv)
    dispatch(s, " ".join(shlex.quote(a) for a in argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
