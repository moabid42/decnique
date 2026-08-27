"""``python -m decnique.cli`` — the DSL tooling subset of plan §5.17.

    decnique.cli parse   FILES...            syntax + semantic check, positional errors
    decnique.cli fmt     FILES...            canonical formatting (in place with --write)
    decnique.cli import  PATHS... -o DIR     native/vendored rules -> .decn (+ --yaml/--json AST)
    decnique.cli load    PATHS...            load a corpus and print a summary
    decnique.cli event   PATHS... -e FILE    which loaded detections observe a concrete event
    decnique.cli admits  PATHS... -m METHOD  which loaded detections can involve a method

Exit codes: 0 ok, 1 issues (errors), 3 input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from decnique.detections import DetectionLibrary, event_from_audit_log
from decnique.dsl import format as fmt
from decnique.dsl import yaml_io
from decnique.dsl.loader import LoadOptions, load_file, load_paths, summary
from decnique.dsl.parser import DslError, parse_file


def _opts(ns: argparse.Namespace) -> LoadOptions:
    return LoadOptions(
        gcp_only=not getattr(ns, "all_platforms", False),
        include_deprecated=getattr(ns, "deprecated", False),
    )


def cmd_parse(ns: argparse.Namespace) -> int:
    rc = 0
    for f in ns.files:
        try:
            b = parse_file(Path(f))
        except DslError as e:
            print(e, file=sys.stderr)
            rc = 1
            continue
        print(
            f"{f}: {len(b.detections)} detections, {len(b.candidates)} candidates, "
            f"{len(b.checks)} checks, {len(b.rulesets)} rulesets"
        )
        if ns.yaml:
            print(yaml_io.dump_yaml(b))
    return rc


def cmd_fmt(ns: argparse.Namespace) -> int:
    rc = 0
    for f in ns.files:
        try:
            b = parse_file(Path(f))
        except DslError as e:
            print(e, file=sys.stderr)
            rc = 1
            continue
        text = fmt.bundle(b)
        if ns.write:
            Path(f).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    return rc


def cmd_import(ns: argparse.Namespace) -> int:
    out = Path(ns.output)
    out.mkdir(parents=True, exist_ok=True)
    options = _opts(ns)
    bundle = load_paths(ns.paths, options)
    for d in bundle.detections:
        (out / f"{d.id}.decn").write_text(fmt.detection(d) + "\n", encoding="utf-8")
    if ns.yaml:
        yaml_io.save(bundle, out / "detections.yaml")
    if ns.json:
        yaml_io.save(bundle, out / "detections.json")
    _print_issues(bundle, ns.verbose)
    print(json.dumps(summary(bundle), indent=2))
    return 1 if bundle.errors else 0


def cmd_load(ns: argparse.Namespace) -> int:
    bundle = load_paths(ns.paths, _opts(ns))
    _print_issues(bundle, ns.verbose)
    if ns.list:
        for d in bundle.detections:
            flag = "~" if d.approximate else " "
            print(f"{flag} {d.source.frontend if d.source else 'dsl':8} {d.paradigm:11} {d.id}")
    print(json.dumps(summary(bundle), indent=2))
    return 1 if bundle.errors else 0


def cmd_event(ns: argparse.Namespace) -> int:
    lib = DetectionLibrary.load(*ns.paths, options=_opts(ns))
    payload = json.loads(Path(ns.event).read_text(encoding="utf-8"))
    event = event_from_audit_log(payload) if "protoPayload" in payload else payload
    obs = lib.observing(event)
    print(
        json.dumps(
            {
                "event": event,
                "observed": obs.observed,
                "observed_by": obs.observed_by,
                "fires_single": obs.fires_single,
                "unknown": obs.unknown,
                "approximate": obs.approximate,
            },
            indent=2,
        )
    )
    return 0


def cmd_admits(ns: argparse.Namespace) -> int:
    lib = DetectionLibrary.load(*ns.paths, options=_opts(ns))
    for d in lib.admitting(ns.method, service=ns.service):
        print(f"{'~' if d.approximate else ' '} {d.id}")
    return 0


def _tri(t: object) -> str:
    return "yes" if t is True else "no" if t is False else "unknown"


def cmd_trace(ns: argparse.Namespace) -> int:
    from decnique.eval import fires, matches_footprint

    lib = DetectionLibrary.load(*ns.paths, options=_opts(ns))
    raw = json.loads(Path(ns.events).read_text(encoding="utf-8"))
    entries = raw if isinstance(raw, list) else [raw]
    events = [event_from_audit_log(e) if "protoPayload" in e else e for e in entries]

    detections = []
    for d in lib.detections:
        t = fires(d.spec, events)
        if t is not False or ns.all_rules:
            detections.append(
                {"id": d.id, "fires": _tri(t), "approximate": d.approximate, "paradigm": d.paradigm}
            )
    candidates = [
        {"id": c.id, "matches": _tri(matches_footprint(c.footprint, events))}
        for c in lib.bundle.candidates
    ]
    print(
        json.dumps(
            {"events": len(events), "detections": detections, "candidates": candidates}, indent=2
        )
    )
    return 0


def cmd_show(ns: argparse.Namespace) -> int:
    for f in ns.files:
        b = load_file(Path(f), _opts(ns))
        sys.stdout.write(fmt.bundle(b))
        _print_issues(b, True)
    return 0


def _print_issues(bundle, verbose: bool) -> None:  # type: ignore[no-untyped-def]
    for i in bundle.issues:
        if i.severity == "error" or verbose:
            print(f"{i.severity}: {i.file}: {i.message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="decnique.cli",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("parse")
    p.add_argument("files", nargs="+")
    p.add_argument("--yaml", action="store_true")
    p.set_defaults(fn=cmd_parse)

    p = sub.add_parser("fmt")
    p.add_argument("files", nargs="+")
    p.add_argument("--write", action="store_true")
    p.set_defaults(fn=cmd_fmt)

    for name, fn in (
        ("import", cmd_import),
        ("load", cmd_load),
        ("event", cmd_event),
        ("trace", cmd_trace),
        ("admits", cmd_admits),
        ("show", cmd_show),
    ):
        p = sub.add_parser(name)
        p.add_argument("paths" if name != "show" else "files", nargs="+")
        p.add_argument("--all-platforms", action="store_true", help="do not restrict to GCP rules")
        p.add_argument("--deprecated", action="store_true", help="include deprecated rules")
        p.add_argument("-v", "--verbose", action="store_true")
        if name == "import":
            p.add_argument("-o", "--output", required=True)
            p.add_argument("--yaml", action="store_true")
            p.add_argument("--json", action="store_true")
        if name == "load":
            p.add_argument("--list", action="store_true")
        if name == "event":
            p.add_argument(
                "-e",
                "--event",
                required=True,
                help="JSON file: event-model dict or a Cloud Audit Log entry",
            )
        if name == "trace":
            p.add_argument(
                "-e",
                "--events",
                required=True,
                help="JSON file: an ordered list of event-model dicts or Cloud Audit Log entries",
            )
            p.add_argument(
                "--all-rules",
                action="store_true",
                help="report every detection, not only those that fire / are uncertain",
            )
        if name == "admits":
            p.add_argument("-m", "--method", required=True)
            p.add_argument("--service")
        p.set_defaults(fn=fn)

    ns = ap.parse_args(argv)
    try:
        return int(ns.fn(ns))
    except (OSError, json.JSONDecodeError) as e:
        print(f"input error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
