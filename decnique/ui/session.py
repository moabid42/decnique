"""The REPL's mutable state: a loaded rule library, an account model, and an event trace.

Loading is the only place the UI mutates anything.  Each loader reports what it took in, in
one calm line, so the bottom toolbar and every later verb have a known footing.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

from decnique.detections import DetectionLibrary, event_from_audit_log
from decnique.dsl.ast import Bundle
from decnique.dsl.loader import LoadOptions
from decnique.dsl.parser import parse_text

from .config import Settings
from .report import Report, save
from .theme import CHECK, console


def _merge_bundles(old: Bundle, new: Bundle) -> Bundle:
    """Merge ``new`` into ``old``; an item whose id is redefined in ``new`` replaces the old
    one (so re-loading a rule set, or a same-id block typed at the prompt, updates in place).
    Everything else from ``old`` is kept — loading is additive, not a reset."""
    ids = {i.id for i in (*new.detections, *new.candidates, *new.checks, *new.rulesets)}
    kept = Bundle(
        tuple(d for d in old.detections if d.id not in ids),
        tuple(c for c in old.candidates if c.id not in ids),
        tuple(c for c in old.checks if c.id not in ids),
        tuple(r for r in old.rulesets if r.id not in ids),
        old.issues,
    )
    return kept + new


def _events_from(raw: object) -> list[dict]:
    entries = raw if isinstance(raw, list) else [raw]
    return [event_from_audit_log(e) if "protoPayload" in e else e for e in entries]


class Session:
    def __init__(self) -> None:
        self.lib: DetectionLibrary | None = None
        self.paths: list[str] = []
        self.events: list[dict] = []
        self.events_src: str = ""
        self.options = LoadOptions()
        self.settings = Settings()
        self.account = None
        self.account_doc: dict = {}
        self.last_report: Report | None = None  # the most recent verb's findings (batch mode reads it)

    # -- loading ---------------------------------------------------------------------------

    def load(self, paths: list[str], want: str = "detections") -> None:
        """Load rule dirs / .decn files into the library (additive).  ``want`` is the object the
        user asked for (``detections`` / ``candidates`` / ``checks``) — only the usage line and a
        hint when the load brought none of that kind depend on it."""
        # flags mirror the CLI: --all (every platform, not just GCP), --deprecated
        flags = {a for a in paths if a.startswith("--")}
        paths = [a for a in paths if not a.startswith("--")]
        if not paths:
            obj = {"detections": "rules", "candidates": "candidates", "checks": "checks"}[want]
            console.print(
                f"[muted]usage:[/muted] {obj} load [--all] [--deprecated] <path> [path …]   "
                "(dirs or .decn/native rule files; default = GCP rules only, _deprecated skipped)"
            )
            return
        self.options = LoadOptions(
            gcp_only=not ({"--all", "--all-platforms"} & flags),
            include_deprecated="--deprecated" in flags,
        )
        new_lib = DetectionLibrary.load(*paths, options=self.options)
        this = new_lib.bundle  # what THIS load brought in (for the count and error lines)
        if self.lib is not None:
            merged = _merge_bundles(self.lib.bundle, this)
            self.lib = DetectionLibrary(merged, new_lib.ref_lists or self.lib.ref_lists)
            self.paths = list(dict.fromkeys([*self.paths, *paths]))  # accumulate, de-duped
        else:
            self.lib = new_lib
            self.paths = paths
        self._attest()
        b = self.lib.bundle
        errs = [i for i in this.issues if i.severity == "error"]
        console.print(
            f"[ok]{CHECK}[/ok] loaded [title]{len(b.detections)}[/title] detections, "
            f"[title]{len(b.candidates)}[/title] candidates, [title]{len(b.checks)}[/title] checks"
            + (f"  [err]{len(errs)} errors[/err]" if errs else "")
        )
        for i in errs:
            console.print(f"    [err]error[/err] {i.file}: {i.message}")
        if not getattr(this, want) and not errs:
            console.print(f"    [warn]note[/warn] these paths brought no {want}")

    def define(self, text: str, file: str = "<repl>") -> Bundle:
        """Parse DSL typed at the prompt (or read from a file) and merge it into the library.
        An item with an id already loaded replaces the old one, so a block can be re-typed."""
        new = parse_text(text, file)
        old = self.lib.bundle if self.lib is not None else Bundle()
        merged = _merge_bundles(old, new)
        self.lib = DetectionLibrary(merged, self.lib.ref_lists if self.lib is not None else None)
        for kind, items in (("detection", new.detections), ("candidate", new.candidates),
                            ("check", new.checks), ("ruleset", new.rulesets)):
            for i in items:
                console.print(f"[ok]{CHECK}[/ok] defined {kind} [key]{i.id}[/key]")
        return new

    def events_load(self, file: str) -> None:
        raw = json.loads(Path(file).read_text(encoding="utf-8"))
        self.events = _events_from(raw)
        self.events_src = file
        console.print(f"[ok]{CHECK}[/ok] loaded [title]{len(self.events)}[/title] events from {file}")

    def account_load(self, file: str, resource: str = "*") -> None:
        """``file`` is the tool's own account JSON, or a raw gcloud export (IAM policy /
        asset search) converted on the fly; ``resource`` scopes a plain IAM policy."""
        from decnique.env import account_from_dict, normalize_account_doc

        raw = json.loads(Path(file).read_text(encoding="utf-8"))
        self.account_doc = normalize_account_doc(raw, resource=resource, name=Path(file).stem)
        converted = self.account_doc is not raw
        self.account = account_from_dict(self.account_doc)
        self._attest()
        n = len(self.account.bindings)
        console.print(
            f"[ok]{CHECK}[/ok] loaded account [key]{self.account.name}[/key]: "
            f"[title]{n}[/title] principals" + ("  (converted from a gcloud export)" if converted else "")
        )
        if converted:
            da = self.account_doc["logging"]["data_access_services"]
            console.print(f"    Data Access logging: {', '.join(da) if da else 'off (Admin Activity only)'}")
        for note in self.account_doc.get("notes", []):
            console.print(f"    [warn]note[/warn] {note}")

    def _attest(self) -> None:
        """Method names the loaded rules test literally are real audit-log spellings: mark them
        verified in the account's catalog (generated entries start unverified)."""
        if self.lib is None or self.account is None:
            return
        from dataclasses import replace

        from decnique.dsl.interpret import spec_methods_literal

        names = {m for d in self.lib.detections for m in spec_methods_literal(d.spec)}
        self.account = replace(self.account, catalog=self.account.catalog.attest(names))

    # -- reports ---------------------------------------------------------------------------

    @contextmanager
    def report(self, verb: str, args: list[str]):
        """Collect a verb's findings; when `report.save` is on, record the screen too and write
        the file at the end (the path is printed, so long output is never lost)."""
        rep = Report(verb, list(args))
        rep.library = {
            "rules": len(self.lib.detections) if self.lib is not None else 0,
            "candidates": len(self.lib.bundle.candidates) if self.lib is not None else 0,
            "paths": list(self.paths),
            "account": self.account.name if self.account else None,
        }
        saving = self.settings.get("report.save") == "on"
        if saving:
            console.record = True
            console.export_text(clear=True)  # drop anything recorded before this verb
        try:
            yield rep
        finally:
            self.last_report = rep
            if saving:
                rep.transcript = console.export_text(clear=True)
                console.record = False
                try:
                    path = save(rep, self.settings.get("report.dir"), self.settings.get("report.format"))
                    console.print(f"[muted]saved report → [key]{path}[/key]  (reopen: reports show {path})[/muted]")
                except OSError as e:
                    console.print(f"[err]could not save report:[/err] {e}")

    # -- guards ----------------------------------------------------------------------------

    def need_lib(self) -> bool:
        if self.lib is None:
            console.print("[warn]no rules loaded[/warn] — run: [key]rules load <paths…>[/key]")
            return False
        return True

    def need_events(self) -> bool:
        if not self.events:
            console.print("[warn]no events loaded[/warn] — run: [key]events load <file.json>[/key]")
            return False
        return True

    def need_account(self) -> bool:
        if self.account is None:
            console.print("[warn]no account loaded[/warn] — run: [key]account load <file.json>[/key]")
            return False
        return True
