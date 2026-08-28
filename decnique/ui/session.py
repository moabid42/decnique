"""The REPL's mutable state: a loaded rule library, an account model, and an event trace.

Loading is the only place the UI mutates anything.  Each loader reports what it took in, in
one calm line, so the bottom toolbar and every later verb have a known footing.
"""

from __future__ import annotations

import json
from pathlib import Path

from decnique.detections import DetectionLibrary, event_from_audit_log
from decnique.dsl.loader import LoadOptions

from .theme import CHECK, console


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
        self.account = None
        self.account_doc: dict = {}

    # -- loading ---------------------------------------------------------------------------

    def load(self, paths: list[str]) -> None:
        # flags mirror the CLI: --all (every platform, not just GCP), --deprecated
        flags = {a for a in paths if a.startswith("--")}
        paths = [a for a in paths if not a.startswith("--")]
        if not paths:
            console.print(
                "[muted]usage:[/muted] load [--all] [--deprecated] <path> [path …]   "
                "(dirs or .decn/native rule files; default = GCP rules only, _deprecated skipped)"
            )
            return
        self.options = LoadOptions(
            gcp_only=not ({"--all", "--all-platforms"} & flags),
            include_deprecated="--deprecated" in flags,
        )
        self.lib = DetectionLibrary.load(*paths, options=self.options)
        self.paths = paths
        b = self.lib.bundle
        errs = [i for i in b.issues if i.severity == "error"]
        console.print(
            f"[ok]{CHECK}[/ok] loaded [title]{len(b.detections)}[/title] detections, "
            f"[title]{len(b.candidates)}[/title] candidates"
            + (f"  [err]{len(errs)} errors[/err]" if errs else "")
        )
        for i in errs:
            console.print(f"    [err]error[/err] {i.file}: {i.message}")

    def events_load(self, file: str) -> None:
        raw = json.loads(Path(file).read_text(encoding="utf-8"))
        self.events = _events_from(raw)
        self.events_src = file
        console.print(f"[ok]{CHECK}[/ok] loaded [title]{len(self.events)}[/title] events from {file}")

    def account_load(self, file: str) -> None:
        from decnique.env import account_from_dict

        self.account_doc = json.loads(Path(file).read_text(encoding="utf-8"))
        self.account = account_from_dict(self.account_doc)
        n = len(self.account.bindings)
        console.print(
            f"[ok]{CHECK}[/ok] loaded account [key]{self.account.name}[/key]: "
            f"[title]{n}[/title] principals"
        )

    # -- guards ----------------------------------------------------------------------------

    def need_lib(self) -> bool:
        if self.lib is None:
            console.print("[warn]no rules loaded[/warn] — run: [key]load <paths…>[/key]")
            return False
        return True

    def need_events(self) -> bool:
        if not self.events:
            console.print("[warn]no events loaded[/warn] — run: [key]events <file.json>[/key]")
            return False
        return True

    def need_account(self) -> bool:
        if self.account is None:
            console.print("[warn]no account loaded[/warn] — run: [key]account <file.json>[/key]")
            return False
        return True
