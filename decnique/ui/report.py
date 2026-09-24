"""Saved runs: what a math verb found, written to a file you can reopen and re-read.

A :class:`Report` holds the structured facts a verb produced (``summary`` + one dict per
``item``: permission / technique / hop / check) and the full on-screen transcript.  It is
written as Markdown (readable, with the data embedded as JSON at the end so it reloads),
JSON, or YAML — ``load`` reads any of the three back.  Nothing here computes; it only records.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

_FENCE = "```json"


@dataclass
class Report:
    verb: str
    args: list[str]
    started: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    summary: dict = field(default_factory=dict)
    items: list[dict] = field(default_factory=list)
    transcript: str = ""
    library: dict = field(default_factory=dict)  # what was loaded: rule count, paths, account

    def add(self, label: str, verdict: str, detail: str = "", **extra) -> None:  # type: ignore[no-untyped-def]
        """One finding: a permission / technique / rule / hop, with what was proven about it."""
        self.items.append({"label": label, "verdict": verdict, "detail": detail, **extra})

    def to_dict(self) -> dict:
        return {
            "verb": self.verb, "args": self.args, "started": self.started, "library": self.library,
            "summary": self.summary, "items": self.items, "transcript": self.transcript,
        }


def _plain(o):  # type: ignore[no-untyped-def]
    """JSON-safe copy: tuples/sets → lists, frozensets sorted, everything else via str()."""
    if isinstance(o, dict):
        return {str(k): _plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_plain(v) for v in o]
    if isinstance(o, (set, frozenset)):
        return sorted(_plain(v) for v in o)
    if isinstance(o, (str, int, float, bool)) or o is None:
        return o
    return str(o)


def to_json(r: Report) -> str:
    return json.dumps(_plain(r.to_dict()), indent=2, ensure_ascii=False) + "\n"


def witness_entries(r: Report, finding: int | None = None) -> Iterator[dict]:
    """Export event and trace evidence, including check rows, without losing multiplicity."""
    from decnique.detections import to_audit_log

    if finding is not None and not 1 <= finding <= len(r.items):
        raise ValueError(f"finding must be between 1 and {len(r.items)}")
    clock = 0
    for i, item in enumerate(r.items, 1):
        base = clock + int(item.get("delay", 0)) if r.verb == "chains" else 0
        if r.verb == "chains":
            clock = base + max((int(e.get("time", 0)) for e in item.get("schedule", [])), default=0)
        if finding is not None and i != finding:
            continue
        caveats = list(dict.fromkeys([*r.library.get("assumptions", []),
                                     *r.summary.get("caveats", []), *item.get("caveats", [])]))
        provenance = {"finding": i, "label": item["label"], "verdict": item["verdict"],
                      "verb": r.verb, "caveats": caveats,
                      "approximate": bool(caveats or item.get("approximate") or
                                          r.summary.get("tag") == "approximate")}
        sources = [(None, item), *enumerate(item.get("rows", []), 1)]
        for row_number, source in sources:
            metadata = dict(provenance)
            if row_number is not None:
                metadata.update(row=row_number, row_label=source["label"], row_verdict=source["verdict"])
            for key in ("event", "schedule", "witness"):
                evidence = source.get(key)
                events = [evidence] if isinstance(evidence, dict) else evidence or []
                for event in events:
                    if r.verb == "chains":
                        event = {**event, "time": int(event.get("time", 0)) + base}
                    yield {**to_audit_log(event), "_decnique": dict(metadata)}


def to_yaml(r: Report) -> str:
    import yaml

    return yaml.safe_dump(_plain(r.to_dict()), sort_keys=False, allow_unicode=True, width=100)


def to_markdown(r: Report) -> str:
    d = _plain(r.to_dict())
    lines = [f"# decnique `{r.verb}` — {r.started}", ""]
    if r.args:
        lines += [f"arguments: `{' '.join(r.args)}`", ""]
    def show(v):  # type: ignore[no-untyped-def]
        return ", ".join(map(str, v)) if isinstance(v, list) else v

    if r.library:
        lines += ["## loaded", ""] + [f"- **{k}**: {show(v)}" for k, v in d["library"].items()] + [""]
    if r.summary:
        lines += ["## summary", ""] + [f"- **{k}**: {v}" for k, v in d["summary"].items()] + [""]
    if r.items:
        lines += ["## findings", "", "| # | label | verdict | detail |", "|---|---|---|---|"]
        for i, it in enumerate(d["items"], 1):
            cells = [str(i), it.get("label", ""), it.get("verdict", ""), it.get("detail", "")]
            lines.append("| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
        lines.append("")
    if r.transcript:
        lines += ["## transcript", "", "```text", r.transcript.rstrip("\n"), "```", ""]
    lines += ["## data", "", "<!-- the run as JSON, so `reports show <file>` can reload this Markdown -->",
              _FENCE, json.dumps(d, indent=2, ensure_ascii=False), "```", ""]
    return "\n".join(lines)


WRITERS = {"json": to_json, "yaml": to_yaml, "md": to_markdown}


def save(r: Report, directory: Path | str, fmt: str) -> Path:
    """Write the report as ``<verb>-<timestamp>.<fmt>`` under ``directory``; return the path."""
    if fmt not in WRITERS:
        raise ValueError(f"unknown report format {fmt!r}; one of {', '.join(WRITERS)}")
    stamp = r.started.replace(":", "").replace("-", "")
    path = Path(directory) / f"{r.verb}-{stamp}.{fmt}"
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 1  # two runs of one verb in the same second must not clobber each other
    while path.exists():
        n += 1
        path = Path(directory) / f"{r.verb}-{stamp}_{n}.{fmt}"
    path.write_text(WRITERS[fmt](r), encoding="utf-8")
    return path


def load(path: Path | str) -> dict:
    """Read a saved report (any of the three formats) back into its dict form."""
    text = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()
    if suffix == ".md":
        m = re.search(rf"{re.escape(_FENCE)}\n(.*?)\n```\s*$", text, re.S)
        if not m:
            raise ValueError(f"{path}: no embedded data block — not a decnique report")
        return json.loads(m.group(1))
    if suffix in (".yaml", ".yml"):
        import yaml

        return yaml.safe_load(text)
    return json.loads(text)


def list_reports(directory: Path | str) -> list[Path]:
    d = Path(directory)
    if not d.is_dir():
        return []
    return sorted((p for p in d.iterdir() if p.suffix in (".md", ".json", ".yaml", ".yml")), reverse=True)
