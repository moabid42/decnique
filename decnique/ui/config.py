"""User settings for the shell — a small registry, persisted as JSON.

Every setting is declared once in :data:`REGISTRY` (key, allowed values, default, help), so
``config`` can list, validate, and explain them, and new settings are one line to add.
Values live in ``~/.config/decnique/config.json`` (override with ``$DECNIQUE_CONFIG``).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Setting:
    key: str
    choices: tuple[str, ...]  # empty = free text
    default: str
    help: str


REGISTRY: dict[str, Setting] = {
    s.key: s
    for s in (
        Setting(
            "blindspots.explain",
            ("rules", "formula", "both", "words"),
            "rules",
            "how blindspots explains a permission's blind region: "
            "'rules' = per kind of change, which rules catch it / which conditions it dodges; "
            "'formula' = the blind region as a formula over the rules' own tests; 'both'; "
            "'words' = plain-English sentences — HARD-CODED, only knows GCP IAM binding deltas "
            "(action/role/member) and a few role/member patterns; everything else falls back "
            "to the rules' syntax (see ui/words.py)",
        ),
        Setting(
            "blindspots.raw",
            ("off", "on"),
            "off",
            "also print the raw witness event (every field) under the sentence",
        ),
        Setting(
            "report.save",
            ("off", "on"),
            "off",
            "save every blindspots / stealth / chains / check run to a report file you can "
            "reopen later with `report <file>` (useful when the output is too long to read)",
        ),
        Setting(
            "report.format",
            ("md", "json", "yaml"),
            "md",
            "report file format: 'md' = readable Markdown for sharing (the data is embedded "
            "at the end, so it reloads too); 'json' = machine-readable; 'yaml' = same, "
            "human-editable",
        ),
        Setting(
            "report.dir",
            (),
            "reports",
            "folder the report files go to (relative to where you run decnique)",
        ),
    )
}


def config_path() -> Path:
    env = os.environ.get("DECNIQUE_CONFIG")
    if env:
        return Path(env)
    return Path.home() / ".config" / "decnique" / "config.json"


class Settings:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config_path()
        self._values: dict[str, str] = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._values = {k: str(v) for k, v in raw.items() if k in REGISTRY}
        except (OSError, ValueError):
            pass

    def get(self, key: str) -> str:
        return self._values.get(key, REGISTRY[key].default)

    def set(self, key: str, value: str, *, persist: bool = True) -> None:
        """``persist=False`` sets the value for this process only (batch flags must not
        rewrite the user's config file)."""
        if key not in REGISTRY:
            raise KeyError(f"unknown setting {key!r}; known: {', '.join(REGISTRY)}")
        spec = REGISTRY[key]
        if spec.choices and value not in spec.choices:
            raise ValueError(f"{key} must be one of {', '.join(spec.choices)} (got {value!r})")
        self._values[key] = value
        if persist:
            self.save()

    def reset(self, key: str) -> None:
        self._values.pop(key, None)
        self.save()

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._values, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass  # settings still apply for this session

    def rows(self) -> list[tuple[str, str, str, str]]:
        """(key, current value, allowed values, help) for every registered setting."""
        return [
            (k, self.get(k), " | ".join(s.choices) if s.choices else "<text>", s.help)
            for k, s in REGISTRY.items()
        ]
