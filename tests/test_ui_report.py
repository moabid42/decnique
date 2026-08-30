"""Saved runs: every format round-trips, verbs save when asked, and `help <verb>` explains."""

from __future__ import annotations

import pytest

from decnique.ui.config import Settings
from decnique.ui.report import Report, list_reports, load, save
from decnique.ui.commands import OBJECTS, SHELL
from decnique.ui.repl import dispatch
from decnique.ui.session import Session


def _report() -> Report:
    r = Report("blindspots", ["iam.serviceAccountKeys.create"], started="2026-08-29T10:00:00")
    r.summary = {"gaps": 1, "covered": 0}
    r.add("iam.serviceAccountKeys.create", "gap", "one | pipe", event={"method": "M", "udm": {"a[b]": "x"}},
          caveats=("c1",), watched=frozenset({"w"}))
    r.transcript = "▸ section\n    ✗ gap"
    return r


@pytest.mark.parametrize("fmt", ["md", "json", "yaml"])
def test_roundtrip_every_format(tmp_path, fmt):
    path = save(_report(), tmp_path, fmt)
    assert path.name == f"blindspots-20260829T100000.{fmt}"
    doc = load(path)
    assert doc["verb"] == "blindspots" and doc["summary"] == {"gaps": 1, "covered": 0}
    it = doc["items"][0]
    assert it["event"]["udm"]["a[b]"] == "x" and it["caveats"] == ["c1"] and it["watched"] == ["w"]
    assert doc["transcript"].startswith("▸ section")
    assert list_reports(tmp_path) == [path]
    with pytest.raises(ValueError):
        save(_report(), tmp_path, "xml")


def test_markdown_is_readable_and_escapes_pipes(tmp_path):
    text = save(_report(), tmp_path, "md").read_text(encoding="utf-8")
    assert "| 1 | iam.serviceAccountKeys.create | gap | one \\| pipe |" in text
    assert "```text\n▸ section" in text and text.rstrip().endswith("```")


def test_verbs_save_reports_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("DECNIQUE_CONFIG", str(tmp_path / "cfg.json"))
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, f"config report.dir {tmp_path / 'out'}")
    dispatch(s, "config report.format json")
    dispatch(s, "account load examples/account.json")
    dispatch(s, 'detection d { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    dispatch(s, "check c { type coverage permission iam.serviceAccountKeys.create }")
    dispatch(s, "ask check c")
    assert list_reports(tmp_path / "out") == []  # saving is off by default
    dispatch(s, "config report.save on")
    dispatch(s, "ask check c")
    files = list_reports(tmp_path / "out")
    assert len(files) == 1 and files[0].suffix == ".json"
    doc = load(files[0])
    assert doc["verb"] == "check" and doc["summary"]["pass"] == 1 and doc["library"]["rules"] == 1
    assert "PASS" in doc["transcript"]
    assert dispatch(s, f"reports show {files[0].name}") is True and dispatch(s, "reports list") is True


def test_help_covers_every_verb(tmp_path):
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    assert dispatch(s, "help") is True
    for obj in OBJECTS.values():
        assert dispatch(s, f"help {obj.name}") is True
        for verb in obj.verbs.values():
            assert verb.detail, f"{obj.name} {verb.name} has no help page"
            assert dispatch(s, f"help {obj.name} {verb.name}") is True
    for word in SHELL:
        assert dispatch(s, f"help {word}") is True
    assert dispatch(s, "config ask blindspots") is True  # verb help, not a setting lookup
    assert dispatch(s, "help nope") is True and dispatch(s, "rules nope") is True and dispatch(s, "nope") is True
    assert dispatch(s, "config report.format") is True
