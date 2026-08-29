"""The computing verbs driven end-to-end through `dispatch`, with their saved report checked:
the numbers on screen must be the numbers the engine proved."""

from __future__ import annotations

from decnique.ui.config import Settings
from decnique.ui.report import list_reports, load
from decnique.ui.repl import dispatch
from decnique.ui.session import Session


def _session(tmp_path) -> Session:
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, f"config report.dir {tmp_path / 'out'}")
    dispatch(s, "config report.format json")
    dispatch(s, "config report.save on")
    dispatch(s, "account examples/account.json")
    return s


def _last(tmp_path) -> dict:
    return load(list_reports(tmp_path / "out")[-1])


def test_blindspots_counts_gap_and_covered(tmp_path):
    s = _session(tmp_path)
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    assert dispatch(s, "blindspots iam.serviceAccountKeys.create resourcemanager.projects.setIamPolicy") is True
    doc = _last(tmp_path)
    assert doc["summary"]["covered"] == 1 and doc["summary"]["gaps"] == 1 and doc["summary"]["inconclusive"] == 0
    by = {it["label"]: it for it in doc["items"]}
    assert by["iam.serviceAccountKeys.create"]["verdict"] == "all_covered"
    assert by["resourcemanager.projects.setIamPolicy"]["verdict"] == "gap"
    assert by["resourcemanager.projects.setIamPolicy"]["event"]["method"] == "SetIamPolicy"


def test_blindspots_inconclusive_is_not_covered(tmp_path, monkeypatch):
    import decnique.smt.coverage as cov

    monkeypatch.setattr(cov, "find_gap", lambda p, lib, account, ctx=None: cov.NoGap(p, "exhausted"))
    s = _session(tmp_path)
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    dispatch(s, "blindspots iam.serviceAccountKeys.create")
    doc = _last(tmp_path)
    assert doc["summary"]["covered"] == 0 and doc["summary"]["inconclusive"] == 1
    assert doc["items"][0]["verdict"] == "exhausted"
    assert "not a proof" in doc["transcript"]
