"""The computing verbs driven end-to-end through `dispatch`, with their saved report checked:
the numbers on screen must be the numbers the engine proved."""

from __future__ import annotations

import json

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
    return load(list_reports(tmp_path / "out")[0])  # newest first


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


def test_stealth_reports_unlogged_step_and_always_detected(tmp_path):
    s = _session(tmp_path)
    acct = tmp_path / "acct.json"
    acct.write_text(json.dumps({"version": 1, "name": "t", "bindings": {"a@x.com": [
        {"permission": "iam.serviceAccountKeys.create"}, {"permission": "storage.objects.get"}]},
        "logging": {"admin_activity": True, "data_access_services": []}}))  # data-access logging off
    dispatch(s, f"account {acct}")
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    dispatch(s, 'detection reads { event method = "storage.objects.get" }')
    dispatch(s, 'candidate mk { required { iam.serviceAccountKeys.create } '
                'footprint { a: "google.iam.admin.v1.CreateServiceAccountKey" } }')
    dispatch(s, 'candidate rd { required { storage.objects.get } footprint { a: "storage.objects.get" } }')
    assert dispatch(s, "stealth") is True
    doc = _last(tmp_path)
    by = {it["label"]: it for it in doc["items"]}
    assert by["mk"]["verdict"] == "always_detected"
    assert by["rd"]["verdict"] == "evasive" and by["rd"]["unlogged"] == ["storage.objects.get"]
    assert "logging gap" in doc["transcript"]
    assert doc["summary"] == {"evasive": 1, "techniques": 2}


def test_chains_replays_the_whole_path(tmp_path):
    s = _session(tmp_path)
    dispatch(s, "load examples/candidates.decn")
    dispatch(s, "account examples/account.json")
    dispatch(s, 'detection key_then_token { events { k: method = "google.iam.admin.v1.CreateServiceAccountKey"'
                '  t: method = "iam.serviceAccounts.getAccessToken" } join { k.principal = t.principal }'
                ' window 1h condition #k >= 1 and #t >= 1 }')
    assert dispatch(s, "chains") is True
    doc = _last(tmp_path)
    assert doc["summary"]["found"] is True
    delays = [it["delay"] for it in doc["items"]]
    assert 3601 in delays  # the search waited out the 1 h correlation window
    assert "replay of the whole path" in doc["transcript"] and "REJECTED" not in doc["transcript"]


def test_blindspots_names_why_rules_answered_dont_know(tmp_path):
    s = _session(tmp_path)
    dispatch(s, 'detection vague { event method = "SetIamPolicy" and unknown("secops:unsupported") }')
    dispatch(s, 'detection other { event method = "x" }')
    dispatch(s, "blindspots resourcemanager.projects.setIamPolicy")
    doc = _last(tmp_path)
    assert doc["items"][0]["verdict"] == "gap" and doc["items"][0]["approximate"] is True
    flat = " ".join(doc["transcript"].split())
    assert "1 rule(s) answered don't-know" in flat and "secops:unsupported ×1" in flat
    assert dispatch(s, "rules ~") is True and dispatch(s, "rules ~vag") is True


def test_blindspots_over_many_permissions_is_brief_and_summarised(tmp_path):
    s = _session(tmp_path)
    acct = tmp_path / "owner.json"
    acct.write_text(json.dumps({"version": 1, "name": "o", "bindings": {"o@x.com": [{"role": "roles/owner"}]},
                                "logging": {"admin_activity": True, "data_access_services": []}}))
    dispatch(s, f"account {acct}")
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    perms = ["iam.serviceAccountKeys.create", "resourcemanager.projects.setIamPolicy"] + [
        p for p in sorted(s.account.catalog.all_permissions()) if p.startswith("dns.")][:25]
    assert dispatch(s, "blindspots " + " ".join(perms)) is True
    doc = _last(tmp_path)
    flat = " ".join(doc["transcript"].split())
    assert f"[1/{len(perms)}]" in flat and "by service" in flat
    assert doc["summary"]["covered"] == 1 and doc["summary"]["gaps"] >= 1
    assert doc["summary"]["unnamed"] == doc["summary"]["gaps"]  # no rule names a dns/setIamPolicy method
    assert "no rule names any of its" in flat
