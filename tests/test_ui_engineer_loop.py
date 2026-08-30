"""The detection engineer's loop: export a witness for the SIEM, get a rule that closes the
gap, define it, confirm; and diff two runs."""

from __future__ import annotations

import json

from decnique.detections import event_from_audit_log, to_audit_log
from decnique.ui.config import Settings
from decnique.ui.report import list_reports
from decnique.ui.repl import dispatch
from decnique.ui.session import Session

_D = "target.resource.attribute.labels[ser_binding_deltas_%s]"


def test_audit_log_round_trip():
    ev = {"method": "SetIamPolicy", "service": "cloudresourcemanager.googleapis.com", "principal": "a@x.com",
          "permission": ["resourcemanager.projects.setIamPolicy"], "granted": True, "resource": "projects/demo",
          "caller_ip": "1.2.3.4", "user_agent": "gcloud", "log_name": "projects/demo/logs/cloudaudit.googleapis.com%2Factivity",
          "udm": {_D % "action": "ADD", _D % "role": "roles/owner", _D % "member": "user:a@x.com", "severity": "NOTICE"}}
    entry = to_audit_log(ev)
    assert entry["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] == [{"action": "ADD", "role": "roles/owner", "member": "user:a@x.com"}]
    assert entry["protoPayload"]["authorizationInfo"][0] == {"permission": "resourcemanager.projects.setIamPolicy", "granted": True, "resource": "projects/demo"}
    back = event_from_audit_log(entry)
    for k in ("method", "service", "principal", "permission", "granted", "resource", "caller_ip", "user_agent", "log_name"):
        assert back[k] == ev[k], k
    assert back["udm"] == {"severity": "NOTICE"}  # deltas moved to their real place; the rest stays raw


def _session(tmp_path) -> Session:
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, f"config report.dir {tmp_path / 'out'}")
    dispatch(s, "config report.format json")
    dispatch(s, "account examples/account.json")
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    role = _D % "role"
    dispatch(s, 'detection owner { event method = "SetIamPolicy" and udm("' + role + '") = "roles/owner" }')
    return s


def test_export_suggest_define_and_diff(tmp_path):
    s = _session(tmp_path)
    assert dispatch(s, "export x.json") is True  # nothing to export yet: a message, not an error
    dispatch(s, "config report.save on")
    dispatch(s, "blindspots resourcemanager.projects.setIamPolicy")
    before = list_reports(tmp_path / "out")[0]
    out = tmp_path / "witness.json"
    assert dispatch(s, f"export {out}") is True
    entries = json.loads(out.read_text())
    assert entries and entries[0]["protoPayload"]["methodName"] == "SetIamPolicy"
    assert entries[0]["_decnique"]["label"] == "resourcemanager.projects.setIamPolicy"
    # suggest rules and define them: the gap must close
    assert dispatch(s, "suggest resourcemanager.projects.setIamPolicy define") is True
    ids = [d.id for d in s.lib.detections]
    # the only atom the rules test on this permission (role = roles/owner) is watched, so no
    # targeted rule is needed; the catch-all closes the rest
    assert "watch_resourcemanager_projects_setIamPolicy" in ids
    dispatch(s, "blindspots resourcemanager.projects.setIamPolicy")
    assert s.last_report.items[0]["verdict"] == "all_covered"  # the gap is closed
    after = list_reports(tmp_path / "out")[0]
    assert after != before  # same-second runs get distinct files
    assert json.loads(after.read_text())["items"][0]["verdict"] == "all_covered"
    assert dispatch(s, f"report diff {before.name} {after.name}") is True
    assert dispatch(s, "suggest iam.serviceAccountKeys.create") is True  # covered: nothing to close
