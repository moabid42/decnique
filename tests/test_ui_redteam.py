"""The red teamer's side: a chain is planned from candidate `gains` and the account (no attack
block needed), shown as a timed schedule, and exported as a replayable plan."""

from __future__ import annotations

import json

from decnique.dsl.parser import parse_text
from decnique.answers import techniques_for
from decnique.ui.config import Settings
from decnique.ui.report import list_reports, load
from decnique.ui.repl import dispatch
from decnique.ui.session import Session

_KEY = "google.iam.admin.v1.CreateServiceAccountKey"
_TOKEN = "iam.serviceAccounts.getAccessToken"


def test_techniques_come_from_gains_or_effects_override():
    lib = __import__("decnique.detections", fromlist=["DetectionLibrary"]).DetectionLibrary(parse_text(f'''
candidate ck {{ required {{ iam.serviceAccountKeys.create }} footprint {{ a: "{_KEY}" }} gains {{ {_TOKEN} }} }}
candidate noeffect {{ required {{ {_TOKEN} }} footprint {{ a: "{_TOKEN}" }} }}
''', "t.decn"))
    from decnique.env.model import Account

    techs = techniques_for(lib, Account())
    assert [t.id for t in techs] == ["ck"] and techs[0].gains == (_TOKEN,)  # noeffect has no gain
    over = techniques_for(lib, Account(), {"noeffect": ["x.y.z"]})
    assert {t.id for t in over} == {"ck", "noeffect"}


def _session(tmp_path) -> Session:
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, f"config report.dir {tmp_path / 'out'}")
    dispatch(s, "config report.format json")
    dispatch(s, "config report.save on")
    dispatch(s, "load examples/candidates.decn")
    dispatch(s, "account examples/account.json")
    return s


def test_chains_plans_from_flags_and_exports(tmp_path):
    s = _session(tmp_path)
    ok = dispatch(s, "chains resourcemanager.projects.setIamPolicy "
                     "--from attacker@demo.iam.gserviceaccount.com --start iam.serviceAccountKeys.create")
    assert ok is True
    doc = load(list_reports(tmp_path / "out")[0])  # newest first
    assert doc["summary"]["found"] is True and doc["summary"]["hops"] == 2
    assert [it["label"] for it in doc["items"]] == ["hop 1: create_service_account_key", "hop 2: mint_access_token"]
    assert "t (s)" in " ".join(doc["transcript"].split())  # the timed schedule table
    # export the plan
    out = tmp_path / "plan.json"
    assert dispatch(s, f"export {out}") is True
    entries = json.loads(out.read_text())
    assert {e["protoPayload"]["methodName"] for e in entries} == {_KEY, _TOKEN}
    assert all("_decnique" in e for e in entries)


def test_chains_without_a_goal_explains(tmp_path):
    s = _session(tmp_path)
    assert dispatch(s, "chains") is True  # no goal → a helpful message, not a crash


def test_chains_needs_a_technique_with_gains(tmp_path):
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, 'candidate x { required { iam.serviceAccountKeys.create } footprint { a: "m" } }')
    dispatch(s, "account examples/account.json")
    assert dispatch(s, "chains resourcemanager.projects.setIamPolicy") is True  # message: no gains


def test_always_detected_names_the_catching_rules(tmp_path):
    from decnique.ui.repl import EXIT_CLEAN, main

    rules = tmp_path / "r.decn"
    T = "iam.serviceAccounts.getAccessToken"
    rules.write_text(f'detection watch {{ event method = "{T}" }}\n'
                     f'candidate use {{ required {{ {T} }} footprint {{ u: "{T}" }} }}\n'
                     f'check c {{ type candidate for use }}\n')
    acct = tmp_path / "a.json"
    acct.write_text('{"version":1,"bindings":{"a@x.com":[{"permission":"iam.serviceAccounts.getAccessToken"}]},'
                    '"logging":{"admin_activity":true,"data_access_services":["iamcredentials.googleapis.com"]}}')
    s = Session()
    from decnique.ui.config import Settings
    s.settings = Settings(tmp_path / "cfg.json")
    dispatch(s, f"load {rules}")
    dispatch(s, f"account {acct}")
    dispatch(s, "stealth use")
    assert s.last_report.items[0]["verdict"] == "always_detected"
    assert s.last_report.items[0]["caught_by"] == ["watch"]
    dispatch(s, "check c")
    assert "caught by watch" in s.last_report.items[0]["detail"]


def test_methods_verb(tmp_path):
    s = Session()
    from decnique.ui.config import Settings
    s.settings = Settings(tmp_path / "cfg.json")
    assert dispatch(s, "methods iam.serviceAccountKeys.create") is True  # no account: guard message
    dispatch(s, "account examples/account.json")
    assert dispatch(s, "methods iam.serviceAccountKeys.create") is True
    assert dispatch(s, "methods no.such.permission") is True
