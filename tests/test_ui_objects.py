"""The object-verb grammar: `<object> <verb> [args…]` — resolution, defaults, and the
inspection verbs of every object (rules / candidates / checks / events / account)."""

from __future__ import annotations

from decnique.ui.commands import ASK, OBJECTS, RULES
from decnique.ui.config import Settings
from decnique.ui.repl import dispatch, resolve
from decnique.ui.session import Session
from decnique.ui.theme import console


def _session(tmp_path) -> Session:
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    return s


def _capture(s: Session, line: str) -> str:
    console.record = True
    console.export_text(clear=True)
    assert dispatch(s, line) is True
    out = console.export_text(clear=True)
    console.record = False
    return out


def test_resolve_object_verb_and_defaults():
    obj, verb, rest = resolve(["rules", "inspect", "d"])
    assert obj is RULES and verb.name == "inspect" and rest == ["d"]
    obj, verb, rest = resolve(["rules"])  # bare object → its default verb
    assert verb.name == "list" and rest == []
    obj, verb, rest = resolve(["rules", "~foo"])  # not a verb → default verb with the word as argument
    assert verb.name == "list" and rest == ["~foo"]
    assert isinstance(resolve(["ask"]), str)  # ask has no default: the math is never run by accident
    assert isinstance(resolve(["ask", "nope"]), str) and isinstance(resolve(["nope"]), str)
    assert set(ASK.verbs) == {"blindspots", "stealth", "chains", "check", "suggest"}
    for obj in OBJECTS.values():  # every verb has a one-line help and a detail page
        for v in obj.verbs.values():
            assert v.help and v.detail


def test_rules_inspect_and_dsl(tmp_path):
    s = _session(tmp_path)
    assert "no rules loaded" in _capture(s, "rules inspect d")
    dispatch(s, 'detection d { event method = "SetIamPolicy" and unknown("secops:unsupported") }')
    out = _capture(s, "rules inspect d")
    assert "SetIamPolicy" in out and "approx" in out and "could not be translated" in out.lower() or "unknown" in out
    out = _capture(s, "rules dsl d")
    assert out.strip().startswith("detection d {") and "╭" not in out  # plain text, no frame
    assert "no detection named" in _capture(s, "rules dsl zzz")
    assert "usage" in _capture(s, "rules dsl")


def test_candidates_and_checks_inspect(tmp_path):
    s = _session(tmp_path)
    dispatch(s, "candidates load examples/candidates_advanced.decn")
    assert s.lib is not None and s.lib.bundle.candidates
    cid = s.lib.bundle.candidates[0].id
    out = _capture(s, f"candidates inspect {cid}")
    assert "required" in out and "step " in out and "gains" in out
    assert _capture(s, f"candidates dsl {cid}").strip().startswith(f"candidate {cid} {{")
    dispatch(s, "checks load examples/checks.decn")
    assert s.lib.bundle.checks
    ck = s.lib.bundle.checks[0].id
    out = _capture(s, f"checks inspect {ck}")
    assert "question" in out and f"ask check {ck}" in out
    assert _capture(s, f"checks dsl {ck}").strip().startswith(f"check {ck} {{")
    assert "load it first" in _capture(s, "ask check examples/checks.decn")  # running never loads


def test_events_list_inspect_and_account_show(tmp_path):
    s = _session(tmp_path)
    assert "no events loaded" in _capture(s, "events list")
    dispatch(s, "events load examples/events.json")
    out = _capture(s, "events")
    assert "events — 7" in out and "SetIamPolicy" in out
    out = _capture(s, "events inspect 4")
    assert '"method": "SetIamPolicy"' in out
    assert "usage" in _capture(s, "events inspect 99") and "usage" in _capture(s, "events inspect x")
    assert "no account loaded" in _capture(s, "account")
    dispatch(s, "account load examples/account.json")
    out = _capture(s, "account show")
    assert "demo-prod" in out and "principals" in out and "data access log" in out


def test_load_says_when_the_object_was_not_in_the_files(tmp_path):
    s = _session(tmp_path)
    out = _capture(s, "rules load examples/candidates.decn")
    assert "brought no detections" in out
    out = _capture(s, "checks load examples/candidates.decn")
    assert "brought no checks" in out
    assert "usage" in _capture(s, "candidates load")
