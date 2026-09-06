"""End to end, the whole way through: four SIEMs on disk -> one language -> an answer.

This is the walk-through in `README.md` run for real.  A directory holds the same detections
written the way each vendor writes them (YARA-L, Sigma, Elastic, Panther, and one native
`.decn`); the loader recognises them by content, the front-ends lower them into one DSL, and
the engine answers `blindspots` / `stealth` / `check` against a concrete account.

Three properties are worth an end-to-end test rather than a unit test, because each one can
only break where the layers meet:

* **the four front-ends compose** — rules from different vendors end up in one library and
  cover for each other;
* **a witness is real** — the event the solver returns for a gap is replayed through the
  oracle here, exactly as invariant #2 requires, so "gap" cannot mean "the encoder forgot";
* **the toolchain closes** — rules exported as an AST document load back as the same rules.
"""

from __future__ import annotations

import json

import pytest

from decnique.detections import DetectionLibrary
from decnique.dsl import format as fmt
from decnique.dsl.loader import LoadOptions, load_paths

pytestmark = pytest.mark.e2e

ACCOUNT = "examples/accounts/custom/account.json"
CANDIDATES = "examples/candidates/candidates.decn"
KEY_METHOD = "google.iam.admin.v1.CreateServiceAccountKey"
KEY_PERM = "iam.serviceAccountKeys.create"
IAM_PERM = "resourcemanager.projects.setIamPolicy"

YARAL = f"""
rule gcp_service_account_key_created {{
  meta:
    author = "security"
    description = "GCP: a service account key was created"
  events:
    $e.metadata.product_event_type = "{KEY_METHOD}"
  condition:
    $e
}}
"""

# the same rule with one more conjunct — narrow enough that an event with the right method
# but another event type slips past it
YARAL_NARROW = YARAL.replace(
    "  condition:", '    $e.metadata.event_type = "USER_RESOURCE_CREATION"\n  condition:'
)

SIGMA = """
title: GCP bucket read by a service account
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: gcp
  service: gcp.audit
detection:
  sel:
    gcp.audit.method_name: 'storage.objects.get'
  condition: sel
"""

ELASTIC = """
[rule]
name = "GCP access token minted"
type = "query"
language = "kuery"
query = 'event.dataset:gcp.audit and event.action:"iam.serviceAccounts.getAccessToken"'
risk_score = 47
severity = "medium"
rule_id = "22222222-2222-2222-2222-222222222222"
description = "gcp: short-lived credentials were minted"
"""

PANTHER_YML = """
AnalysisType: rule
RuleID: GCP.Logging.Sink.Deleted
LogTypes: [GCP.AuditLog]
Enabled: true
Severity: High
Filename: sink_deleted.py
Description: gcp logging sink removed
"""

PANTHER_PY = """
def rule(event):
    return event.deep_get("protoPayload", "methodName") == "google.logging.v2.ConfigServiceV2.DeleteSink"
"""

DECN = 'detection native_secret_read { event method = "SecretManagerService.AccessSecretVersion" }\n'


@pytest.fixture
def rules_dir(tmp_path):
    """A rule directory shaped like a real one: several vendors, several sub-folders."""
    d = tmp_path / "rules"
    (d / "gcp").mkdir(parents=True)
    (d / "gcp" / "key_created.yaral").write_text(YARAL)
    (d / "bucket_read.yml").write_text(SIGMA)
    (d / "token_minted.toml").write_text(ELASTIC)
    (d / "sink_deleted.yml").write_text(PANTHER_YML)
    (d / "sink_deleted.py").write_text(PANTHER_PY)
    (d / "native.decn").write_text(DECN)
    return d


# --- the loader over a mixed directory ---------------------------------------------------


def test_every_front_end_contributes_to_one_library(rules_dir):
    bundle = load_paths([str(rules_dir)], LoadOptions())
    frontends = {d.source.frontend for d in bundle.detections if d.source}
    assert frontends == {"secops", "sigma", "elastic", "panther", "dsl"}
    assert not bundle.errors, bundle.errors


def test_rules_from_different_vendors_answer_about_the_same_event(rules_dir):
    """The whole premise: once lowered, a YARA-L rule and a `.decn` rule are comparable."""
    lib = DetectionLibrary.load(str(rules_dir))
    obs = lib.observing({"method": KEY_METHOD, "event_type": "USER_RESOURCE_CREATION"})
    assert obs.observed is True
    assert list(obs.observed_by) == ["gcp_service_account_key_created"]
    minted = lib.observing({"method": "iam.serviceAccounts.getAccessToken"})
    assert list(minted.observed_by) == ["elastic_22222222_2222_2222_2222_222222222222"]


# --- the shell, over that directory ------------------------------------------------------


def test_the_documented_walkthrough_runs_and_finds_the_gap(run_cli, rules_dir, tmp_path):
    """`rules load` → `account load` → `ask blindspots`, as a script, exactly as documented."""
    script = tmp_path / "session.txt"
    script.write_text(
        f"rules load {rules_dir}\n"
        f"candidates load {CANDIDATES}\n"
        f"account load {ACCOUNT}\n"
        f"ask blindspots {KEY_PERM}\n"
        f"ask blindspots {IAM_PERM}\n"
    )
    r = run_cli("run.py", "-f", str(script))
    assert r.code == 0, r.err
    assert KEY_PERM in r.out and IAM_PERM in r.out


def test_the_key_rule_closes_the_key_permission_but_not_the_iam_one(run_cli, rules_dir):
    watched = run_cli("run.py", "--fail-on", "finding", "--rules", str(rules_dir),
                      "--account", ACCOUNT, "ask", "blindspots", KEY_PERM)
    assert watched.code == 0, watched.err
    unwatched = run_cli("run.py", "--fail-on", "finding", "--rules", str(rules_dir),
                        "--account", ACCOUNT, "ask", "blindspots", IAM_PERM)
    assert unwatched.code == 2, "nothing in this directory watches project IAM changes"


def test_one_extra_conjunct_reopens_a_permission_that_looked_covered(run_cli, tmp_path):
    """The finding the tool exists to produce: the rule still names the right method, but the
    added `event_type` test means an event with that method and another type goes unseen."""
    narrow = tmp_path / "narrow"
    narrow.mkdir()
    (narrow / "key_created.yaral").write_text(YARAL_NARROW)
    r = run_cli("run.py", "--json", "--fail-on", "finding", "--rules", str(narrow),
                "--account", ACCOUNT, "ask", "blindspots", KEY_PERM)
    assert r.code == 2
    (gap,) = [it for it in r.json()["items"] if it["verdict"] == "gap"]
    assert gap["event"]["method"] == KEY_METHOD  # the very method the rule names


def test_the_witness_for_a_gap_really_is_unobserved(run_cli, rules_dir):
    """Invariant #2 across the process boundary: take the event the engine printed and replay
    it through the oracle.  If any loaded rule fired on it, the finding was a lie."""
    r = run_cli("run.py", "--json", "--rules", str(rules_dir), "--account", ACCOUNT,
                "ask", "blindspots", IAM_PERM)
    assert r.code == 0, r.err
    gaps = [it for it in r.json()["items"] if it["verdict"] == "gap"]
    assert gaps, r.out
    lib = DetectionLibrary.load(str(rules_dir))
    for gap in gaps:
        obs = lib.observing(gap["event"])
        assert obs.observed is not True, (gap["event"], obs.observed_by)


def test_a_check_block_is_answered_over_the_loaded_corpus(run_cli, rules_dir, tmp_path):
    checks = tmp_path / "checks.decn"
    checks.write_text(
        f"check keys_watched {{ type coverage permission {KEY_PERM} }}\n"
        f"check iam_watched {{ type coverage permission {IAM_PERM} }}\n"
    )
    r = run_cli("run.py", "--json", "--rules", str(rules_dir), str(checks),
                "--account", ACCOUNT, "ask", "check")
    assert r.code == 0, r.err
    verdicts = {it["label"]: it["verdict"] for it in r.json()["items"]}
    assert verdicts["keys_watched"] == "pass"
    assert verdicts["iam_watched"] == "fail"


def test_stealth_is_answered_for_the_example_techniques(run_cli, rules_dir):
    r = run_cli("run.py", "--json", "--rules", str(rules_dir), CANDIDATES,
                "--account", ACCOUNT, "ask", "stealth")
    assert r.code == 0, r.err
    verdicts = {it["label"]: it["verdict"] for it in r.json()["items"]}
    assert verdicts, r.out
    assert set(verdicts.values()) <= {"evasive", "not_feasible", "always_detected", "exhausted"}


# --- saved runs --------------------------------------------------------------------------


def test_two_runs_can_be_saved_listed_and_compared(run_cli, rules_dir, tmp_path):
    """`reports diff` is how a team sees "did last night's change open a hole?"."""
    out = tmp_path / "reports"
    before = run_cli("run.py", "--rules", str(rules_dir), "--account", ACCOUNT,
                     "--report", str(out), "--format", "json",
                     "ask", "blindspots", KEY_PERM, IAM_PERM)
    assert before.code == 0, before.err
    only_native = tmp_path / "only_native.decn"
    only_native.write_text(DECN)
    after = run_cli("run.py", "--rules", str(only_native), "--account", ACCOUNT,
                    "--report", str(out), "--format", "json",
                    "ask", "blindspots", KEY_PERM, IAM_PERM)
    assert after.code == 0, after.err
    saved = sorted(out.glob("blindspots-*.json"), key=lambda p: p.name)
    assert len(saved) == 2, saved
    gaps = [
        {it["label"] for it in json.loads(p.read_text())["items"] if it["verdict"] == "gap"}
        for p in saved
    ]
    assert gaps == [{IAM_PERM}, {IAM_PERM, KEY_PERM}]  # dropping the rules opened the key one

    script = tmp_path / "diff.txt"
    script.write_text(
        f"config report.dir {out}\nreports list\nreports diff {saved[0].name} {saved[1].name}\n"
    )
    r = run_cli("run.py", "-f", str(script))
    assert r.code == 0, r.err
    flat = " ".join(r.out.split())  # the table is line-wrapped for the terminal
    assert "1 finding(s) changed" in flat


def test_a_saved_run_records_what_was_loaded(run_cli, rules_dir, tmp_path):
    out = tmp_path / "reports"
    r = run_cli("run.py", "--rules", str(rules_dir), "--account", ACCOUNT,
                "--report", str(out), "--format", "json", "ask", "blindspots", KEY_PERM)
    assert r.code == 0, r.err
    doc = json.loads(next(out.glob("blindspots-*.json")).read_text())
    assert doc["verb"] == "blindspots"
    assert doc["library"]["rules"] == 5
    assert doc["transcript"]


# --- the toolchain closes on itself -------------------------------------------------------


def test_native_rules_exported_as_an_ast_document_load_back_unchanged(run_cli, rules_dir, tmp_path):
    out = tmp_path / "exported"
    r = run_cli("-m", "decnique.cli", "import", str(rules_dir), "-o", str(out), "--json")
    assert r.code == 0, r.err
    original = DetectionLibrary.load(str(rules_dir))
    reloaded = DetectionLibrary.load(str(out / "detections.json"))
    assert {d.id for d in reloaded.detections} == {d.id for d in original.detections}
    for d in original.detections:
        assert reloaded.bundle.detection(d.id).spec == d.spec


def test_each_rule_also_survives_as_canonical_dsl_text(run_cli, rules_dir, tmp_path):
    """`import` writes one `.decn` per rule; re-loading that directory must give the same
    specs — invariant §5 (`parse(format(x)) == x`) across every front-end at once."""
    out = tmp_path / "exported"
    assert run_cli("-m", "decnique.cli", "import", str(rules_dir), "-o", str(out)).code == 0
    original = DetectionLibrary.load(str(rules_dir))
    reloaded = DetectionLibrary.load(str(out))
    for d in original.detections:
        # the canonical text is the comparison: it is what `parse(format(x)) == x` is about
        assert fmt.detection(reloaded.bundle.detection(d.id)) == fmt.detection(d)
