"""Panther front-end: the ``.yml`` rule file, and the regex scraper of last resort.

`load_panther_file` and the literal scraper only ever ran against the vendored corpus, so a
clean checkout never exercised them.  What breaks when they are wrong: a rule that is silently
dropped (the library under-counts what is watched), a threshold that disappears (the rule looks
stricter than it is), or a scraped literal attached to the wrong field.
"""

from __future__ import annotations

import pytest

from decnique.dsl.interpret import evaluate
from decnique.frontends.panther import (
    is_panther_gcp,
    load_panther_file,
    lower_panther,
)
from decnique.model.predicates import In, Unknown, unknowns
from decnique.model.trace import Count

_YML = """AnalysisType: rule
RuleID: GCP.IAM.SetIamPolicy
DisplayName: IAM policy changed
Enabled: true
Severity: High
Description: someone changed a policy
LogTypes:
    - GCP.AuditLog
Filename: gcp_iam.py
Reports:
    MITRE ATT&CK:
        - privilege_escalation:T1098
"""

# a body the evaluator cannot read at all — the front-end then falls back to scraping literals
_OPAQUE = "    if pattern_match(event, 'x'):\n        return False\n"


def _write(tmp_path, yml: str = _YML, py: str | None = None, py_name: str = "gcp_iam.py"):
    (tmp_path / "rule.yml").write_text(yml)
    if py is not None:
        (tmp_path / py_name).write_text(py)
    return tmp_path / "rule.yml"


def _scraped(body: str):
    """The predicate the scraper recovers from a ``rule()`` it cannot evaluate."""
    py = "from panther_base_helpers import pattern_match\n\ndef rule(event):\n" + _OPAQUE + body
    d, unsupported = lower_panther({"AnalysisType": "rule", "RuleID": "r", "LogTypes": ["GCP.AuditLog"]}, py, "r.yml")
    assert "panther:python_logic" in unsupported, "expected the scraper, not the evaluator"
    return d.spec.events[0].pred


# --- the .yml file ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ({"LogTypes": ["GCP.AuditLog"]}, True),
        ({"RuleID": "GCP.Something"}, True),
        ({"LogTypes": ["AWS.CloudTrail"], "RuleID": "AWS.Rule"}, False),
    ],
)
def test_is_panther_gcp(doc, expected):
    """A rule for another cloud must not end up in a GCP library."""
    assert is_panther_gcp(doc) is expected


def test_a_rule_loads_with_its_python_file_and_metadata(tmp_path):
    p = _write(tmp_path, py='def rule(event):\n    return event.deep_get("protoPayload", "methodName") == "SetIamPolicy"\n')
    d = load_panther_file(p).detections[0]
    assert d.id == "panther_GCP_IAM_SetIamPolicy"
    assert d.meta["severity"] == "High" and d.meta["enabled"] is True
    assert d.meta["mitre_attack_technique_id"] == "T1098"
    assert evaluate(d.spec.events[0].pred, {"method": "SetIamPolicy"}) is True


def test_a_missing_python_file_leaves_the_logic_unknown_not_true(tmp_path):
    d = load_panther_file(_write(tmp_path)).detections[0]
    assert "panther:python_logic" in d.source.unsupported
    assert evaluate(d.spec.events[0].pred, {"method": "anything"}) is None


def test_a_non_gcp_file_is_skipped_unless_all_platforms_are_asked_for(tmp_path):
    yml = _YML.replace("GCP.AuditLog", "AWS.CloudTrail").replace("RuleID: GCP.", "RuleID: AWS.")
    p = _write(tmp_path, yml, py="def rule(event):\n    return True\n")
    assert load_panther_file(p).detections == ()
    assert load_panther_file(p, gcp_only=False).detections


def test_a_gcp_named_file_that_is_not_a_gcp_rule_is_dropped(tmp_path):
    """The cheap text test says "GCP." somewhere; the document test is the one that decides."""
    yml = _YML.replace("- GCP.AuditLog", "- AWS.CloudTrail\nDedupPeriodMinutes: 60  # not GCP.AuditLog")
    yml = yml.replace("RuleID: GCP.IAM.SetIamPolicy", "RuleID: AWS.Rule")
    assert load_panther_file(_write(tmp_path, yml)).detections == ()


def test_a_yaml_file_that_is_not_a_rule_is_ignored(tmp_path):
    assert load_panther_file(_write(tmp_path, "AnalysisType: policy\nRuleID: GCP.X\n")).detections == ()


def test_broken_yaml_is_a_load_error_not_a_crash(tmp_path):
    b = load_panther_file(_write(tmp_path, "AnalysisType: rule\nGCP.: [\n  bad: indent\n"))
    assert b.detections == () and any("panther yaml" in i.message for i in b.errors)


def test_an_unreadable_rule_is_reported_as_a_warning(tmp_path):
    b = load_panther_file(_write(tmp_path, py="def rule(event):\n    return frobnicate(event)\n"))
    assert any("unsupported constructs" in i.message for i in b.issues)


def test_a_rule_without_an_id_is_named_after_its_file():
    d, _ = lower_panther({"AnalysisType": "rule", "LogTypes": ["GCP.AuditLog"]}, None, "dir/my_rule.yml")
    assert d.id == "panther_my_rule"


def test_a_threshold_becomes_a_count_over_the_dedup_window():
    """Dropping the threshold would make the rule look like it fires on a single event."""
    doc = {
        "AnalysisType": "rule",
        "RuleID": "GCP.Many",
        "LogTypes": ["GCP.AuditLog"],
        "Threshold": 5,
        "DedupPeriodMinutes": 30,
    }
    d, _ = lower_panther(doc, 'def rule(event):\n    return event.deep_get("protoPayload", "methodName") == "SetIamPolicy"\n', "r.yml")
    assert d.spec.condition == Count("e", ">=", 5)
    assert d.spec.window.seconds == 30 * 60
    assert d.meta["threshold"] == 5


def test_a_correlation_rule_is_a_dont_know_that_names_what_it_correlates():
    doc = {
        "AnalysisType": "correlation_rule",
        "RuleID": "GCP.Chain",
        "LogTypes": ["GCP.AuditLog"],
        "Detection": [{"Group": [{"RuleID": "GCP.A"}, {"RuleID": "GCP.B"}]}],
    }
    d, unsupported = lower_panther(doc, None, "r.yml")
    assert "panther:correlation_rule" in unsupported
    assert d.meta["correlates"] == "GCP.A,GCP.B"
    assert evaluate(d.spec.events[0].pred, {"method": "SetIamPolicy"}) is None


def test_a_data_model_rule_over_an_unnamed_event_type_still_translates():
    """`event.udm("event_type") == "literal"` is not the data-model idiom; it must not crash."""
    d, _ = lower_panther(
        {"AnalysisType": "rule", "RuleID": "GCP.X", "LogTypes": ["GCP.AuditLog"]},
        'def rule(event):\n    return event.udm("event_type") == "ADMIN_ROLE_ASSIGNED"\n',
        "r.yml",
    )
    assert unknowns(d.spec.events[0].pred)  # a string compare against the data model: don't know


def test_a_partly_readable_body_names_the_construct_it_could_not_read():
    py = (
        'def rule(event):\n'
        '    if event.deep_get("protoPayload", "methodName") != "storage.objects.get":\n'
        '        return False\n'
        '    return event.deep_get("protoPayload", "resourceName", default="").split("/")[-1] == "s"\n'
    )
    d, unsupported = lower_panther({"AnalysisType": "rule", "RuleID": "r", "LogTypes": ["GCP.AuditLog"]}, py, "r.yml")
    assert any(u.startswith("panther:python:") for u in unsupported)
    assert evaluate(d.spec.events[0].pred, {"method": "SetIamPolicy"}) is False


# --- the scraper of last resort ---------------------------------------------------------------


def test_the_scraper_never_claims_more_than_a_dont_know_alongside_the_literals():
    p = _scraped('    return method == "SetIamPolicy"\n')
    assert "panther:python_logic" in {u.label for u in unknowns(p)}
    assert evaluate(p, {"method": "SetIamPolicy"}) is None  # never "fires"
    assert evaluate(p, {"method": "storage.objects.get"}) is False  # but the literal still bounds it


def test_the_scraper_reads_equality_endswith_startswith_and_substring_tests():
    for body, fires_on in [
        ('    return method_name == "SetIamPolicy"\n', "SetIamPolicy"),
        ('    return method_name.endswith(".setIamPolicy")\n', "v1.setIamPolicy"),
        ('    return method_name.startswith("storage.")\n', "storage.objects.get"),
        ('    return "SetIamPolicy" in method_name\n', "v1.SetIamPolicy"),
    ]:
        p = _scraped(body)
        assert evaluate(p, {"method": fires_on}) is None, body
        assert evaluate(p, {"method": "unrelated.method.name"}) is False, body


def test_the_scraper_reads_a_literal_method_set():
    p = _scraped('    return method_name in ("SetIamPolicy", "storage.buckets.delete")\n')
    assert evaluate(p, {"method": "storage.buckets.delete"}) is None
    assert evaluate(p, {"method": "other.method.here"}) is False


def test_the_scraper_reads_a_module_level_method_constant():
    py = (
        "from panther_base_helpers import pattern_match\n"
        'ADMIN_METHODS = ["SetIamPolicy", "google.iam.admin.v1.CreateServiceAccountKey"]\n\n'
        "def rule(event):\n" + _OPAQUE + "    return method_name in ADMIN_METHODS\n"
    )
    d, _ = lower_panther({"AnalysisType": "rule", "RuleID": "r", "LogTypes": ["GCP.AuditLog"]}, py, "r.yml")
    ins = [x for x in _leaves(d.spec.events[0].pred) if isinstance(x, In)]
    assert ins and set(ins[0].values) == {"SetIamPolicy", "google.iam.admin.v1.CreateServiceAccountKey"}


def test_a_negated_method_set_is_not_scraped_as_the_method_list():
    """`method not in (...)` fires on *other* methods; reading it as the list inverts the rule."""
    p = _scraped('    return method_name not in ("SetIamPolicy", "storage.buckets.delete")\n')
    assert not [x for x in _leaves(p) if isinstance(x, In) and x.field == (None, "method")]
    assert evaluate(p, {"method": "SetIamPolicy"}) is None  # nothing is claimed either way
    assert evaluate(p, {"method": "other.method.name"}) is None


def test_a_not_equal_method_test_is_also_left_open():
    p = _scraped('    return method_name != "SetIamPolicy"\n')
    assert "panther:negated_method_test" in {u.label for u in unknowns(p)}


def test_a_literal_next_to_another_field_is_not_read_as_a_method():
    """A `logName` test in the same expression must not be attached to `method`."""
    p = _scraped('    return log_name.endswith("cloudaudit.googleapis.com%2Factivity")\n')
    assert evaluate(p, {"method": "anything.at.all"}) is None  # nothing was pinned to the method


def test_the_scraper_reads_permission_literals():
    p = _scraped('    return permission == "iam.serviceAccounts.actAs"\n')
    perms = [x for x in _leaves(p) if isinstance(x, In) and x.field == (None, "permission")]
    assert perms and perms[0].values == ("iam.serviceAccounts.actAs",)


def _leaves(p):
    kids = getattr(p, "children", None)
    if kids is not None:
        return [x for c in kids for x in _leaves(c)]
    child = getattr(p, "child", None)
    if child is not None:
        return _leaves(child)
    return [p]


def test_a_syntactically_broken_python_file_is_a_dont_know(tmp_path):
    d = load_panther_file(_write(tmp_path, py="def rule(event:\n    return True\n")).detections[0]
    assert isinstance(d.spec.events[0].pred, Unknown) or unknowns(d.spec.events[0].pred)
    assert evaluate(d.spec.events[0].pred, {"method": "x"}) is None
