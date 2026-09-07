"""Elastic front-end: TOML rules and the KQL subset, without the private corpus.

Elastic rules were only ever translated in tests that need the vendored corpus, so the KQL
parser and the rule-type handling ran nowhere on a clean checkout.  Each test below names one
way a mistranslation would show up in an answer: a rule that covers too much, a threshold that
silently disappears, or a GCP rule that never loads at all.
"""

from __future__ import annotations

import pytest

from decnique.dsl.interpret import evaluate
from decnique.frontends.elastic import (
    is_elastic_gcp,
    load_elastic_file,
    load_elastic_text,
    lower_elastic,
    parse_kql,
)
from decnique.model.predicates import Cmp, Const, Exists, Like, Not, Pred, Unknown, unknowns


def _toml(query: str, **extra: str) -> str:
    head = (
        '[metadata]\nmaturity = "production"\nintegration = ["gcp"]\n\n'
        '[rule]\nrule_id = "abc-123"\nname = "Test rule"\n'
        'index = ["logs-gcp.audit-*"]\nlanguage = "kuery"\ntype = "query"\n'
    )
    for k, v in extra.items():
        head += f"{k} = {v}\n"
    return head + f'query = """\n{query}\n"""\n'


def _pred(query: str) -> Pred:
    b = load_elastic_text(_toml(query), "r.toml")
    assert b.detections, b.issues
    return b.detections[0].spec.events[0].pred


def _kql(query: str) -> Pred:
    return parse_kql(query, [])


# --- what loads ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ({"metadata": {"integration": ["gcp"]}, "rule": {}}, True),
        ({"metadata": {"integration": "gcp"}, "rule": {}}, True),  # a bare string, not a list
        ({"metadata": {}, "rule": {"index": ["logs-gcp.audit-*"]}}, True),
        ({"metadata": {}, "rule": {"query": "gcp.audit.method_name:*"}}, True),
        ({"metadata": {"integration": ["aws"]}, "rule": {"index": ["logs-aws-*"]}}, False),
    ],
)
def test_is_elastic_gcp(doc, expected):
    """A rule for another cloud in the library would answer questions about the wrong events."""
    assert is_elastic_gcp(doc) is expected


def test_a_non_gcp_rule_is_skipped_unless_all_platforms_are_asked_for():
    text = '[rule]\nrule_id = "x"\nname = "n"\nindex = ["logs-aws-*"]\nquery = """\nevent.action:foo\n"""\n'
    assert load_elastic_text(text, "aws.toml").detections == ()
    assert load_elastic_text(text, "aws.toml", gcp_only=False).detections


def test_a_deprecated_rule_loads_only_when_asked_for():
    text = _toml("event.action:SetIamPolicy").replace('maturity = "production"', 'maturity = "deprecated"')
    assert load_elastic_text(text, "d.toml").detections == ()
    b = load_elastic_text(text, "d.toml", include_deprecated=True)
    assert b.detections and b.detections[0].meta["maturity"] == "deprecated"


def test_broken_toml_is_a_load_error_not_a_crash():
    b = load_elastic_text("[rule\nname = ", "broken.toml")
    assert b.detections == () and any("elastic toml" in i.message for i in b.errors)


def test_a_toml_file_that_is_not_a_rule_is_ignored():
    assert load_elastic_text('[metadata]\nmaturity = "production"\n', "notarule.toml").detections == ()


def test_load_elastic_file_reads_from_disk(tmp_path):
    p = tmp_path / "r.toml"
    p.write_text(_toml("event.action:SetIamPolicy"))
    assert load_elastic_file(p).detections[0].id == "elastic_abc_123"


def test_a_rule_without_an_id_is_named_after_its_file():
    doc = {"rule": {"name": "n", "query": "event.action:X"}}
    d, _ = lower_elastic(doc, "some/dir/my_rule.toml")
    assert d.id == "elastic_my_rule"


def test_metadata_including_mitre_technique_ids_survives():
    text = _toml("event.action:SetIamPolicy", severity='"high"', risk_score="73", description='"d"')
    text += (
        '\n[[rule.threat]]\nframework = "MITRE ATT&CK"\n'
        '[[rule.threat.technique]]\nid = "T1098"\nname = "Account Manipulation"\n'
        '[[rule.threat.technique.subtechnique]]\nid = "T1098.001"\nname = "Additional Cloud Credentials"\n'
    )
    d = load_elastic_text(text, "r.toml").detections[0]
    assert d.meta["severity"] == "high" and d.meta["risk_score"] == 73
    assert d.meta["mitre_attack_technique_id"] == "T1098,T1098.001"


# --- rule types ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rtype", "language", "label"),
    [
        ("eql", "eql", "elastic:eql"),
        ("esql", "esql", "elastic:esql"),
        ("machine_learning", "kuery", "elastic:machine_learning"),
        ("query", "lucene", "elastic:query:lucene"),
    ],
)
def test_a_rule_we_cannot_read_is_a_dont_know_never_true(rtype, language, label):
    text = _toml("any where true", type=f'"{rtype}"', language=f'"{language}"').replace(
        'type = "query"\n', "", 1
    ).replace('language = "kuery"\n', "", 1)
    d = load_elastic_text(text, "r.toml").detections[0]
    assert isinstance(d.spec.events[0].pred, Unknown)
    assert label in d.source.unsupported


def test_a_new_terms_rule_keeps_its_query_and_flags_the_new_terms_part():
    text = _toml("event.action:SetIamPolicy", type='"new_terms"').replace('type = "query"\n', "", 1)
    text += '\n[rule.new_terms]\nfield = "new_terms_fields"\nvalue = ["user.name"]\n'
    d = load_elastic_text(text, "r.toml").detections[0]
    assert "elastic:new_terms" in d.source.unsupported
    # the query half still constrains: a different method cannot match
    assert evaluate(d.spec.events[0].pred, {"method": "other"}) is False


def test_a_threshold_rule_keeps_its_query_and_flags_the_count():
    text = _toml("event.action:SetIamPolicy", type='"threshold"').replace('type = "query"\n', "", 1)
    text += '\n[rule.threshold]\nfield = ["user.name"]\nvalue = 5\n'
    d = load_elastic_text(text, "r.toml").detections[0]
    assert "elastic:threshold" in d.source.unsupported
    assert "elastic:threshold" in {u.label for u in unknowns(d.spec.events[0].pred)}


# --- KQL -------------------------------------------------------------------------------------


def test_a_field_value_pair_is_a_case_insensitive_equality():
    p = _pred("event.action:SetIamPolicy")
    assert p == Cmp(field=(None, "method"), op="=", value="SetIamPolicy", nocase=True)
    assert evaluate(p, {"method": "setiampolicy"}) is True


def test_a_quoted_value_keeps_its_spaces():
    assert _pred('user_agent.original:"Google Cloud SDK"').value == "Google Cloud SDK"


def test_a_star_value_asks_only_that_the_field_is_present():
    assert _pred("user.email:*") == Exists(field=(None, "principal"))


def test_a_wildcard_value_becomes_a_glob_and_an_escaped_star_stays_literal():
    p = _pred("event.action:*.SetIamPolicy")
    assert isinstance(p, Like)
    assert evaluate(p, {"method": "v1.SetIamPolicy"}) is True
    assert isinstance(_kql("event.action:lit\\*eral"), Cmp)  # \\* is a literal star, not a glob


def test_and_or_not_and_parentheses():
    p = _pred("(event.action:A or event.action:B) and not source.ip:10.0.0.1")
    assert evaluate(p, {"method": "A", "caller_ip": "1.2.3.4"}) is True
    assert evaluate(p, {"method": "A", "caller_ip": "10.0.0.1"}) is False


def test_a_value_group_expands_over_one_field():
    p = _pred("event.action:(A or B)")
    assert evaluate(p, {"method": "B"}) is True
    assert evaluate(p, {"method": "C"}) is False


def test_a_value_group_supports_and_not_and_nesting():
    p = _pred("user_agent.original:(curl and not (wget or lynx))")
    assert isinstance(p, Pred)
    negated = _kql("event.action:(not A)")
    assert isinstance(negated, Not)


@pytest.mark.parametrize("op", ["<", "<=", ">", ">="])
def test_range_operators_become_numeric_comparisons(op):
    p = _kql(f"http.response.bytes {op} 1000")
    assert isinstance(p, Cmp) and p.op == op and p.value == 1000


def test_a_non_numeric_range_bound_is_kept_as_text():
    p = _kql("@timestamp >= now-1d")
    assert isinstance(p, Cmp) and p.value == "now-1d"


def test_event_outcome_reads_as_the_granted_flag():
    assert _pred("event.outcome:success") == Cmp(field=(None, "granted"), op="=", value=True)
    assert _pred("event.outcome:failure").value is False


def test_a_boolean_word_on_a_non_name_field_is_a_boolean():
    assert _pred("gcp.audit.authorization_info.granted:true").value is True
    assert _kql("user_agent.original:true").value is True
    # …but a method literally called "true" is still a string
    assert _pred("event.action:true").value == "true"


def test_an_unrecognised_outcome_word_stays_a_string():
    assert _kql("event.outcome:unknown").value == "unknown"


def test_the_gcp_dataset_marker_is_implied_by_the_loader_scope():
    assert _kql("event.dataset:gcp.audit") == Const(value=True)


def test_another_dataset_value_stays_an_equality_and_never_collapses_to_true():
    """Collapsing an unrelated dataset test to `true` once made rules cover every event."""
    p = _kql("event.dataset:azure.activitylogs")
    assert isinstance(p, Cmp) and p.value == "azure.activitylogs"


def test_a_derived_ecs_field_is_a_dont_know_not_a_free_field():
    """`event.category` is computed by the integration; a free value would invent a blind spot."""
    p = _kql("event.category:iam")
    assert isinstance(p, Unknown) and p.label == "elastic:derived_field"


def test_free_text_search_is_a_dont_know():
    p = _kql("SetIamPolicy")
    assert isinstance(p, Unknown) and p.label == "elastic:kql_free_text"


@pytest.mark.parametrize(
    "query",
    [
        "event.action:",  # value missing
        "event.action:(A or",  # unclosed group
        "(event.action:A",  # unclosed parenthesis
        "event.action:A )",  # trailing tokens
        ":A",  # no field
        "event.action:(:)",  # junk inside a group
        "(event.action:A event.action:B)",  # a group that never closes
        "event.action:(A B)",  # two values with no operator
        "event.action:>",  # an operator where a value belongs
        "event.action:(not (A B))",  # a nested group that never closes
    ],
)
def test_an_unreadable_query_is_a_dont_know_never_true(query):
    unsupported: list[str] = []
    p = parse_kql(query, unsupported)
    assert isinstance(p, Unknown) and p.label == "elastic:kql"
    assert any(u.startswith("kql:") for u in unsupported)


def test_elastic_rules_do_not_require_every_field_to_be_present():
    """KQL has no zero-value guard: a test on a missing field is false, not unknown."""
    d = load_elastic_text(_toml("event.action:SetIamPolicy"), "r.toml").detections[0]
    assert d.spec.options.allow_zero_values
    assert evaluate(d.spec.events[0].pred, {"method": "other"}) is False
