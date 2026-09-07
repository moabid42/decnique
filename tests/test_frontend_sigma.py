"""Sigma front-end: the idioms real GCP rules use, without the private corpus.

Until now every Sigma construct below was only ever exercised by the vendored corpus, so a
machine without it (CI) never ran this code.  Each test names one thing that breaks in the
product: a modifier that silently changes meaning, a condition the parser mis-reads, or a
non-GCP rule that leaks into the library.
"""

from __future__ import annotations

import pytest

from decnique.dsl.interpret import evaluate
from decnique.frontends.sigma import (
    is_sigma_gcp,
    load_sigma_file,
    load_sigma_text,
    lower_sigma,
)
from decnique.model.predicates import (
    Cmp,
    InCidr,
    Like,
    Not,
    Pred,
    Regex,
    StrFn,
    Unknown,
    unknowns,
)

_HEAD = """
title: Set IAM policy
id: 11111111-2222-3333-4444-555555555555
status: experimental
level: high
author: tester
date: 2024/01/01
description: a rule
tags:
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: gcp
    service: gcp.audit
detection:
"""


def _rule(detection_block: str) -> object:
    b = load_sigma_text(_HEAD + detection_block, "r.yml")
    assert b.detections, b.issues
    return b.detections[0]


def _pred(detection_block: str) -> Pred:
    return _rule(detection_block).spec.events[0].pred


def _leaves(p: Pred) -> list[Pred]:
    kids = getattr(p, "children", None)
    if kids is not None:
        return [x for c in kids for x in _leaves(c)]
    child = getattr(p, "child", None)
    if child is not None:
        return _leaves(child)
    return [p]


# --- what counts as a GCP rule ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("logsource", "expected"),
    [
        ({"product": "gcp"}, True),
        ({"service": "gcp.audit"}, True),
        ({"product": "aws", "service": "cloudtrail"}, False),
        ("not-a-mapping", False),
    ],
)
def test_is_sigma_gcp(logsource, expected):
    """A non-GCP rule that slips into the library answers questions about the wrong cloud."""
    assert is_sigma_gcp({"logsource": logsource}) is expected


def test_a_non_gcp_file_is_skipped_entirely():
    text = "title: t\nlogsource:\n    product: aws\ndetection:\n    selection:\n        f: v\n    condition: selection\n"
    assert load_sigma_text(text, "aws.yml").detections == ()
    assert load_sigma_text(text, "aws.yml", gcp_only=False).detections  # …unless asked for all


def test_a_non_gcp_rule_inside_a_gcp_file_is_dropped():
    text = _HEAD + "    selection:\n        gcp.audit.method_name: A\n    condition: selection\n"
    text += "---\ntitle: other\nlogsource:\n    product: azure\ndetection:\n    selection:\n        f: v\n    condition: selection\n"
    b = load_sigma_text(text, "mixed.yml")
    assert len(b.detections) == 1


def test_a_document_without_a_detection_block_is_not_a_rule():
    text = _HEAD.replace("detection:\n", "") + "\n"
    assert load_sigma_text(text, "meta.yml").detections == ()


def test_broken_yaml_is_a_load_error_not_a_crash():
    b = load_sigma_text("product: gcp\ntitle: t\n  bad: [indent\n", "broken.yml")
    assert b.detections == () and any("sigma yaml" in i.message for i in b.errors)


def test_load_sigma_file_reads_from_disk(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text(_HEAD + "    selection:\n        gcp.audit.method_name: SetIamPolicy\n    condition: selection\n")
    assert load_sigma_file(p).detections[0].id.startswith("sigma_")


def test_metadata_and_id_survive_the_translation():
    d = _rule("    selection:\n        gcp.audit.method_name: SetIamPolicy\n    condition: selection\n")
    assert d.id == "sigma_11111111_2222_3333_4444_555555555555"
    assert d.meta["level"] == "high" and d.meta["author"] == "tester"
    assert d.meta["tags"] == "attack.privilege_escalation,attack.t1098"
    assert d.meta["logsource"] == "gcp.audit"


def test_a_rule_without_an_id_is_named_after_its_file():
    doc = {"title": "t", "logsource": {"product": "gcp"}, "detection": {"selection": {"gcp.audit.method_name": "X"}, "condition": "selection"}}
    d, unsupported = lower_sigma(doc, "some/dir/my_rule.yml")
    assert d.id == "sigma_my_rule" and not unsupported


# --- field clauses ---------------------------------------------------------------------------


def test_a_plain_value_is_a_case_insensitive_equality():
    p = _pred("    selection:\n        gcp.audit.method_name: SetIamPolicy\n    condition: selection\n")
    assert p == Cmp(field=(None, "method"), op="=", value="SetIamPolicy", nocase=True)
    assert evaluate(p, {"method": "setiampolicy"}) is True


def test_an_unmapped_field_becomes_a_raw_udm_field():
    p = _pred("    selection:\n        some.other.field: v\n    condition: selection\n")
    assert p.field == (None, "udm:some.other.field")


def test_a_list_of_values_is_an_or_and_the_all_modifier_makes_it_an_and():
    any_p = _pred("    selection:\n        gcp.audit.method_name:\n            - A\n            - B\n    condition: selection\n")
    assert evaluate(any_p, {"method": "A"}) is True
    all_p = _pred("    selection:\n        user_agent|contains|all:\n            - curl\n            - go\n    condition: selection\n")
    assert evaluate(all_p, {"udm": {"user_agent": "curl-go"}}) is True
    assert evaluate(all_p, {"udm": {"user_agent": "curl"}}) is False


def test_a_null_value_means_the_field_is_absent():
    p = _pred("    selection:\n        gcp.audit.request_metadata.caller_ip: null\n    condition: selection\n")
    assert isinstance(p, Not)
    assert evaluate(p, {"method": "X"}) is True


def test_the_re_modifier_becomes_a_regex():
    p = _pred("    selection:\n        gcp.audit.method_name|re: '.*SetIamPolicy$'\n    condition: selection\n")
    assert isinstance(p, Regex)
    assert evaluate(p, {"method": "v1.SetIamPolicy"}) is True


def test_the_cidr_modifier_becomes_a_network_test():
    p = _pred("    selection:\n        gcp.audit.request_metadata.caller_ip|cidr: 10.0.0.0/8\n    condition: selection\n")
    assert p == InCidr(field=(None, "caller_ip"), cidrs=("10.0.0.0/8",))


@pytest.mark.parametrize(("mod", "op"), [("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")])
def test_the_numeric_modifiers_become_comparisons(mod, op):
    p = _pred(f"    selection:\n        sent_bytes|{mod}: 1000\n    condition: selection\n")
    assert isinstance(p, Cmp) and p.op == op and p.value == 1000


def test_a_non_numeric_bound_is_kept_as_text_rather_than_crashing():
    p = _pred("    selection:\n        sent_bytes|gt: many\n    condition: selection\n")
    assert isinstance(p, Cmp) and p.value == "many"


def test_an_encoding_modifier_is_a_dont_know_not_a_guess():
    """base64 of a value is not the value: translating it as equality would invent a match."""
    p = _pred("    selection:\n        user_agent|base64: Y3VybA==\n    condition: selection\n")
    assert isinstance(p, Unknown) and p.label == "sigma:modifier:encoding"


def test_an_unknown_modifier_is_a_dont_know_and_is_reported():
    b = load_sigma_text(_HEAD + "    selection:\n        user_agent|fieldref: other\n    condition: selection\n", "r.yml")
    p = b.detections[0].spec.events[0].pred
    assert isinstance(p, Unknown) and "fieldref" in p.label
    assert any("unsupported constructs" in i.message for i in b.issues)


@pytest.mark.parametrize(("written", "expected"), [("true", True), ("false", False)])
def test_granted_reads_as_a_boolean_however_it_is_written(written, expected):
    p = _pred(f"    selection:\n        gcp.audit.authorization_info.granted: '{written}'\n    condition: selection\n")
    assert p == Cmp(field=(None, "granted"), op="=", value=expected)


def test_a_yaml_boolean_or_integer_stays_typed():
    p = _pred("    selection:\n        gcp.audit.authorization_info.granted: true\n    condition: selection\n")
    assert p.value is True
    q = _pred("    selection:\n        sent_bytes: 42\n    condition: selection\n")
    assert q.value == 42


@pytest.mark.parametrize(
    ("mod", "kind"), [("contains", "contains"), ("startswith", "startswith"), ("endswith", "endswith")]
)
def test_the_substring_modifiers_become_string_functions(mod, kind):
    p = _pred(f"    selection:\n        gcp.audit.method_name|{mod}: SetIam\n    condition: selection\n")
    assert isinstance(p, StrFn) and p.fn == kind and p.nocase


@pytest.mark.parametrize("mod", ["contains", "startswith", "endswith"])
def test_a_substring_modifier_with_a_wildcard_becomes_a_glob(mod):
    p = _pred(f"    selection:\n        gcp.audit.method_name|{mod}: 'Set*Policy'\n    condition: selection\n")
    assert isinstance(p, Like) and "Set*Policy" in p.pattern


def test_a_bare_wildcard_value_is_a_glob_and_an_escaped_one_is_a_literal():
    glob = _pred("    selection:\n        gcp.audit.method_name: '*.SetIamPolicy'\n    condition: selection\n")
    assert isinstance(glob, Like)
    assert evaluate(glob, {"method": "v1.SetIamPolicy"}) is True
    literal = _pred("    selection:\n        gcp.audit.method_name: 'lit\\*eral'\n    condition: selection\n")
    assert isinstance(literal, Cmp) and literal.value == "lit*eral"


def test_a_keywords_list_is_a_dont_know():
    """Free-text keywords search the whole record; nothing in the event model matches that."""
    b = load_sigma_text(_HEAD + "    keywords:\n        - 'setIamPolicy'\n    condition: keywords\n", "r.yml")
    d = b.detections[0]
    assert unknowns(d.spec.events[0].pred)
    assert any(u.startswith("keywords:") for u in d.source.unsupported)


def test_a_list_of_maps_is_an_or_of_selections():
    p = _pred(
        "    selection:\n"
        "        - gcp.audit.method_name: A\n"
        "        - gcp.audit.method_name: B\n"
        "    condition: selection\n"
    )
    assert evaluate(p, {"method": "B"}) is True


def test_a_scalar_selection_body_is_a_dont_know():
    b = load_sigma_text(_HEAD + "    selection: just-a-string\n    condition: selection\n", "r.yml")
    d = b.detections[0]
    assert isinstance(d.spec.events[0].pred, Unknown)
    assert "selection:selection" in d.source.unsupported


# --- the condition language -------------------------------------------------------------------

_TWO = (
    "    sel_a:\n        gcp.audit.method_name: A\n"
    "    sel_b:\n        gcp.audit.service_name: S\n"
    "    filter:\n        gcp.audit.request_metadata.caller_ip: 10.0.0.1\n"
)


def test_and_or_not_and_parentheses():
    p = _pred(_TWO + "    condition: (sel_a or sel_b) and not filter\n")
    assert evaluate(p, {"method": "A", "caller_ip": "1.2.3.4"}) is True
    assert evaluate(p, {"method": "A", "caller_ip": "10.0.0.1"}) is False
    assert evaluate(p, {"method": "Z", "service": "other", "caller_ip": "10.0.0.1"}) is False


def test_one_of_them_and_all_of_them():
    one = _pred(_TWO + "    condition: 1 of them\n")
    assert evaluate(one, {"method": "A"}) is True
    every = _pred("    sel_a:\n        gcp.audit.method_name: A\n    sel_b:\n        gcp.audit.service_name: S\n    condition: all of them\n")
    assert evaluate(every, {"method": "A"}) is False
    assert evaluate(every, {"method": "A", "service": "S"}) is True


def test_one_of_a_prefix_selects_only_the_matching_selections():
    p = _pred(_TWO + "    condition: 1 of sel_* and not filter\n")
    assert evaluate(p, {"method": "A", "caller_ip": "1.1.1.1"}) is True


def test_any_of_is_accepted_as_a_synonym_for_one_of():
    p = _pred(_TWO + "    condition: any of sel_*\n")
    assert evaluate(p, {"service": "S"}) is True


def test_n_of_keeps_the_count_as_a_dont_know():
    """"2 of them" is weaker than "any of them"; pretending otherwise would broaden the rule."""
    d = _rule(_TWO + "    condition: 2 of sel_*\n")
    assert unknowns(d.spec.events[0].pred)
    assert any("2 of" in u for u in d.source.unsupported)


def test_an_aggregation_keeps_the_base_query_and_flags_the_count():
    d = _rule(_TWO + "    condition: sel_a | count() > 5\n")
    assert "condition:aggregation" in d.source.unsupported
    labels = {u.label for u in unknowns(d.spec.events[0].pred)}
    assert "sigma:aggregation" in labels


@pytest.mark.parametrize(
    "cond", ["nosuchselection", "sel_a and", "sel_a sel_b", "1 of nomatch_*", "1 sel_a", "(sel_a"]
)
def test_an_unreadable_condition_is_a_dont_know_never_true(cond):
    d = _rule(_TWO + f"    condition: {cond}\n")
    assert isinstance(d.spec.events[0].pred, Unknown)
    assert any(u.startswith("condition:") for u in d.source.unsupported)


def test_a_rule_with_no_condition_defaults_to_the_selection():
    doc = {"title": "t", "logsource": {"product": "gcp"}, "detection": {"selection": {"gcp.audit.method_name": "A"}}}
    d, _ = lower_sigma(doc, "r.yml")
    assert evaluate(d.spec.events[0].pred, {"method": "A"}) is True


def test_sigma_rules_do_not_require_every_field_to_be_present():
    """Sigma has no zero-value guard: a test on a missing field is false, not unknown."""
    d = _rule("    selection:\n        gcp.audit.method_name: A\n    condition: selection\n")
    assert d.spec.options.allow_zero_values
    assert evaluate(d.spec.events[0].pred, {"method": "B"}) is False
