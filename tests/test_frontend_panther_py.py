"""Panther rule() bodies are evaluated symbolically: control flow, reads, loops, helpers —
and anything else is an explicit don't-know."""

from __future__ import annotations

import pytest

from decnique.dsl.interpret import evaluate
from decnique.frontends.panther_py import rule_predicate
from decnique.model.predicates import unknowns

_D = "target.resource.attribute.labels[ser_binding_deltas_%s]"  # bare path under event["udm"]


def _ev(**kw):
    e = {"method": "SetIamPolicy", "principal": "a@x.com", "granted": True, "permission": ["p"], "udm": {}}
    e.update(kw)
    return e


def _pred(src: str):
    p, missing = rule_predicate(src)
    return p, missing


def test_guards_loops_and_constants():
    src = '''
METHODS = ("dns.changes.create", "dns.managedZones.delete")
def rule(event):
    if event.get("severity") == "ERROR":
        return False
    if event.deep_get("protoPayload", "methodName", default="") not in METHODS:
        return False
    for auth in event.deep_walk("protoPayload", "authorizationInfo"):
        if auth.get("permission") == "dns.changes.create" and auth.get("granted") is True:
            return True
    return False
'''
    p, missing = _pred(src)
    assert not missing and not unknowns(p)
    ok = _ev(method="dns.changes.create", permission=["dns.changes.create"])
    assert evaluate(p, ok) is True
    assert evaluate(p, _ev(method="dns.changes.create", permission=["dns.changes.create"], udm={"severity": "ERROR"})) is False
    assert evaluate(p, _ev(method="other", permission=["dns.changes.create"])) is False
    assert evaluate(p, _ev(method="dns.changes.create", permission=["dns.changes.create"], granted=False)) is False


def test_any_all_endswith_regex_and_helpers():
    src = '''
import re
PATTERN = re.compile(r"v\\d\\.ConfigServiceV\\d\\.UpdateSink")
def _robot(event):
    return event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="").endswith(".gserviceaccount.com")
def rule(event):
    granted = event.deep_walk("protoPayload", "authorizationInfo", "granted", default=[])
    authenticated = any(granted) if isinstance(granted, list) else bool(granted)
    return all([
        authenticated,
        PATTERN.search(event.deep_get("protoPayload", "methodName", default="")) is not None,
        not _robot(event),
        "logging" in event.deep_get("protoPayload", "serviceName", default=""),
    ])
'''
    p, missing = _pred(src)
    assert not missing and not unknowns(p)
    good = _ev(method="google.logging.v2.ConfigServiceV2.UpdateSink", service="logging.googleapis.com")
    assert evaluate(p, good) is True
    assert evaluate(p, {**good, "principal": "sa@p.iam.gserviceaccount.com"}) is False
    assert evaluate(p, {**good, "method": "google.logging.v2.ConfigServiceV2.DeleteSink"}) is False
    assert evaluate(p, {**good, "granted": False}) is False


def test_binding_deltas_and_data_model():
    src = '''
from panther_gcp_helpers import get_binding_deltas
def rule(event):
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD" and delta.get("role") in ("roles/owner", "roles/editor"):
            return True
    return False
'''
    p, missing = _pred(src)
    assert not missing
    assert evaluate(p, _ev(udm={_D % "action": "ADD", _D % "role": "roles/editor"})) is True
    assert evaluate(p, _ev(udm={_D % "action": "REMOVE", _D % "role": "roles/editor"})) is False
    dm, missing = _pred('def rule(event):\n    return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED\n')
    assert not missing
    assert evaluate(dm, _ev(udm={_D % "action": "ADD", _D % "role": "roles/owner"})) is True
    assert evaluate(dm, _ev(udm={_D % "action": "ADD", _D % "role": "roles/viewer"})) is False
    other, _ = _pred('def rule(event):\n    return event.udm("event_type") == event_type.FAILED_LOGIN\n')
    assert evaluate(other, _ev()) is False  # the GCP data model never yields it


def test_unsupported_construct_is_an_explicit_dont_know():
    src = '''
def rule(event):
    if event.deep_get("protoPayload", "methodName") != "storage.objects.get":
        return False
    parts = event.deep_get("protoPayload", "resourceName", default="").split("/")
    return parts[-1] == "secret"
'''
    p, missing = _pred(src)
    assert missing == ["str.split"]
    u = unknowns(p)
    assert u and u[0].label == "panther:python:str.split" and u[0].fields == ((None, "resource"),)
    assert evaluate(p, _ev(method="storage.objects.get", resource="b/o/secret")) is None  # don't know
    assert evaluate(p, _ev(method="SetIamPolicy")) is False  # the understood guard still decides


# --- one test per idiom the corpus uses; each names what a mistranslation would cost ----------


def _p(body: str, head: str = ""):
    """``rule()`` with ``body`` as its indented body."""
    return rule_predicate(head + "def rule(event):\n" + body)


def _labels(p):
    return {u.label for u in unknowns(p)}


def test_a_read_of_a_field_with_no_event_model_name_keeps_its_raw_path():
    p, missing = _p('    return event.deep_get("protoPayload", "request", "policy") == "x"\n')
    assert not missing
    assert evaluate(p, _ev(udm={"protoPayload.request.policy": "x"})) is True


def test_the_binding_deltas_and_authorization_info_are_recognised_lists():
    p, _ = _p('    return bool(event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas"))\n')
    assert evaluate(p, _ev(udm={_D % "action": "ADD"})) is True
    q, _ = _p('    return bool(event.deep_get("protoPayload", "authorizationInfo"))\n')
    assert evaluate(q, _ev()) is True


def test_a_single_delta_key_maps_onto_its_label():
    p, missing = _p('    return event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas", "role") == "roles/owner"\n')
    assert not missing
    assert evaluate(p, _ev(udm={_D % "role": "roles/owner"})) is True


def test_a_field_read_as_a_condition_is_python_truthiness_by_sort():
    """`if not event.deep_get(...)` is a presence test, not an equality with anything."""
    string_field, _ = _p('    return bool(event.deep_get("protoPayload", "authenticationInfo", "principalEmail"))\n')
    assert evaluate(string_field, _ev(principal="a@x.com")) is True
    assert evaluate(string_field, _ev(principal="")) is False
    bool_field, _ = _p('    return bool(event.deep_get("protoPayload", "authorizationInfo", "granted"))\n')
    assert evaluate(bool_field, _ev(granted=False)) is False
    assert evaluate(bool_field, _ev(granted=True)) is True


@pytest.mark.parametrize(("op", "value", "fires"), [("<", 10, 5), (">", 10, 20), ("<=", 5, 5), (">=", 5, 5)])
def test_numeric_comparisons_both_ways_round(op, value, fires):
    p, missing = _p(f'    return int(event.deep_get("sent_bytes")) {op} {value}\n')
    assert not missing
    assert evaluate(p, _ev(udm={"sent_bytes": fires})) is True
    flipped, _ = _p(f'    return {value} {op} int(event.deep_get("sent_bytes"))\n')
    assert isinstance(flipped, type(p))


def test_a_field_compared_to_none_is_a_presence_test():
    p, missing = _p('    return event.deep_get("protoPayload", "requestMetadata", "callerIp") is None\n')
    assert not missing
    assert evaluate(p, _ev(caller_ip="1.2.3.4")) is False


def test_lower_makes_the_match_case_insensitive():
    p, missing = _p('    return event.deep_get("protoPayload", "methodName", default="").lower() == "setiampolicy"\n')
    assert not missing
    assert evaluate(p, _ev(method="SetIamPolicy")) is True


def test_startswith_accepts_a_tuple_of_prefixes():
    p, missing = _p('    return event.deep_get("protoPayload", "methodName", default="").startswith(("storage.", "compute."))\n')
    assert not missing
    assert evaluate(p, _ev(method="compute.instances.delete")) is True
    assert evaluate(p, _ev(method="iam.roles.create")) is False


def test_fnmatch_becomes_a_glob():
    p, missing = _p('    return fnmatch(event.deep_get("protoPayload", "methodName", default=""), "*.SetIamPolicy")\n',
                    head="from fnmatch import fnmatch\n")
    assert not missing
    assert evaluate(p, _ev(method="v1.SetIamPolicy")) is True


def test_re_match_and_fullmatch_are_anchored():
    search, _ = _p('    return re.search(r"SetIam", event.deep_get("protoPayload", "methodName", default="")) is not None\n',
                   head="import re\n")
    assert evaluate(search, _ev(method="v1.SetIamPolicy")) is True
    match, _ = _p('    return re.match(r"SetIam", event.deep_get("protoPayload", "methodName", default="")) is not None\n',
                  head="import re\n")
    assert evaluate(match, _ev(method="v1.SetIamPolicy")) is False
    full, _ = _p('    return re.fullmatch(r"SetIam", event.deep_get("protoPayload", "methodName", default="")) is not None\n',
                 head="import re\n")
    assert evaluate(full, _ev(method="SetIam")) is True


def test_a_substring_test_on_a_field_becomes_contains():
    p, missing = _p('    return "iam" in event.deep_get("protoPayload", "serviceName", default="")\n')
    assert not missing
    assert evaluate(p, _ev(service="iam.googleapis.com")) is True


def test_a_generator_over_a_literal_list_expands():
    p, missing = _p(
        '    return any(event.deep_get("protoPayload", "methodName", default="").endswith(s) for s in SUFFIXES)\n',
        head='SUFFIXES = (".delete", ".setIamPolicy")\n',
    )
    assert not missing
    assert evaluate(p, _ev(method="v1.compute.instances.delete")) is True


def test_a_generator_over_the_binding_deltas_keeps_one_representative_delta():
    p, missing = _p(
        '    return any(d.get("role") == "roles/owner" for d in event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas"))\n'
    )
    assert not missing
    assert evaluate(p, _ev(udm={_D % "role": "roles/owner"})) is True


def test_a_subscript_on_a_loop_variable_reads_the_same_field_as_get():
    p, missing = _p(
        '    for d in event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas"):\n'
        '        if d["action"] == "ADD":\n'
        '            return True\n'
        "    return False\n"
    )
    assert not missing
    assert evaluate(p, _ev(udm={_D % "action": "ADD"})) is True


def test_a_helper_with_the_wrong_number_of_arguments_is_a_dont_know():
    p, missing = _p("    return helper(event, 1)\n", head="def helper(e):\n    return True\n")
    assert missing == ["helper:helper:arity"] and unknowns(p)


def test_an_early_return_true_short_circuits_the_rest_of_the_body():
    p, missing = _p(
        '    if event.deep_get("protoPayload", "methodName") == "SetIamPolicy":\n'
        "        return True\n"
        "    return False\n"
    )
    assert not missing
    assert evaluate(p, _ev(method="SetIamPolicy")) is True
    assert evaluate(p, _ev(method="other")) is False


def test_pass_continue_and_bare_expressions_do_not_change_the_meaning():
    p, missing = _p(
        '    for d in event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas"):\n'
        '        "a docstring-like expression"\n'
        '        if d.get("action") != "ADD":\n'
        "            continue\n"
        "        return True\n"
        "    pass\n"
        "    return False\n"
    )
    assert not missing
    assert evaluate(p, _ev(udm={_D % "action": "ADD"})) is True


@pytest.mark.parametrize(
    ("body", "what"),
    [
        ("    while True:\n        return True\n", "while"),
        ('    return event.deep_get("protoPayload", "methodName") < "a"\n', "compare_op"),
        ("    return event.foo()\n", "event.foo"),
        ('    return event.udm("other_thing") == 1\n', "event.udm:other_thing"),
        ("    return undefined_name\n", "name:undefined_name"),
        ("    return {1: 2}\n", "dict"),
        ("    for x in [1, 2]:\n        return True\n", "for_over_tuple"),
        ("    return 1 < 2 < 3\n", "chained_compare"),
        ('    return event.deep_get(*keys) == "x"\n', "starred"),
    ],
)
def test_a_construct_outside_the_subset_is_named_and_left_unknown(body, what):
    """The rule must stay a don't-know rather than silently mean something else."""
    p, missing = _p(body)
    assert any(what in m for m in missing) or any(what in label for label in _labels(p)), (missing, _labels(p))
    assert evaluate(p, _ev()) is None or unknowns(p)


def test_a_python_file_with_no_rule_function_is_a_dont_know():
    p, missing = rule_predicate("def helper(event):\n    return True\n")
    assert missing == ["no rule() function"] and unknowns(p)


def test_a_syntax_error_is_reported_not_raised():
    p, missing = rule_predicate("def rule(event:\n    return True\n")
    assert missing == ["syntax"] and unknowns(p)


def test_a_comparison_between_two_literals_is_decided_statically():
    p, _ = _p('    return "a" == "a"\n')
    assert evaluate(p, _ev()) is True


def test_a_predicate_compared_to_a_boolean_keeps_its_meaning():
    p, missing = _p('    return (event.deep_get("protoPayload", "methodName") == "SetIamPolicy") == False\n')
    assert not missing
    assert evaluate(p, _ev(method="SetIamPolicy")) is False


def test_a_conditional_expression_decided_by_isinstance_picks_one_branch():
    p, missing = _p(
        '    granted = event.deep_walk("protoPayload", "authorizationInfo", "granted", default=[])\n'
        "    return any(granted) if isinstance(granted, list) else False\n"
    )
    assert not missing
    assert evaluate(p, _ev(granted=True)) is True


def test_the_module_level_deep_get_helper_reads_the_same_fields():
    """`from panther_base_helpers import deep_get` is as common as the method on the event."""
    p, missing = _p(
        '    return deep_get(event, "protoPayload", "methodName") == "SetIamPolicy"\n',
        head="from panther_base_helpers import deep_get\n",
    )
    assert not missing
    assert evaluate(p, _ev(method="SetIamPolicy")) is True


def test_the_data_model_event_type_can_be_tested_with_in():
    p, missing = _p(
        '    return event.udm("event_type") in (event_type.ADMIN_ROLE_ASSIGNED, event_type.FAILED_LOGIN)\n'
    )
    assert not missing
    assert evaluate(p, _ev(udm={_D % "action": "ADD", _D % "role": "roles/owner"})) is True


def test_constant_branches_are_folded_away():
    always, _ = _p("    return True or event.deep_get('protoPayload', 'methodName') == 'X'\n")
    assert evaluate(always, _ev()) is True
    never, _ = _p("    return False and event.deep_get('protoPayload', 'methodName') == 'X'\n")
    assert evaluate(never, _ev()) is False
    negated, _ = _p("    return not 1 == 2\n")
    assert evaluate(negated, _ev()) is True


def test_a_loop_variable_used_as_a_condition_is_a_dont_know():
    p, missing = _p(
        '    for d in event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas"):\n'
        "        if d:\n"
        "            return True\n"
        "    return False\n"
    )
    assert missing and unknowns(p)


def test_a_filtered_comprehension_is_a_dont_know_not_an_unfiltered_one():
    """Dropping the `if` would make the rule fire on elements it actually skips."""
    p, missing = _p(
        '    return any(d.get("role") == "roles/owner" for d in event.deep_get("protoPayload", "serviceData", "policyDelta", "bindingDeltas") if d)\n'
    )
    assert missing == ["comprehension"] and unknowns(p)


def test_a_call_that_is_not_a_plain_name_or_attribute_is_a_dont_know():
    p, missing = _p("    return (lambda e: True)(event)\n")
    assert missing == ["call"] and unknowns(p)
