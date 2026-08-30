"""`like` is the SIEM wildcard language (`*`, `?`, backslash escapes, no character classes);
DSL strings keep unknown escapes; Elastic derived fields are don't-know."""

from __future__ import annotations

from decnique.dsl.ast import Bundle
from decnique.dsl.format import bundle as fmt_bundle
from decnique.dsl.interpret import glob_has_wildcard, glob_match, glob_unescape, observes
from decnique.dsl.parser import parse_text
from decnique.frontends.elastic import load_elastic_text
from decnique.frontends.sigma import load_sigma_text
from decnique.model.predicates import Cmp, Like, Regex


def test_glob_matcher_semantics():
    assert glob_match("projects/[x]/foo", "projects/[x]/*")       # `[` is literal
    assert not glob_match("projects/x/foo", "projects/[x]/*")
    assert glob_match("a*b", r"a\*b") and not glob_match("aXb", r"a\*b")
    assert glob_match("aXb", "a?b") and not glob_match("ab", "a?b")
    assert glob_match("ABC", "a*", nocase=True) and not glob_match("ABC", "a*")
    assert glob_match("multi\nline", "multi*")
    assert glob_has_wildcard("a*") and not glob_has_wildcard(r"a\*") and glob_has_wildcard(r"a\\*")
    assert glob_unescape(r"a\*b\\c") == r"a*b\c"


def test_dsl_string_keeps_regex_escapes_and_round_trips():
    d = parse_text(r'detection d { event principal matches "\d+@x\.com" and resource like "p/[1]/*" }', "t").detections[0]
    pred = d.spec.events[0].pred
    leaves = {type(x): x for x in pred.children}
    assert leaves[Regex].pattern == r"\d+@x\.com" and leaves[Like].pattern == "p/[1]/*"
    assert observes(d, {"principal": "123@x.com", "resource": "p/[1]/z"}) is True
    text = fmt_bundle(Bundle(detections=(d,)))
    assert parse_text(text, "t").detections[0] == d


def test_sigma_and_kql_escaped_wildcards():
    sig = """
title: t
logsource: {product: gcp, service: gcp.audit}
detection:
  sel:
    gcp.audit.method_name: 'Set\\*'
    gcp.audit.authentication_info.principal_email|contains: 'a[1]'
  condition: sel
"""
    d = load_sigma_text(sig, "t.yml", gcp_only=False).detections[0]
    leaves = list(d.spec.events[0].pred.children)
    assert any(isinstance(x, Cmp) and x.value == "Set*" for x in leaves)
    assert observes(d, {"method": "Set*", "principal": "xa[1]y"}) is True
    assert observes(d, {"method": "SetIamPolicy", "principal": "xa[1]y"}) is False
    kql = '''
[rule]
name = "n"
type = "query"
language = "kuery"
query = 'event.dataset:gcp.audit and event.action:Set\\* and event.type:start'
risk_score = 1
severity = "low"
rule_id = "x"
description = "d"
'''
    d = load_elastic_text(kql, "t.toml").detections[0]
    assert "derived:event.type" in d.source.unsupported
    assert observes(d, {"method": "Set*"}) is None  # event.type is don't-know, never a free dodge
    assert observes(d, {"method": "SetIamPolicy"}) is False
