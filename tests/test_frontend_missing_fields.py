"""Sigma / Elastic rules that test for an *absent* field must be able to fire (honesty #1: a
front-end must not make a real branch of a rule dead)."""

from decnique.dsl.interpret import observes
from decnique.frontends.elastic import load_elastic_text
from decnique.frontends.sigma import load_sigma_text

_SIGMA = """
title: anonymous policy change
logsource: {product: gcp, service: gcp.audit}
detection:
  sel: {gcp.audit.method_name: 'SetIamPolicy'}
  anon: {gcp.audit.authentication_info.principal_email: null}
  condition: sel and anon
"""

_ELASTIC = """
[rule]
name = "anonymous"
type = "query"
language = "kuery"
query = 'event.dataset:gcp.audit and event.action:"SetIamPolicy" and not client.user.email:*'
risk_score = 1
severity = "low"
rule_id = "x"
description = "d"
"""


def test_sigma_null_branch_fires_on_missing_field():
    d = load_sigma_text(_SIGMA, "t.yml", gcp_only=False).detections[0]
    assert d.spec.options.allow_zero_values
    assert observes(d, {"method": "SetIamPolicy"}) is True
    assert observes(d, {"method": "SetIamPolicy", "principal": "a@x.com"}) is False


def test_elastic_not_exists_fires_on_missing_field():
    d = load_elastic_text(_ELASTIC, "t.toml").detections[0]
    assert observes(d, {"method": "SetIamPolicy"}) is True
    assert observes(d, {"method": "SetIamPolicy", "principal": "a@x.com"}) is False
