"""SecOps front-end: structural scanning must skip ``/regex/`` literals.

A YARA-L regex literal routinely contains ``"`` (``[^"]``), ``:``, and braces (``.{16}``), and a
string literal can contain braces (a ``{GUID}``).  The comment stripper, the section-header
finder, and the rule-brace matcher all used to treat those as real quotes / colons / braces,
which desynced them: a ``//`` comment survived, the ``outcome:`` header was swallowed into
``events:``, and the closing rule ``}`` leaked into ``condition:``.  These are the regression
guards for that fix (all three failed before ``_spans`` / ``_mask_literals``).
"""

from __future__ import annotations

from decnique.frontends.secops import load_yaral_text
from decnique.frontends.secops.parser import split_rules, split_sections

# Regexes carry stray quotes; a trailing `//` comment; a `{GUID}` in a string; `.{16}` in a
# regex; a bare-variable condition — every trap the old char scanners tripped on.
_RULE = r"""
rule regex_quote_traps {
  meta:
    author = "test"
  events:
    $e.metadata.product_name = "Google Cloud IAM"
    $e.target.process.command_line = /^"[A-Za-z]:\\.{16}\\cmd\.exe" \/c [^"][^:]/ nocase
    //Tuning: this comment must not leak into the events section
    $e.target.registry.registry_value_data = "{d6886603-9d2f-4eb2-b667-1971041fa96b}"
  outcome:
    $risk_score = 65
  condition:
    $e
}
"""


def test_sections_split_despite_quotes_and_braces_in_literals() -> None:
    name, body, _ = split_rules(_RULE)[0]
    assert name == "regex_quote_traps"
    secs = split_sections(body)
    # outcome header is found, not swallowed into events
    assert set(secs) == {"meta", "events", "outcome", "condition"}
    # the // comment did not survive into the events section
    assert "Tuning" not in secs["events"]
    # the closing rule brace did not leak into the condition
    assert secs["condition"].strip() == "$e"
    assert "}" not in secs["condition"]


def test_rule_translates_without_masking_artifacts() -> None:
    d = load_yaral_text(_RULE, "traps.yaral").detections[0]
    reasons = list(d.source.unsupported) if d.source else []
    # none of the old desync artifacts (unparsed events, leaked outcome/condition) remain
    assert not any(
        r.startswith(("events:unparsed", "condition:unparsed", "condition:partially_lowered"))
        for r in reasons
    ), reasons
