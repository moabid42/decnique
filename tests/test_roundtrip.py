"""Guard: M0 must not regress the language — parse(format(x)) == x holds.

Invariant §1.4 of the plan.  The formatter's canonical text must re-parse to the same
bundle for the multi-event and footprint constructs the evaluator now consumes.
"""

from __future__ import annotations

import pytest

from decnique.dsl import format as fmt
from decnique.dsl.parser import parse_text

_SOURCES = [
    """
    detection burst { events { e: method = "storage.objects.get" }
      group by e.principal window 600s condition #e > 3 }
    """,
    """
    detection chain {
      events { a: method = "create" b: method = "use" }
      join { a.principal = b.principal }
      window 3600s after a order a < b
      condition #a >= 1 and #b >= 1 }
    """,
    """
    detection agg { events { e: method = "list" }
      group by e.principal
      aggregates { ips = count_distinct(e.caller_ip) }
      condition ips >= 2 }
    """,
    """
    candidate esc {
      required { iam.serviceAccounts.setIamPolicy }
      footprint {
        grant: "SetIAMPolicy"
        use:   "getAccessToken" repeat 2 within 300s distinct caller_ip
        order grant < use
        span 1h }
    }
    """,
]


@pytest.mark.parametrize("src", _SOURCES)
def test_format_roundtrip(src):
    once = parse_text(src, "t.decn")
    twice = parse_text(fmt.bundle(once), "t.decn")
    assert fmt.bundle(once) == fmt.bundle(twice)
