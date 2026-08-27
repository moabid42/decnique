"""M0 acceptance: per-construct fixtures for fires() and matches_footprint()."""

from __future__ import annotations

import pytest

from decnique.dsl.parser import parse_text
from decnique.eval import fires, matches_footprint


def _detection(src: str):
    b = parse_text(src, "t.decn")
    return b.detections[0]


def _candidate(src: str):
    b = parse_text(src, "t.decn")
    return b.candidates[0]


# --- count -------------------------------------------------------------------------------


def test_pure_count_threshold():
    d = _detection(
        """
        detection burst { events { e: method = "storage.objects.get" }
          condition #e > 3 }
        """
    )
    evs = [{"method": "storage.objects.get"} for _ in range(4)]
    assert fires(d.spec, evs) is True
    assert fires(d.spec, evs[:3]) is False


# --- group by ----------------------------------------------------------------------------


def test_group_by_partitions_per_principal():
    d = _detection(
        """
        detection burst { events { e: method = "storage.objects.get" }
          group by e.principal condition #e > 2 }
        """
    )
    # 3 for principal a, 1 for b -> a's group fires
    evs = [{"method": "storage.objects.get", "principal": p} for p in ("a", "a", "a", "b")]
    assert fires(d.spec, evs) is True
    # spread across principals so no single group crosses the threshold
    spread = [{"method": "storage.objects.get", "principal": p} for p in ("a", "b", "c")]
    assert fires(d.spec, spread) is False


# --- window ------------------------------------------------------------------------------


def test_window_in_and_out_of_span():
    d = _detection(
        """
        detection burst { events { e: method = "m" }
          group by e.principal window 600s condition #e > 3 }
        """
    )
    within = [{"method": "m", "principal": "a", "time": t} for t in (0, 100, 200, 300)]
    outside = [{"method": "m", "principal": "a", "time": t} for t in (0, 1000, 2000, 3000)]
    assert fires(d.spec, within) is True
    assert fires(d.spec, outside) is False


def test_window_missing_timestamp_is_unknown():
    d = _detection(
        """
        detection burst { events { e: method = "m" }
          window 600s condition #e > 1 }
        """
    )
    evs = [{"method": "m"}, {"method": "m"}]  # no time -> window undecidable
    assert fires(d.spec, evs) is None


# --- order -------------------------------------------------------------------------------


def test_order_before_after():
    d = _detection(
        """
        detection chain {
          events { a: method = "create" b: method = "use" }
          join { a.principal = b.principal }
          order a < b condition #a >= 1 and #b >= 1 }
        """
    )
    ok = [
        {"method": "create", "principal": "p", "time": 1},
        {"method": "use", "principal": "p", "time": 2},
    ]
    reversed_ = [
        {"method": "create", "principal": "p", "time": 5},
        {"method": "use", "principal": "p", "time": 2},
    ]
    assert fires(d.spec, ok) is True
    assert fires(d.spec, reversed_) is False


def test_join_key_must_match():
    d = _detection(
        """
        detection chain {
          events { a: method = "create" b: method = "use" }
          join { a.principal = b.principal }
          condition #a >= 1 and #b >= 1 }
        """
    )
    diff = [
        {"method": "create", "principal": "p"},
        {"method": "use", "principal": "q"},
    ]
    assert fires(d.spec, diff) is False


# --- count_distinct ----------------------------------------------------------------------


def test_count_distinct_ips():
    d = _detection(
        """
        detection multi_ip { events { e: method = "list" }
          group by e.principal
          aggregates { ips = count_distinct(e.caller_ip) }
          condition ips >= 2 }
        """
    )
    two = [
        {"method": "list", "principal": "a", "caller_ip": "1.1.1.1"},
        {"method": "list", "principal": "a", "caller_ip": "2.2.2.2"},
    ]
    one = [
        {"method": "list", "principal": "a", "caller_ip": "1.1.1.1"},
        {"method": "list", "principal": "a", "caller_ip": "1.1.1.1"},
    ]
    assert fires(d.spec, two) is True
    assert fires(d.spec, one) is False


# --- combined (the plan's headline example) ----------------------------------------------


def test_key_created_then_used_from_outside():
    d = _detection(
        """
        detection key_created_then_used_from_outside {
          events {
            c: method = "google.iam.admin.v1.CreateServiceAccountKey"
            u: method = "iam.serviceAccounts.getAccessToken" and not caller_ip in cidr ["10.0.0.0/8"]
          }
          join { c.principal = u.principal }
          window 3600s after c
          order c < u
          condition #c >= 1 and #u >= 1 }
        """
    )
    outside = [
        {"method": "google.iam.admin.v1.CreateServiceAccountKey", "principal": "sa", "time": 0},
        {"method": "iam.serviceAccounts.getAccessToken", "principal": "sa",
         "caller_ip": "203.0.113.5", "time": 60},
    ]
    inside = [
        {"method": "google.iam.admin.v1.CreateServiceAccountKey", "principal": "sa", "time": 0},
        {"method": "iam.serviceAccounts.getAccessToken", "principal": "sa",
         "caller_ip": "10.1.2.3", "time": 60},
    ]
    assert fires(d.spec, outside) is True
    assert fires(d.spec, inside) is False


# --- honesty -----------------------------------------------------------------------------


def test_unknown_leaf_is_dont_know():
    d = _detection(
        """
        detection approx { event method = "m" and unknown("panther:python_logic") }
        """
    )
    assert fires(d.spec, [{"method": "m"}]) is None  # never a confident yes/no


# --- footprint ---------------------------------------------------------------------------


def test_footprint_repeat_within_order_span():
    c = _candidate(
        """
        candidate esc {
          required { iam.serviceAccounts.setIamPolicy }
          footprint {
            grant: "SetIAMPolicy"
            use:   "getAccessToken" repeat 2 within 300s distinct caller_ip
            order grant < use
            span 1h }
        }
        """
    )
    good = [
        {"method": "SetIAMPolicy", "time": 0},
        {"method": "getAccessToken", "time": 100, "caller_ip": "1.1.1.1"},
        {"method": "getAccessToken", "time": 200, "caller_ip": "2.2.2.2"},
    ]
    assert matches_footprint(c.footprint, good) is True


@pytest.mark.parametrize(
    "bad",
    [
        # repeat unmet: only one getAccessToken
        [
            {"method": "SetIAMPolicy", "time": 0},
            {"method": "getAccessToken", "time": 100, "caller_ip": "1.1.1.1"},
        ],
        # distinct unmet: same caller_ip twice
        [
            {"method": "SetIAMPolicy", "time": 0},
            {"method": "getAccessToken", "time": 100, "caller_ip": "1.1.1.1"},
            {"method": "getAccessToken", "time": 200, "caller_ip": "1.1.1.1"},
        ],
        # order unmet: use before grant
        [
            {"method": "getAccessToken", "time": 0, "caller_ip": "1.1.1.1"},
            {"method": "getAccessToken", "time": 50, "caller_ip": "2.2.2.2"},
            {"method": "SetIAMPolicy", "time": 100},
        ],
    ],
)
def test_footprint_violations(bad):
    c = _candidate(
        """
        candidate esc {
          required { iam.serviceAccounts.setIamPolicy }
          footprint {
            grant: "SetIAMPolicy"
            use:   "getAccessToken" repeat 2 within 300s distinct caller_ip
            order grant < use
            span 1h }
        }
        """
    )
    assert matches_footprint(c.footprint, bad) is False
