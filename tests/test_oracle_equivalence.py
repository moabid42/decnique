"""M0 acceptance: fires() generalizes the single-event interpreter.

For every single-event detection, ``fires(spec, [e])`` must equal ``observes(R, e)`` on
any event (Hypothesis-generated).  This is the contract that proves the multi-event
evaluator is a faithful extension of :mod:`decnique.dsl.interpret`, not a reimplementation
that drifts.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from decnique.dsl.interpret import observes
from decnique.dsl.parser import parse_text
from decnique.eval import fires

# A small corpus of single-event detections exercising the predicate constructs.
_CORPUS_SRC = """
detection eq        { event method = "storage.objects.get" }
detection ne        { event principal != "root@example.com" }
detection like_     { event resource like "*/buckets/*" }
detection startsw   { event method startswith "google.iam" }
detection contains_ { event user_agent contains "curl" }
detection regex_    { event method matches /Create.*Key/ }
detection in_list   { event method in ["a.b.c", "d.e.f"] }
detection cidr_     { event caller_ip in cidr ["10.0.0.0/8", "192.168.0.0/16"] }
detection exists_   { event caller_ip exists }
detection missing_  { event user_agent missing }
detection bool_     { event granted = false }
detection conj      { event method = "m" and granted = true }
detection disj      { event method = "a" or method = "b" }
detection negation  { event not principal = "sa@x.gserviceaccount.com" }
detection allow0    { event granted = true options { allow_zero_values = true } }
"""

_CORPUS = parse_text(_CORPUS_SRC, "corpus.decn")


def test_corpus_all_single_event():
    for d in _CORPUS.detections:
        assert d.spec.is_single_event, d.id


_METHODS = st.sampled_from(
    ["storage.objects.get", "google.iam.admin.v1.CreateServiceAccountKey", "a.b.c", "m", "a", "b"]
)
_PRINCIPALS = st.sampled_from(["root@example.com", "sa@x.gserviceaccount.com", "u@example.com"])
_IPS = st.sampled_from(["10.1.2.3", "192.168.1.9", "203.0.113.5"])
_UA = st.sampled_from(["curl/8.0", "Mozilla", "python-requests"])
_RES = st.sampled_from(["p/buckets/b", "p/instances/i"])

_EVENT = st.fixed_dictionaries(
    {},
    optional={
        "method": _METHODS,
        "service": st.sampled_from(["storage.googleapis.com", "iam.googleapis.com"]),
        "principal": _PRINCIPALS,
        "resource": _RES,
        "caller_ip": _IPS,
        "user_agent": _UA,
        "granted": st.booleans(),
    },
)


@given(event=_EVENT)
def test_fires_equals_observes_on_single_event(event):
    for d in _CORPUS.detections:
        assert fires(d.spec, [event]) == observes(d, event), (d.id, event)
