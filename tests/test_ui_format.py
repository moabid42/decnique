"""The one-cell summaries in every listing (`ui/format.py`).

They are deliberately lossy, so the test is not "does it say everything" but "does it stay
honest": a window that is one-sided must not read as symmetric, a condition the front-end
could not translate must not read as ``always``, and a witness must not present z3's
model-completion placeholders as if they were values the attacker chose.
"""

from __future__ import annotations

from decnique.dsl import ast as A
from decnique.model.predicates import Cmp
from decnique.model.trace import (
    AggCmp,
    CAnd,
    CNot,
    COr,
    Count,
    CTrue,
    CUnknown,
    EventVar,
    TraceSpec,
    Window,
)
from decnique.ui.format import cond_str, event_brief, footprint_str, window_str

E = EventVar("e", Cmp(field=(None, "method"), op="=", value="m"))


def _spec(window):
    return TraceSpec(events=(E,), window=window)


def test_no_window_reads_as_a_dash_not_as_zero():
    assert window_str(_spec(None)) == "—"


def test_a_symmetric_window_is_just_its_length():
    assert window_str(_spec(Window(600))) == "600s"


def test_a_one_sided_window_says_which_side():
    assert window_str(_spec(Window(600, anchor="a", side="after"))) == "600s/after"
    assert window_str(_spec(Window(600, anchor="a", side="before"))) == "600s/before"


def test_conditions_read_the_way_they_are_written():
    assert cond_str(CTrue()) == "always"
    assert cond_str(Count("e", ">=", 3)) == "#e>=3"
    assert cond_str(AggCmp("ips", ">", 2)) == "ips>2"
    assert cond_str(CAnd((Count("a", ">=", 1), Count("b", ">=", 1)))) == "#a>=1 & #b>=1"
    assert cond_str(COr((Count("a", ">=", 1), Count("b", ">=", 1)))) == "#a>=1 | #b>=1"
    assert cond_str(CNot(Count("a", ">=", 1))) == "!(#a>=1)"


def test_an_untranslated_condition_is_a_question_mark_not_always():
    """``always`` would claim the rule fires on any group — the opposite of don't-know."""
    assert cond_str(CUnknown("panther:python-body")) == "?"


def test_a_footprint_lists_its_steps_with_the_constraints_that_matter():
    fp = A.Footprint(
        steps=(
            A.Step("grant", "SetIamPolicy"),
            A.Step("use", "GetToken", repeat=3, within_seconds=300, distinct=((None, "caller_ip"),)),
        )
    )
    assert footprint_str(fp) == "grant, use×3 (within 300s; distinct caller_ip)"


def test_a_single_step_footprint_has_no_decoration():
    assert footprint_str(A.Footprint(steps=(A.Step("act", "M"),))) == "act"


def test_event_brief_puts_the_telling_fields_first():
    ev = {"resource": "projects/p", "extra": "x", "method": "SetIamPolicy", "principal": "u@x"}
    assert event_brief(ev) == "method=SetIamPolicy  principal=u@x  resource=projects/p  extra=x"


def test_event_brief_hides_solver_placeholders_and_filler():
    """``!0!`` is z3 completing a field the model left free — showing it would suggest the
    attacker had to pick that value."""
    ev = {"method": "SetIamPolicy", "principal": "!0!", "caller_ip": "0.0.0.0", "port": 0, "ua": ""}
    assert event_brief(ev) == "method=SetIamPolicy"


def test_an_event_with_nothing_to_show_says_so():
    assert event_brief({}) == "(empty event)"
    assert event_brief({"method": "!1!"}) == "(empty event)"
