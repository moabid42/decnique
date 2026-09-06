"""``yaml_io`` is the AST's serialisation format — it must lose nothing.

Every tool that stores a bundle outside the process (``decnique.cli import --yaml/--json``,
golden files) goes through here, so the property that matters is the same one the formatter
has to keep: **decode(encode(x)) == x**, for every node of the language and not only for the
parts a hand-written example happens to use.

The bundle below is built by hand on purpose: the parser cannot produce ``Unknown``,
``InList``, ``AggIf`` or ``CUnknown`` — those come from the front-ends — and they are exactly
the nodes whose loss would silently turn an approximate rule into an exact-looking one.
"""

from __future__ import annotations

import json

import pytest
import yaml

from decnique.dsl import ast as A
from decnique.dsl import yaml_io
from decnique.dsl.parser import parse_file, parse_text
from decnique.model import predicates as P
from decnique.model import trace as T

EXAMPLES = [
    "examples/candidates/candidates.decn",
    "examples/candidates/candidates_medium.decn",
    "examples/candidates/candidates_advanced.decn",
    "examples/checks/checks.decn",
]


def _every_predicate() -> P.Pred:
    """One predicate holding every leaf kind and both connectives."""
    return P.All(
        children=(
            P.Cmp(field=(None, "method"), op="=", value="SetIamPolicy"),
            P.Cmp(field=("a", "count"), op=">=", value=3),
            P.Like(field=(None, "resource"), pattern="projects/*", nocase=True),
            P.Regex(field=(None, "principal"), pattern="^svc-.*@.*$", quant="all"),
            P.StrFn(field=(None, "principal"), fn="endswith", value=".gserviceaccount.com"),
            P.In(field=(None, "method"), values=("a", "b", 7, True)),
            P.InCidr(field=(None, "caller_ip"), cidrs=("10.0.0.0/8", "::1/128")),
            P.InList(field=(None, "principal"), list_name="allowlist", kind="regex"),
            P.Exists(field=(None, "resource")),
            P.Not(child=P.Const(value=False)),
            P.Any(
                children=(
                    P.Unknown(
                        label="secops:re.capture",
                        raw="re.capture($e.x, /y/)",
                        fields=((None, "principal"), ("b", "resource")),
                    ),
                    P.Const(value=True),
                )
            ),
        )
    )


def _every_node_bundle() -> A.Bundle:
    spec = T.TraceSpec(
        events=(
            T.EventVar("a", _every_predicate()),
            T.EventVar("b", P.Cmp(field=(None, "method"), op="!=", value="Get")),
        ),
        joins=(T.Join(("a", "principal"), ("b", "principal")),),
        group_by=((None, "resource"), ("a", "principal")),
        window=T.Window(600, anchor="a", side="after"),
        order=("a", "b"),
        aggregates=(
            ("ips", T.AggCall("count_distinct", ("a", "caller_ip"))),
            ("n", T.AggCall("count", None)),
            (
                "score",
                T.AggBin(
                    "+",
                    T.AggIf(
                        P.Cmp(field=("a", "method"), op="=", value="x"),
                        T.AggConst(2),
                        T.AggRef("ips"),
                    ),
                    T.AggConst(1),
                ),
            ),
        ),
        condition=T.CAnd(
            (
                T.Count("a", ">=", 2),
                T.COr((T.AggCmp("ips", ">", 1), T.CNot(T.CTrue()))),
                T.CUnknown("panther:python-body"),
            )
        ),
        options=T.RuleOptions(allow_zero_values=True, extra=(("severity", "HIGH"), ("z", 3))),
    )
    detection = A.Detection(
        id="everything",
        spec=spec,
        meta={"title": "all nodes", "severity": 4, "enabled": True},
        source=A.Provenance(
            file="r.yaral",
            frontend="secops",
            line=12,
            native_id="rule_x",
            unsupported=("re.capture",),
            notes=("translated by hand",),
        ),
    )
    candidate = A.Candidate(
        id="tech",
        required=(
            A.Required("resourcemanager.projects.setIamPolicy"),
            A.Required("iam.serviceAccounts.getAccessToken", P.Exists(field=(None, "resource"))),
        ),
        footprint=A.Footprint(
            steps=(
                A.Step("grant", "SetIamPolicy"),
                A.Step(
                    "use",
                    "GenerateAccessToken",
                    repeat=3,
                    within_seconds=300,
                    distinct=((None, "caller_ip"),),
                    where=P.Cmp(field=(None, "resource"), op="=", value="projects/p"),
                ),
            ),
            order=("grant", "use"),
            span_seconds=3600,
        ),
        meta={"note": "hand built"},
        actor=P.Cmp(field=(None, "principal"), op="=", value="attacker@x.com"),
        context=P.Const(value=True),
        share=("principal", "resource"),
        gains=("resourcemanager.projects.setIamPolicy",),
    )
    check = A.Check(
        id="q",
        type="coverage",
        params={
            "permission": "resourcemanager.projects.setIamPolicy",
            "rules": ("r1", "r2"),
            "event": P.Cmp(field=(None, "method"), op="=", value="SetIamPolicy"),
            "mode": "observed",
        },
    )
    ruleset = A.Ruleset("rs", includes=("a", "b"), disabled=frozenset({"x"}), enabled=frozenset({"y"}))
    issue = A.LoadIssue(severity="warning", file="r.yaral", message="unsupported", rule_id="rule_x")
    return A.Bundle((detection,), (candidate,), (check,), (ruleset,), (issue,))


def test_every_node_survives_a_dict_round_trip():
    b = _every_node_bundle()
    assert yaml_io.bundle_from_dict(yaml_io.bundle_to_dict(b)) == b


def test_every_node_survives_yaml_and_json():
    b = _every_node_bundle()
    assert yaml_io.load_yaml(yaml_io.dump_yaml(b)) == b
    assert yaml_io.load_json(yaml_io.dump_json(b)) == b


def test_dumps_are_plain_data_a_human_can_read():
    """The point of the format is that another tool can read it without importing us."""
    b = _every_node_bundle()
    doc = yaml.safe_load(yaml_io.dump_yaml(b))
    assert doc == json.loads(yaml_io.dump_json(b))
    assert doc["detections"][0]["spec"]["events"][0]["pred"]["node"] == "All"
    assert doc["detections"][0]["source"]["unsupported"] == ["re.capture"]


def test_a_reference_list_keeps_both_its_node_tag_and_its_own_kind():
    """``InList`` has a field called ``kind`` (string / regex / cidr).  While the node tag was
    also called ``kind`` the field overwrote it and no ``field in %list`` predicate could be
    read back — the round trip above is what caught it."""
    p = P.InList(field=(None, "principal"), list_name="allowlist", kind="regex")
    d = yaml_io.pred_to_dict(p)
    assert d["node"] == "InList" and d["kind"] == "regex"
    assert yaml_io.pred_from_dict(d) == p


def test_documents_written_before_the_node_tag_still_load():
    """The tag used to be ``kind``; files on disk from then must keep working."""
    old = {"kind": "Cmp", "field": [None, "method"], "op": "=", "value": "X"}
    assert yaml_io.pred_from_dict(old) == P.Cmp(field=(None, "method"), op="=", value="X")
    assert yaml_io.cond_from_dict({"kind": "Count", "var": "e", "op": ">=", "n": 1}) == T.Count(
        "e", ">=", 1
    )
    assert yaml_io.agg_from_dict({"kind": "AggConst", "value": 2}) == T.AggConst(2)


def test_the_unknown_atom_keeps_its_label_and_fields():
    """Invariant #1: losing an ``Unknown`` on the way through YAML would make an approximate
    rule read as exact.  ``approximate`` must survive the round trip too."""
    b = yaml_io.load_yaml(yaml_io.dump_yaml(_every_node_bundle()))
    d = b.detection("everything")
    assert d.approximate is True
    assert d.unknown_labels == ("secops:re.capture",)
    (u,) = [p for p in P.unknowns(d.spec.event("a").pred)]
    assert u.raw == "re.capture($e.x, /y/)"
    assert u.fields == ((None, "principal"), ("b", "resource"))


@pytest.mark.parametrize("path", EXAMPLES)
def test_the_bundled_examples_round_trip(path):
    b = parse_file(path)
    assert yaml_io.load_yaml(yaml_io.dump_yaml(b)) == b


def test_save_and_load_pick_the_format_from_the_suffix(tmp_path):
    b = parse_text('detection d { event method = "X" }\n', "t.decn")
    for name in ("b.yaml", "b.yml", "b.json"):
        path = tmp_path / name
        yaml_io.save(b, path)
        assert yaml_io.load(path) == b
    assert (tmp_path / "b.json").read_text().lstrip().startswith("{")
    assert not (tmp_path / "b.yaml").read_text().lstrip().startswith("{")


def test_an_empty_yaml_document_loads_as_an_empty_bundle():
    assert yaml_io.load_yaml("") == A.Bundle()


def test_an_unknown_predicate_kind_is_rejected_rather_than_guessed():
    with pytest.raises(KeyError):
        yaml_io.pred_from_dict({"node": "NotAPredicate"})
