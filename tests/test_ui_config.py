"""Settings registry + the explanations behind blindspots (rules / formula)."""

from __future__ import annotations

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.smt.coverage import CoverageContext, NoGap, blind_region, find_gap, probe_atoms
from decnique.ui.config import REGISTRY, Settings

_D = 'udm("target.resource.attribute.labels[ser_binding_deltas_%s]")'
_LIB = f"""
detection owner_added {{
  event method = "SetIamPolicy" and {_D % "action"} = "ADD" and {_D % "role"} = "roles/owner"
}}
"""


def _account() -> Account:
    return Account(
        name="t",
        bindings={"a@x.com": (Grant(permission="resourcemanager.projects.setIamPolicy"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
    )


def test_settings_roundtrip(tmp_path):
    st = Settings(tmp_path / "c.json")
    assert st.get("blindspots.explain") == "rules"  # the default
    st.set("blindspots.explain", "formula")
    assert Settings(tmp_path / "c.json").get("blindspots.explain") == "formula"
    st.reset("blindspots.explain")
    assert st.get("blindspots.explain") == "rules"
    import pytest

    with pytest.raises(ValueError):
        st.set("blindspots.explain", "nonsense")
    with pytest.raises(KeyError):
        st.set("no.such.key", "x")
    assert all(k in REGISTRY for k, *_ in st.rows())


def test_covered_change_names_the_rule_in_the_core():
    lib = DetectionLibrary(parse_text(_LIB, "t.decn"))
    ctx = CoverageContext(lib)
    verdicts = probe_atoms("resourcemanager.projects.setIamPolicy", lib, _account(), ctx=ctx)
    pair = [v for v in verdicts if len(v.atoms) == 2 and {a.text for a in v.atoms} == {"ADD", "roles/owner"}]
    assert pair and pair[0].covered
    assert pair[0].result.covered_by == ("owner_added",)


def test_blind_region_is_a_proven_dnf_over_the_rule_tests():
    lib = DetectionLibrary(parse_text(_LIB, "t.decn"))
    cubes = blind_region("resourcemanager.projects.setIamPolicy", lib, _account())
    assert cubes and all(c.proven for c in cubes)
    text = " || ".join(c.describe() for c in cubes)
    # the hole is exactly: not ADD, or not owner
    assert '¬(labels[ser_binding_deltas_action] = "ADD")' in text.replace("udm:target.resource.attribute.", "")
    assert '¬(labels[ser_binding_deltas_role] = "roles/owner")' in text.replace("udm:target.resource.attribute.", "")
    assert all(len(c.literals) == 1 for c in cubes)  # prime: one literal each


def test_no_gap_when_rule_is_unconditional():
    lib = DetectionLibrary(parse_text('detection all { event method = "SetIamPolicy" }', "t.decn"))
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, _account())
    assert isinstance(r, NoGap) and r.covered_by == ("all",)
    assert blind_region("resourcemanager.projects.setIamPolicy", lib, _account()) == ()
