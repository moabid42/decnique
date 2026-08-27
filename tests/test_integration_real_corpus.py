"""End-to-end soundness against the real IAMouflage corpus (skipped if the data is absent).

Loads the vendored gsecops detections + the example candidates/account and asserts that every
answer the engine reports replays clean through the concrete M0 oracle:

* each blind-spot event is unobserved by *all* 27 real rules (M2 soundness);
* each stealth schedule and each chain hop is unobserved by all rules (M3/M4 soundness).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from decnique.detections import DetectionLibrary
from decnique.env import load_account
from decnique.eval import fires
from decnique.report import chains_report
from decnique.smt.coverage import probe_permissions
from decnique.smt.stealth import Evasive, stealth_feasible

_DATA = Path("/Users/nil/BachelorArbeit/Bachelorarbeit/code/IAMouflage/data")
_GSECOPS = _DATA / "detections" / "gsecops-detection-rules"
_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

pytestmark = pytest.mark.skipif(
    not _GSECOPS.is_dir(), reason="IAMouflage corpus not present on this machine"
)


@pytest.fixture(scope="module")
def lib() -> DetectionLibrary:
    return DetectionLibrary.load(str(_GSECOPS), str(_EXAMPLES / "candidates.decn"))


@pytest.fixture(scope="module")
def account():
    return load_account(_EXAMPLES / "account.json")


def test_corpus_loads(lib):
    assert len(lib.detections) >= 20
    assert len(lib.bundle.candidates) == 3


def test_blindspot_events_are_unobserved_by_all_real_rules(lib, account):
    rep = probe_permissions(lib, account)
    assert rep.gaps, "expected at least one blind spot for the demo account"
    for gap in rep.gaps:
        # soundness: no real rule fires on the witness
        for d in lib.detections:
            assert fires(d.spec, [gap.event], ref_lists=lib.ref_lists) is not True, (
                gap.permission,
                d.id,
            )


def test_stealth_schedules_replay_clean(lib, account):
    for c in lib.bundle.candidates:
        r = stealth_feasible(c, lib, account)
        if isinstance(r, Evasive):
            for d in lib.detections:
                assert fires(d.spec, list(r.schedule), ref_lists=lib.ref_lists) is not True, (
                    c.id,
                    d.id,
                )


def test_stealthy_chain_is_valid_hop_by_hop(lib, account):
    """Soundness of the chain search, and its corrected verdict under the realism invariants.

    A real ``CreateServiceAccountKey`` event carries ``product_name = "Google Cloud IAM"`` and
    ``granted = true`` (both fixed by the method / authorization), so the corpus rule that watches
    for key creation fires on it — the step is *not* stealthy.  The demo account therefore has no
    stealthy escalation running through key creation (the earlier "found" chain was an artifact of
    the solver fabricating a key-creation event with an empty product_name).  Whatever path the
    search *does* return must still replay clean hop by hop.
    """
    import json

    from decnique.smt.stealth import Evasive, stealth_feasible

    attack = json.loads((_EXAMPLES / "account.json").read_text())["attack"]
    rep = chains_report(lib, account, attack)

    # soundness: every hop of any returned path is unobserved by all rules
    for hop in rep.get("hops", ()):
        for d in lib.detections:
            assert fires(d.spec, hop["schedule"], ref_lists=lib.ref_lists) is not True

    # root cause of the corrected verdict: key creation is caught, so no stealthy path exists
    kc = next(c for c in lib.bundle.candidates if c.id == "create_service_account_key")
    assert not isinstance(stealth_feasible(kc, lib, account), Evasive)
    assert rep["found"] is False
