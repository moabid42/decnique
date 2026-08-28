"""Differential test: the atom-abstraction coverage engine agrees with the legacy z3-string
engine (kept in ``decnique.smt.legacy_coverage``) on gap / no-gap, and its witnesses are sound.
See docs/COVERAGE_ABSTRACTION.md §3."""

from __future__ import annotations

from pathlib import Path

import pytest

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires
from decnique.smt import legacy_coverage as legacy
from decnique.smt.coverage import CoverageContext, Gap, find_gap

PERMS = (
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.getAccessToken",
    "resourcemanager.projects.setIamPolicy",
    "storage.objects.get",
)

SUITES = {
    "plain": """
        detection watch_key { event method = "google.iam.admin.v1.CreateServiceAccountKey" }
        detection watch_token {
          event method = "iam.serviceAccounts.getAccessToken"
            and not caller_ip in cidr ["10.0.0.0/8"]
        }
    """,
    "substrings": """
        detection ua { event user_agent contains "curl" and method = "storage.objects.get" }
        detection ua2 { event user_agent startswith "python" and method = "storage.objects.get" }
        detection set { event method = "SetIamPolicy" or method = "google.iam.admin.v1.SetIAMPolicy"
                        or method = "google.cloud.resourcemanager.v3.Projects.SetIamPolicy" }
    """,
    "allowlist": """
        detection not_internal {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
            and not (user_agent like "*gcloud*" or user_agent like "kube-probe*")
        }
        detection anyget { event method = "storage.objects.get" and resource like "projects/*" }
    """,
    "udm": """
        detection raw { event udm("principal.ip") = "1.2.3.4" and method = "storage.objects.get" }
        detection token { event method = "iam.serviceAccounts.getAccessToken" and principal endswith "@x.com" }
    """,
}


def _account() -> Account:
    return Account(
        name="t",
        bindings={"attacker@x.com": tuple(Grant(permission=p) for p in PERMS)},
        logging=LogConfig(
            admin_activity=True,
            data_access_services=frozenset({"iamcredentials.googleapis.com", "storage.googleapis.com"}),
        ),
    )


def _sound(lib: DetectionLibrary, acct: Account, g: Gap) -> None:
    assert all(fires(d.spec, [g.event]) is not True for d in lib.detections)
    assert acct.logged(g.event["method"])
    assert acct.reach(g.event["principal"], g.permission, g.event.get("resource", "*"))


@pytest.mark.parametrize("name", sorted(SUITES))
def test_new_agrees_with_legacy(name: str):
    lib = DetectionLibrary(parse_text(SUITES[name], f"{name}.decn"))
    acct = _account()
    ctx = CoverageContext(lib)
    for p in PERMS:
        new = find_gap(p, lib, acct, ctx=ctx)
        old = legacy.find_gap(p, lib, acct)
        assert new.found == old.found, (name, p, new, old)
        if isinstance(new, Gap):
            _sound(lib, acct, new)
    assert ctx.stats["unproven"] == 0  # every verdict above is a proof, not an exhaustion


_DATA = Path("/Users/nil/BachelorArbeit/Bachelorarbeit/code/IAMouflage/data/detections")


@pytest.mark.skipif(not _DATA.is_dir(), reason="IAMouflage corpus not present on this machine")
def test_corpus_gcp_witnesses_sound_and_fast():
    import time

    from decnique.env import load_account

    dirs = ("gsecops-detection-rules", "elastic-detection-rules", "sigma-rules", "panther-analysis-rules")
    lib = DetectionLibrary.load(*[str(_DATA / d) for d in dirs])
    acct = load_account(Path(__file__).resolve().parent.parent / "examples" / "account.json")
    ctx = CoverageContext(lib)
    perms = sorted(p for p in acct.catalog.all_permissions() if acct.reachable(p))
    t = time.time()
    for p in perms:
        r = find_gap(p, lib, acct, ctx=ctx)
        if isinstance(r, Gap):
            _sound(lib, acct, r)
    assert time.time() - t < 5.0  # the legacy engine needed seconds *per permission*
    assert ctx.stats["unproven"] == 0
