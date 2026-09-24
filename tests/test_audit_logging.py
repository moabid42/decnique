"""Category-specific audit logging and exemptions must agree in the account, solver and replay."""

from dataclasses import replace

import pytest

from decnique.checks import run_check
from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env import (
    Account,
    AuditLogConfig,
    Catalog,
    Grant,
    LogConfig,
    MethodInfo,
    account_from_dict,
)
from decnique.env.gcp_import import account_doc_from_gcp
from decnique.smt.coverage import Gap, NoGap, find_gap
from decnique.smt.stealth import AlwaysDetected, Evasive, Exhausted, stealth_feasible

READ, WRITE = "storage.objects.get", "storage.objects.delete"
SERVICE, ACTOR, PROJECT = "storage.googleapis.com", "alice@example.test", "projects/p"


def _account(*configs):
    return Account(bindings={ACTOR: (Grant("storage.*", PROJECT),)}, catalog=Catalog.seed(),
                   logging=LogConfig(audit_configs=tuple(configs)))


def _config(category="DATA_READ", *, resource=PROJECT, exempt=(), service=SERVICE):
    return AuditLogConfig(service, category, resource, exempt)


def _lib(method=READ, actor=""):
    return DetectionLibrary(parse_text(
        f'detection watched {{ event method = "{method}" }}\n'
        f'candidate action {{ {actor} required {{ {method} }} footprint {{ act: "{method}" }} }}\n'
        'check covered { type candidate for action }', "logging.decn"))


@pytest.mark.parametrize("category,read,write", [("DATA_READ", True, False), ("DATA_WRITE", False, True),
                                               ("ADMIN_READ", False, False)])
def test_categories_do_not_enable_each_other(category, read, write):
    """Enabling read telemetry must not invent write telemetry, or vice versa."""
    acct = _account(_config(category))
    assert acct.logged(READ, principal=ACTOR, resource=PROJECT) is read
    assert acct.logged(WRITE, principal=ACTOR, resource=PROJECT) is write
    assert not acct.logged(READ, principal=ACTOR, resource="projects/other")


def test_admin_read_is_imported_without_enabling_data_read():
    """IAM token auditing uses ADMIN_READ, which the importer must not discard."""
    raw = {"bindings": [], "auditConfigs": [{"service": "allServices", "auditLogConfigs": [
        {"logType": "ADMIN_READ"}]}]}
    acct = account_from_dict(account_doc_from_gcp(raw, resource=PROJECT), catalog=Catalog.seed())
    assert acct.logged("iam.serviceAccounts.getAccessToken", resource=PROJECT)
    assert not acct.logged(READ, resource=PROJECT)


def test_inherited_and_service_wide_exemptions_are_unioned():
    """A child/service-specific enable cannot cancel a parent/allServices exemption."""
    acct = _account(_config(resource="folders/f", service="*", exempt=(ACTOR,)), _config())
    acct.hierarchy[PROJECT] = "folders/f"
    acct.hierarchy["buckets/b"] = PROJECT
    assert not acct.logged(READ, principal=ACTOR, resource="buckets/b")
    assert acct.logged(READ, principal="bob@example.test", resource="buckets/b")


def test_exempted_actor_evades_even_a_method_wide_rule():
    """The solver must choose an exempted actor and replay no event into the detection rule."""
    acct = _account(_config(exempt=(ACTOR,)))
    acct.bindings["bob@example.test"] = (Grant(READ, PROJECT),)
    lib = _lib()
    result = stealth_feasible(lib.bundle.candidates[0], lib, acct)
    assert isinstance(result, Evasive), result
    assert result.principal == ACTOR and result.unlogged == (READ,)
    assert not result.approximate
    assert not any(acct.event_logged(e) for e in result.schedule)
    check = run_check(lib.bundle.checks[0], lib, acct)
    assert check.verdict == "fail" and not check.approximate


def test_logging_scope_is_symbolic_and_not_a_service_wide_switch():
    """A technique in an unaudited project must evade despite another project's audit config."""
    acct = _account(_config(resource="projects/other"))
    lib = _lib()
    result = stealth_feasible(lib.bundle.candidates[0], lib, acct)
    assert isinstance(result, Evasive) and result.unlogged == (READ,)
    audited = replace(acct, logging=LogConfig(audit_configs=(_config(),)))
    assert isinstance(stealth_feasible(lib.bundle.candidates[0], lib, audited), AlwaysDetected)


def test_coverage_witness_must_be_logged_for_its_concrete_actor():
    """Coverage cannot report an exempted principal as evidence of a logged blind spot."""
    acct = _account(_config(exempt=(ACTOR,)))
    acct.bindings["bob@example.test"] = (Grant(READ, PROJECT),)
    empty = DetectionLibrary(parse_text("", "empty.decn"))
    result = find_gap(READ, empty, acct)
    assert isinstance(result, Gap), result
    assert result.event["principal"] == "bob@example.test" and acct.event_logged(result.event)
    assert not result.approximate
    exempt_only = _account(_config(exempt=(ACTOR,)))
    assert isinstance(find_gap(READ, empty, exempt_only), NoGap)
    assert find_gap(WRITE, empty, acct).reason == "no_logged_method"


def test_unknown_category_cannot_become_an_exact_proof_or_export():
    """Missing method/category facts must survive as caveats through checks and engines."""
    acct = _account(_config())
    acct.catalog = Catalog({READ: MethodInfo(READ, (READ,), SERVICE, data_access=True)})
    lib = _lib()
    result = stealth_feasible(lib.bundle.candidates[0], lib, acct)
    assert isinstance(result, Exhausted) and "category" in " ".join(result.caveats)
    gap = find_gap(READ, DetectionLibrary(parse_text("", "empty.decn")), acct)
    assert isinstance(gap, Gap) and gap.approximate and gap.caveats
    check = run_check(lib.bundle.checks[0], lib, acct)
    assert check.verdict == "unknown" and check.caveats


def test_opaque_exemptions_remain_assumptions_and_precise_empty_configs_override_legacy():
    """Group membership cannot be guessed, nor can a summary service list enable absent categories."""
    raw = {"bindings": [], "auditConfigs": [{"service": SERVICE, "auditLogConfigs": [
        {"logType": "DATA_READ", "exemptedMembers": ["group:security@example.test"]}]}]}
    acct = account_from_dict(account_doc_from_gcp(raw), catalog=Catalog.seed())
    assert any("exemption" in note for note in acct.assumptions)
    legacy = replace(acct, logging=LogConfig(data_access_services=frozenset({SERVICE})))
    assert legacy.logged(READ) and legacy.logged(WRITE)
    precise = replace(legacy, logging=replace(legacy.logging, audit_configs=()))
    assert not precise.logged(READ) and not precise.logged(WRITE)
