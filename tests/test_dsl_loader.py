"""The loader: which files are recognised, which front-end reads them, and what a directory
of mixed rules turns into.

`rules load <dir>` is how every corpus reaches the tool.  With no corpus on the machine this
whole path used to run nowhere, so a file type silently stopping to load would not show up
until someone pointed the shell at a real rule directory.
"""

from __future__ import annotations

import pytest

from decnique.dsl.loader import (
    LoadOptions,
    iter_files,
    load_corpus,
    load_file,
    load_paths,
    select,
    sniff,
    summary,
)

_DECN = 'detection d_local { event method = "SetIamPolicy" }\n'
_YARAL = 'rule y_gcp {\n  meta:\n    platform = "GCP"\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n}\n'
_SIGMA = (
    "title: sigma rule\nid: aaaa-bbbb\nlogsource:\n    product: gcp\n    service: gcp.audit\n"
    "detection:\n    selection:\n        gcp.audit.method_name: SetIamPolicy\n    condition: selection\n"
)
_ELASTIC = (
    '[metadata]\nmaturity = "production"\nintegration = ["gcp"]\n\n[rule]\nrule_id = "e-1"\n'
    'name = "elastic rule"\nlanguage = "kuery"\ntype = "query"\nquery = """\nevent.action:SetIamPolicy\n"""\n'
)
_PANTHER_YML = "AnalysisType: rule\nRuleID: GCP.Panther.One\nLogTypes:\n    - GCP.AuditLog\nFilename: p.py\n"
_PANTHER_PY = 'def rule(event):\n    return event.deep_get("protoPayload", "methodName") == "SetIamPolicy"\n'
_AST_YAML = (
    "detections:\n"
    "  - kind: detection\n    id: y_from_yaml\n    spec:\n      events:\n"
    '        - name: e\n          pred: {kind: cmp, field: [null, method], op: "=", value: SetIamPolicy}\n'
    "      condition: {kind: count, var: e, op: '>=', n: 1}\n"
)


def _corpus(tmp_path):
    """A directory shaped like a real mixed corpus."""
    (tmp_path / "gcp").mkdir()
    (tmp_path / "gcp" / "rule.yaral").write_text(_YARAL)
    (tmp_path / "sigma_rule.yml").write_text(_SIGMA)
    (tmp_path / "elastic_rule.toml").write_text(_ELASTIC)
    (tmp_path / "panther.yml").write_text(_PANTHER_YML)
    (tmp_path / "p.py").write_text(_PANTHER_PY)
    (tmp_path / "own.decn").write_text(_DECN)
    return tmp_path


# --- recognising files ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        ("r.decn", _DECN, "dsl"),
        ("r.yaral", _YARAL, "secops"),
        ("r.yml", _SIGMA, "sigma"),
        ("r.yml", _PANTHER_YML, "panther"),
        ("r.toml", _ELASTIC, "elastic"),
        ("r.yaml", _AST_YAML, "ast"),
        ("r.json", '{"detections": [], "candidates": []}', "ast"),
        ("r.toml", "[tool.black]\nline-length = 100\n", None),
        ("r.yml", "name: some other yaml\n", None),
        ("r.txt", "anything", None),
        ("r.json", "[1, 2, 3]", None),
    ],
)
def test_sniff_recognises_a_file_by_its_content(name, text, expected, tmp_path):
    """Recognition is by content: a corpus laid out differently must still load."""
    p = tmp_path / name
    p.write_text(text)
    assert sniff(p) == expected
    assert sniff(p, text) == expected


def test_a_file_that_cannot_be_read_is_not_a_rule(tmp_path):
    p = tmp_path / "binary.yml"
    p.write_bytes(b"\xff\xfe\x00\x01")
    assert sniff(p) is None
    assert load_file(p).detections == ()


def test_an_unrecognised_file_loads_nothing(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    assert load_file(p) .detections == ()


def test_a_front_end_can_be_switched_off(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text(_SIGMA)
    assert load_file(p).detections
    assert load_file(p, LoadOptions(frontends=("dsl",))).detections == ()


def test_a_broken_dsl_file_is_a_load_error_not_a_crash(tmp_path):
    p = tmp_path / "bad.decn"
    p.write_text("detection d { event method = }\n")
    assert any(i.severity == "error" for i in load_file(p).issues)


# --- walking a directory ------------------------------------------------------------------------


def test_a_mixed_directory_loads_every_front_end(tmp_path):
    b = load_paths([_corpus(tmp_path)])
    assert not b.errors, b.errors
    by_frontend = summary(b)["by_frontend"]
    assert by_frontend == {"dsl": 1, "secops": 1, "sigma": 1, "elastic": 1, "panther": 1}


def test_load_corpus_is_the_same_as_loading_the_directory(tmp_path):
    root = _corpus(tmp_path)
    assert len(load_corpus(root).detections) == len(load_paths([root]).detections)


def test_the_walk_skips_the_directories_a_repository_keeps_rules_out_of(tmp_path):
    root = _corpus(tmp_path)
    for skipped in (".git", "tests", "docs", "_deprecated"):
        (root / skipped).mkdir()
        (root / skipped / "x.decn").write_text('detection d_skipped { event method = "X" }\n')
    files = {p.name for p in iter_files(root)}
    assert "x.decn" not in files
    kept = iter_files(root, LoadOptions(include_deprecated=True))
    assert any(p.parent.name == "_deprecated" for p in kept)


def test_a_file_larger_than_the_limit_is_skipped(tmp_path):
    root = _corpus(tmp_path)
    assert list(iter_files(root, LoadOptions(max_file_bytes=10))) == []


def test_naming_one_file_loads_only_that_file(tmp_path):
    root = _corpus(tmp_path)
    assert [p.name for p in iter_files(root / "own.decn")] == ["own.decn"]


def test_a_path_that_does_not_exist_is_reported(tmp_path):
    b = load_paths([tmp_path / "nope"])
    assert any("does not exist" in i.message for i in b.errors)


def test_a_secops_rule_outside_a_gcp_directory_needs_to_say_it_is_gcp(tmp_path):
    (tmp_path / "other.yaral").write_text(_YARAL.replace('platform = "GCP"', 'platform = "AWS"'))
    assert load_paths([tmp_path]).detections == ()
    assert load_paths([tmp_path], LoadOptions(gcp_only=False)).detections


def test_a_secops_rule_that_never_mentions_gcp_is_not_even_parsed(tmp_path):
    (tmp_path / "aws.yaral").write_text(
        'rule aws_only {\n  events:\n    $e.metadata.event_type = "X"\n  condition:\n    $e\n}\n'
    )
    assert load_paths([tmp_path]).detections == ()


def test_selecting_by_front_end_and_by_name(tmp_path):
    b = load_paths([_corpus(tmp_path)])
    assert [d.id for d in select(b, frontend="dsl")] == ["d_local"]
    assert [d.id for d in select(b, pattern="y_*")] == ["y_gcp"]


def test_the_summary_counts_what_the_shell_shows(tmp_path):
    b = load_paths([_corpus(tmp_path)])
    s = summary(b)
    assert s["detections"] == 5
    assert s["exact"] + s["approximate"] == s["detections"]
    assert s["candidates"] == 0 and s["checks"] == 0
    assert isinstance(s["unsupported_labels"], dict)


# --- rulesets ------------------------------------------------------------------------------------


def test_a_ruleset_includes_files_relative_to_the_file_that_declares_it(tmp_path):
    (tmp_path / "extra.decn").write_text('detection d_extra { event method = "storage.objects.get" }\n')
    (tmp_path / "main.decn").write_text(_DECN + 'ruleset rs { include "extra.decn" }\n')
    b = load_paths([tmp_path / "main.decn"])
    assert {d.id for d in b.detections} == {"d_local", "d_extra"}


def test_a_ruleset_include_that_matches_nothing_is_a_warning(tmp_path):
    (tmp_path / "main.decn").write_text(_DECN + 'ruleset rs { include "nowhere/*.decn" }\n')
    b = load_paths([tmp_path / "main.decn"])
    assert any("matches no file" in i.message for i in b.issues)


def test_a_ruleset_can_disable_a_rule_and_enable_it_again(tmp_path):
    (tmp_path / "main.decn").write_text(
        _DECN + 'detection d_two { event method = "storage.objects.get" }\n'
        "ruleset rs { disable d_two }\n"
    )
    assert {d.id for d in load_paths([tmp_path / "main.decn"]).detections} == {"d_local"}
    (tmp_path / "both.decn").write_text(
        _DECN + "ruleset rs_off { disable d_local }\nruleset rs_on { enable d_local }\n"
    )
    assert {d.id for d in load_paths([tmp_path / "both.decn"]).detections} == {"d_local"}


def test_disabling_a_rule_that_does_not_exist_is_a_warning(tmp_path):
    (tmp_path / "main.decn").write_text(_DECN + "ruleset rs { disable d_nothing }\n")
    b = load_paths([tmp_path / "main.decn"])
    assert any("unknown rule d_nothing" in i.message for i in b.issues)
