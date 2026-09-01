"""Loading the same thing twice yields it once.  An id that repeats with identical content
collapses silently (even across two files); an id that repeats with *different* content is a
real clash and is reported.  Events dedupe by content."""

from __future__ import annotations

from decnique.dsl.loader import load_paths
from decnique.ui.session import _events_from


def _w(tmp, name, text):
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_same_file_twice_in_one_load_collapses(tmp_path):
    f = _w(tmp_path, "r.decn",
           'detection d1 { event method = "SetIamPolicy" }\n'
           'candidate c1 { required { iam.serviceAccountKeys.create } '
           'footprint { a: "google.iam.admin.v1.CreateServiceAccountKey" span 1h } }\n'
           'check q1 { type dead_rules }\n')
    b = load_paths([f, f])  # same path listed twice
    assert len(b.detections) == 1 and len(b.candidates) == 1 and len(b.checks) == 1
    assert not b.errors  # identical content is not a clash


def test_identical_rule_in_two_files_collapses_silently(tmp_path):
    a = _w(tmp_path, "a.decn", 'detection d1 { event method = "SetIamPolicy" }\n')
    c = _w(tmp_path, "b.decn", 'detection d1 { event method = "SetIamPolicy" }\n')
    b = load_paths([a, c])
    assert len(b.detections) == 1
    assert not b.errors


def test_same_id_different_content_is_a_clash(tmp_path):
    a = _w(tmp_path, "a.decn", 'detection d1 { event method = "SetIamPolicy" }\n')
    c = _w(tmp_path, "b.decn", 'detection d1 { event method = "storage.objects.get" }\n')
    b = load_paths([a, c])
    assert len(b.detections) == 1  # first kept
    assert any("duplicate detection id d1" in i.message for i in b.errors)


def test_duplicate_candidates_collapse(tmp_path):
    f = _w(tmp_path, "c.decn",
           'candidate c1 { required { iam.serviceAccountKeys.create } '
           'footprint { a: "google.iam.admin.v1.CreateServiceAccountKey" span 1h } }\n')
    b = load_paths([f, f, f])
    assert len(b.candidates) == 1 and not b.errors


def test_events_dedupe_by_content():
    e = {"udm": {"metadata": {"event_type": "x"}}, "method": "SetIamPolicy"}
    other = {"method": "storage.objects.get"}
    out = _events_from([e, dict(e), other, dict(e)])
    assert out == [e, other]  # duplicates dropped, order and first-seen preserved
