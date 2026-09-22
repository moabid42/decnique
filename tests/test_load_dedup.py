"""Loading the same thing twice yields it once.  An id that repeats with identical content
collapses silently (even across two files); an id that repeats with *different* content is a
real clash and is reported.  Event occurrences keep their multiplicity unless Cloud Logging's
stable identity proves that an exported record was ingested twice."""

from __future__ import annotations

from decnique.dsl.loader import load_paths
from decnique.dsl.parser import parse_text
from decnique.eval import fires
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


def test_identical_events_without_provider_ids_keep_their_multiplicity():
    """A count detection must see two equal occurrences instead of one normalized value."""
    event = {"method": "SetIamPolicy"}
    events = _events_from([event, dict(event)])
    detection = parse_text(
        'detection repeated { events { e: method = "SetIamPolicy" } condition #e >= 2 }',
        "count.decn",
    ).detections[0]

    assert events == [event, event]
    assert fires(detection.spec, events) is True


def test_cloud_logging_ingestion_duplicates_collapse_by_stable_identity():
    """An exported retry must not inflate a count detection when its provider identity agrees."""
    entry = {
        "insertId": "abc123",
        "timestamp": "2026-09-22T10:00:00Z",
        "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {"methodName": "SetIamPolicy"},
    }

    assert _events_from([entry, dict(entry)]) == _events_from([entry])


def test_insert_id_alone_does_not_collapse_distinct_occurrences():
    """Cloud Logging scopes duplicate identity by log and timestamp, not insertId alone."""
    first = {
        "insertId": "abc123",
        "timestamp": "2026-09-22T10:00:00Z",
        "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {"methodName": "SetIamPolicy"},
    }
    later = {**first, "timestamp": "2026-09-22T10:01:00Z"}

    assert len(_events_from([first, later])) == 2
