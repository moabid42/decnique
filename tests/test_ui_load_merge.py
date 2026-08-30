"""`load` is additive: loading candidates after rules must keep the rules (and vice-versa).
Regression for the bug where the second `load` replaced the whole library."""

from decnique.ui.session import Session


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_load_is_additive(tmp_path):
    rules = _write(tmp_path, "r.decn",
                   'detection d1 { event method = "SetIamPolicy" }\n'
                   'detection d2 { event method = "storage.objects.get" }\n')
    cands = _write(tmp_path, "c.decn",
                   'candidate c1 { required { iam.serviceAccountKeys.create } '
                   'footprint { a: "google.iam.admin.v1.CreateServiceAccountKey" span 1h } }\n')

    s = Session()
    s.load([rules])
    assert len(s.lib.detections) == 2 and len(s.lib.bundle.candidates) == 0

    s.load([cands])  # must NOT drop the rules
    assert len(s.lib.detections) == 2, "loading candidates dropped the rules"
    assert len(s.lib.bundle.candidates) == 1


def test_reload_replaces_by_id_no_duplicate(tmp_path):
    rules = _write(tmp_path, "r.decn", 'detection d1 { event method = "SetIamPolicy" }\n')
    s = Session()
    s.load([rules])
    s.load([rules])  # same id twice
    assert len(s.lib.detections) == 1, "reloading duplicated the detection"


def test_candidate_only_library_is_usable(tmp_path):
    """A library with 0 detections but some candidates must still count as loaded
    (DetectionLibrary is falsy at len 0 — callers must test `is not None`, not truthiness)."""
    cands = _write(tmp_path, "c.decn",
                   'candidate c1 { required { iam.serviceAccountKeys.create } '
                   'footprint { a: "google.iam.admin.v1.CreateServiceAccountKey" span 1h } }\n')
    s = Session()
    s.load([cands])
    assert s.lib is not None
    assert s.need_lib() is True
    assert len(s.lib.bundle.candidates) == 1
