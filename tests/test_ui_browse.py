"""The browsing verbs: perms / methods / roles / who never flood the screen and never need
the solver.  They run without an account or rules where they can, and say what they need."""

from decnique.ui.config import Settings
from decnique.ui.repl import dispatch
from decnique.ui.session import Session


def _session(tmp_path) -> Session:
    from decnique.ui.render import console

    console.width = 240  # the capture is 80 columns wide; long names must not wrap
    s = Session()
    s.settings = Settings(tmp_path / "cfg.json")
    return s


def test_perms_without_account_or_rules(tmp_path, capsys):
    s = _session(tmp_path)
    assert dispatch(s, "perms") is True
    out = capsys.readouterr().out
    assert "permissions by service" in out and "showing 20 of" in out
    assert dispatch(s, "perms iam.serviceAccountKeys --limit 2") is True
    out = capsys.readouterr().out
    assert "iam.serviceAccountKeys.create" in out and "showing 2 of" in out
    assert dispatch(s, "perms --reachable") is True  # needs an account: guard, not a crash
    assert "needs an account" in capsys.readouterr().out
    assert dispatch(s, "perms --tag nope") is True
    assert "unknown tag" in capsys.readouterr().out


def test_perms_with_account_and_tag(tmp_path, capsys):
    s = _session(tmp_path)
    dispatch(s, "account examples/account.json")
    capsys.readouterr()
    assert dispatch(s, "perms --reachable") is True
    out = capsys.readouterr().out
    assert "resourcemanager.projects.setIamPolicy" in out and "admin@demo.com" in out
    assert dispatch(s, "perms --tag PrivEsc --reachable") is True
    assert "setIamPolicy" in capsys.readouterr().out


def test_methods_permission_and_method_card(tmp_path, capsys):
    s = _session(tmp_path)
    assert dispatch(s, "methods iam.serviceAccountKeys.create") is True  # works without an account
    out = capsys.readouterr().out
    assert "CreateServiceAccountKey" in out and "verified" in out
    assert dispatch(s, "methods google.iam.admin.v1.CreateServiceAccountKey") is True
    out = capsys.readouterr().out
    assert "pinned fields" in out and "iam.serviceAccountKeys.create" in out
    assert dispatch(s, "methods iam.serviceAccountKeys.creat") is True
    assert "did you mean" in capsys.readouterr().out


def test_roles(tmp_path, capsys):
    s = _session(tmp_path)
    assert dispatch(s, "roles iam.serviceAccount --limit 3") is True
    assert "showing 3 of" in capsys.readouterr().out
    assert dispatch(s, "roles --with iam.serviceAccountKeys.create --limit 3") is True
    out = capsys.readouterr().out
    assert out.index("roles/iam.serviceAccountKeyAdmin") < out.index("roles/iam.editor")  # smallest first
    assert dispatch(s, "roles roles/owner iam.serviceAccountKeys") is True
    assert "iam.serviceAccountKeys.create" in capsys.readouterr().out
    assert dispatch(s, "roles no/such/role") is True
    assert "no role matches" in capsys.readouterr().out


def test_who(tmp_path, capsys):
    s = _session(tmp_path)
    assert dispatch(s, "who") is True  # no account: guard
    assert "no account" in capsys.readouterr().out
    dispatch(s, "account examples/account.json")
    capsys.readouterr()
    assert dispatch(s, "who") is True
    assert "admin@demo.com" in capsys.readouterr().out
    assert dispatch(s, "who resourcemanager.projects.setIamPolicy") is True
    assert "admin@demo.com" in capsys.readouterr().out
    assert dispatch(s, "who admin@demo.com") is True
    assert "setIamPolicy" in capsys.readouterr().out
    assert dispatch(s, "who no.such.permission") is True
    assert "nobody" in capsys.readouterr().out
