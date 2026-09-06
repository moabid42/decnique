"""Shared test setup.

Two things every test in this repository needs and should not repeat:

* **the repository root as the working directory** — the suite refers to the bundled data by
  relative path (``examples/accounts/custom/account.json``), so `pytest` must behave the same
  whether it was started from the root, from ``tests/``, or by an IDE;
* **an isolated config file** — the shell persists settings to ``~/.config/decnique/config.json``
  (or ``$DECNIQUE_CONFIG``).  Without this a developer's own settings would change test results,
  and a test could overwrite them.

`run_cli` runs the real command-line entry points in a **subprocess**, which is what the
end-to-end tests need: it exercises argv parsing, the console script and the process exit code,
none of which an in-process call to ``main()`` can check.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _repo_root_cwd(monkeypatch):
    """Every test runs from the repository root, wherever pytest was started."""
    monkeypatch.chdir(ROOT)


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    """No test reads or writes the developer's real ``config.json``."""
    monkeypatch.setenv("DECNIQUE_CONFIG", str(tmp_path / "decnique-config.json"))


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@dataclass(frozen=True)
class CliResult:
    argv: list[str]
    code: int
    out: str
    err: str

    def json(self) -> object:
        """The JSON document printed on stdout, ignoring anything printed before it."""
        import json

        start = self.out.find("{")
        assert start >= 0, f"no JSON object on stdout of {self.argv}:\n{self.out}\n{self.err}"
        return json.loads(self.out[start:])


@pytest.fixture
def run_cli(tmp_path):
    """Run an entry point in a fresh process and return its exit code and output.

    ``run_cli("run.py", "ask", "check")`` or ``run_cli("-m", "decnique.cli", "parse", f)``.
    The child gets the repository on ``PYTHONPATH`` so the suite passes against the working
    tree whether or not the package is pip-installed, and an isolated config file.
    """

    def run(*args: str, timeout: float = 300.0) -> CliResult:
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT), env.get("PYTHONPATH", "")]).rstrip(
            os.pathsep
        )
        env["DECNIQUE_CONFIG"] = str(tmp_path / "child-config.json")
        env["PYTHONIOENCODING"] = "utf-8"
        argv = [sys.executable, *args]
        p = subprocess.run(
            argv,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,  # a command that opens the shell must not wait for a tty
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CliResult(argv=argv, code=p.returncode, out=p.stdout, err=p.stderr)

    return run
