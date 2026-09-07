#!/bin/sh
# The `pre-push` hook's body: the gates CI runs, before the push instead of after.
#
#   1. ruff, if this machine has one (the `pre-commit` hook only sees *staged* files)
#   2. the unit suite with the coverage floor, and the rule corpus HIDDEN
#   3. the end-to-end suite (the entry points as real processes)
#   4. the corpus tests, when this machine has a rule corpus
#
# Gate 1 hides the corpus on purpose (`$DECNIQUE_CORPUS` points nowhere).  CI has no corpus,
# and the corpus is what exercises the four front-ends: with it visible the coverage floor
# passes here and fails there — which is how a red CI run got pushed in the first place.
#
# A git hook inherits your *login* environment, not the shell you typed `git push` in, so the
# virtualenv is usually not active and a bare `python` is whatever came with the system — which
# does not have lark or z3 and fails with an import error that looks like a broken repository.
# Find the right interpreter instead of assuming one.

set -e

for candidate in "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}" ./.venv/bin/python ./venv/bin/python; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        PY="$candidate"
        break
    fi
done

if [ -z "$PY" ]; then
    PY=$(command -v python3 || command -v python || true)
fi

if [ -z "$PY" ] || ! "$PY" -c "import pytest, decnique" >/dev/null 2>&1; then
    echo "pre-push: no interpreter with the project installed."
    echo "  uv venv && uv pip install -e '.[dev]'    (or the pip equivalent)"
    echo "  to push anyway, once:  git push --no-verify"
    exit 1
fi

if ! "$PY" -c "import pytest_cov" >/dev/null 2>&1; then
    echo "pre-push: pytest-cov is missing, so the coverage floor CI enforces cannot be checked."
    echo "  uv pip install -e '.[dev]'"
    exit 1
fi

RUFF=""
for candidate in "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/ruff}" ./.venv/bin/ruff "$(command -v ruff || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        RUFF="$candidate"
        break
    fi
done

echo "pre-push 1/4: ruff"
if [ -n "$RUFF" ]; then
    "$RUFF" check .
elif command -v uvx >/dev/null 2>&1; then
    uvx ruff@0.16.6 check .          # the version the CI job and the pre-commit hook pin
else
    echo "  no ruff on this machine — skipped (CI still runs it)"
fi

echo "pre-push 2/4: unit suite + coverage floor, with no rule corpus (what CI runs)"
DECNIQUE_CORPUS=./.no-such-corpus \
    "$PY" -m pytest -q -m "not e2e" --cov=decnique --cov-report=term-missing

echo "pre-push 3/4: end-to-end suite"
"$PY" -m pytest -q -m e2e

echo "pre-push 4/4: corpus tests (skipped when this machine has no corpus)"
"$PY" -m pytest -q -m corpus
