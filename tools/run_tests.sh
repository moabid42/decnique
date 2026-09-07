#!/bin/sh
# The `pre-push` hook's body: the unit suite, with the project's own interpreter.
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

exec "$PY" -m pytest -q -m "not e2e"
