# Contributing

Read `AGENTS.md` first — it explains the project in two minutes, lists the layout, and states
the five invariants. Nothing below repeats it; this file is only *how to run the checks*.

## Set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # runtime + pytest + hypothesis + ruff + build
npm install                      # installs the git hooks (husky) — see below
```

`npm install` exists only for the hooks; nothing in the package imports JavaScript. Skip it and
you simply lose the local checks — CI runs the same ones.

## The checks, in the order CI runs them

```bash
ruff check .                     # lint; `ruff check --fix .` fixes most of it
pytest -m "not e2e"              # the unit suite — ~20 s
pytest -m e2e                    # the entry points, as real processes — ~15 s
pytest                           # both
```

Two markers exist:

| marker | what it means |
|---|---|
| `e2e` | runs `run.py` or `decnique.cli` in a **subprocess**; slower, checks argv, stdout and exit codes |
| `corpus` | needs a native rule corpus that is not in this repository; skips cleanly without it |

Coverage, the way CI measures it (the gate is 80 %):

```bash
pytest -m "not e2e" --cov=decnique --cov-report=term-missing --cov-fail-under=80
```

The whole test suite assumes the **repository root is the working directory** — `tests/conftest.py`
enforces that, so `pytest` works from anywhere. It also points `$DECNIQUE_CONFIG` at a temporary
file, so no test can read or overwrite your own shell settings.

## The git hooks

`npm install` puts three husky hooks in place. Each one is a few lines of shell in `.husky/`, and
each says how to skip it:

| hook | what it runs | roughly |
|---|---|---|
| `pre-commit` | `ruff check --fix` on the **staged** `.py` files (lint-staged) | under a second |
| `commit-msg` | `commitlint` against `commitlint.config.js` | instant |
| `pre-push` | `pytest -m "not e2e"` | ~20 s |

`git commit --no-verify` / `git push --no-verify` skips them for one command — fine on a branch of
your own, and CI checks the same things anyway.

## The commit convention

`AGENTS.md` §8: **one line**, `type(scope): what and why`, atomic, **no trailers**.
`commitlint.config.js` turns that into rules — Conventional Commits for the shape, plus three of
this project's own: the type list it actually uses (`feat` `fix` `docs` `test` `refactor` `perf`
`chore` `ci` `build` `revert`), `body-empty` (that is what "one line" means), and a local
`no-trailers` rule that rejects `Co-authored-by:`, `Signed-off-by:` and friends. `revert:` commits
are exempt, because `git revert` writes its own message.

```
test: cover the CLI, yaml_io and the predicate model          ✓
fix(yaml_io): tag AST nodes under node so InList reads back   ✓
added stuff                                                   ✗  type may not be empty
wip: something                                                ✗  type must be one of […]
feat: Adds a thing.                                           ✗  subject-case, subject-full-stop
```

CI re-runs `commitlint` over every commit in a pull request, since a local hook can be skipped.

## What CI does

`.github/workflows/ci.yml`, five jobs:

1. **commits** — `commitlint` over the pull request's commits.
2. **lint** — `ruff check`.
3. **test** — the unit suite on Python 3.11, 3.12 and 3.13, with the coverage floor.
4. **e2e** — installs the package (not editable) and runs the `e2e`-marked tests, so the
   console script and the packaged data files (`grammar.lark`, the GCP catalogs) are exercised
   the way a user meets them.
5. **package** — builds the sdist and wheel, runs `twine check`, installs the wheel into a fresh
   virtualenv and parses a rule with it.

## Writing a change

The conventions in `AGENTS.md` §8 hold. In particular:

- **No new runtime dependencies.** `lark`, `pyyaml`, `z3-solver`, `rich`, `prompt_toolkit` — that
  is the list. Test and lint tooling lives in the `test` / `dev` extras and is never imported by
  the package; the npm packages are hooks only.
- **A test for every behaviour change.** Corpus-dependent tests must skip cleanly without the corpus.

### What a good test looks like here

The suite is not aiming at line coverage for its own sake; it pins the properties the tool's
answers rest on. When you add one, say in its docstring *what breaks in the product* if the
assertion fails. Worked examples already in the tree:

- `tests/test_model_predicates.py` — `normalize` may never change what a predicate means
  (property-based, against the interpreter, in three-valued logic).
- `tests/test_dsl_yaml_io.py` — every AST node survives a round trip, so an `unknown` atom can
  never be lost on the way through YAML and make an approximate rule read as exact.
- `tests/e2e/test_pipeline_e2e.py` — a reported gap's witness is replayed through the oracle,
  which is invariant #2 checked across a process boundary.
- `tests/test_roundtrip.py` — `parse(format(x)) == x` over every bundled example.

The extending recipes (a new front-end idiom, check type, shell verb, setting) are in
`AGENTS.md` §6, each of which names the test that has to stay green.
