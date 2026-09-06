# Contributing

Read `AGENTS.md` first — it explains the project in two minutes, lists the layout, and states
the five invariants. Nothing below repeats it; this file is only *how to run the checks*.

## Set up

With [uv](https://docs.astral.sh/uv/) — what CI uses, and it resolves this dependency set in
about a second:

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"       # runtime + pytest + hypothesis + ruff + pre-commit + build
pre-commit install               # the git hooks — see below
```

Plain pip works exactly the same (`python -m venv .venv`, `pip install -e ".[dev]"`); uv is
faster, not required. Nothing in the toolchain is outside the Python ecosystem.

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

`pre-commit install` sets up all three hook types at once (`.pre-commit-config.yaml` says so):

| hook | what it runs | roughly |
|---|---|---|
| `pre-commit` | `ruff check --fix` on the **staged** files, plus whitespace / YAML / TOML / JSON checks | under a second |
| `commit-msg` | `python tools/commit_msg.py` | instant |
| `pre-push` | `pytest -m "not e2e"` | ~20 s |

`pre-commit run --all-files` runs them over the whole tree by hand.
`git commit --no-verify` / `git push --no-verify` skips them for one command — fine on a branch of
your own, and CI checks the same things anyway.

A git hook inherits your *login* environment, not the shell you typed the command in, so the venv
is usually not active when one runs. Both local hooks handle that themselves: the commit checker
is standard-library-only, and `tools/run_fast_tests.sh` looks for `$VIRTUAL_ENV`, then `.venv/`,
before falling back to the system interpreter.

## The commit convention

`AGENTS.md` §8: **one line**, `type(scope): what and why`, atomic, **no trailers**.
`tools/commit_msg.py` is that paragraph as a program — 60 lines of standard library, no
dependency, and `tests/test_commit_msg.py` covers it. It checks the type against the list this
repository actually uses (`feat` `fix` `docs` `test` `refactor` `perf` `chore` `ci` `build`
`revert`), a lower-case subject with no full stop, a header under 100 characters, one line only,
and no `Co-authored-by:` / `Signed-off-by:` style trailers. Merges, reverts and `fixup!`/`squash!`
commits pass untouched, and the `#` comments and diff that `git commit -v` puts in the file are
not mistaken for a body.

```
test: cover the CLI, yaml_io and the predicate model          ✓
fix(yaml_io): tag AST nodes under node so InList reads back   ✓
added stuff                                                   ✗  the header must read `type(scope): what and why`
wip: something                                                ✗  type 'wip' is not one of: feat, fix, …
feat: Adds a thing.                                           ✗  the subject starts lower case / no full stop
feat: x  +  Co-authored-by: …                                 ✗  commits carry no trailers
```

Check a range yourself with `python tools/commit_msg.py --range origin/dev..HEAD` — that is
exactly what CI runs over a pull request, since a local hook can be skipped.

## What CI does

`.github/workflows/ci.yml`, five jobs. Installs go through `uv`:

1. **commits** — `tools/commit_msg.py --range` over the pull request's commits.
2. **lint** — `ruff check`, at the version pinned in the `dev` extra.
3. **test** — the unit suite on Python 3.11, 3.12 and 3.13, with the coverage floor.
4. **e2e** — installs the package (not editable) and runs the `e2e`-marked tests, so the
   console script and the packaged data files (`grammar.lark`, the GCP catalogs) are exercised
   the way a user meets them.
5. **package** — `uv build`, `twine check`, then installs the wheel into a fresh virtualenv and
   parses a rule with it.

## Writing a change

The conventions in `AGENTS.md` §8 hold. In particular:

- **No new runtime dependencies.** `lark`, `pyyaml`, `z3-solver`, `rich`, `prompt_toolkit` — that
  is the list. Test and lint tooling lives in the `test` / `dev` extras and is never imported by
  the package.
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
