# Development guide

This guide is for contributors extending decnique without weakening its result guarantees.

## Set up a development environment

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
pre-commit install
```

The hooks install for commit, commit-message, and push stages. The project targets Python 3.11+
and adds no runtime dependencies beyond Lark, PyYAML, Z3, Rich, and prompt-toolkit.

## Fast and full validation

```bash
ruff check .
pytest -m "not e2e"
pytest -m e2e
pytest
```

CI also runs the unit suite on Python 3.11, 3.12, and 3.13 with branch coverage and the configured
80% floor, runs e2e tests against an installed package, builds/checks distributions, installs the
wheel in a clean environment, and validates commit messages.

The push hook runs `tools/run_tests.sh`. It hides any local rule corpus during the coverage-gated
unit run so local results match CI, then runs optional corpus tests separately when available.

Tests always switch to the repository root and point `DECNIQUE_CONFIG` at a temporary file. They do
not read or overwrite personal shell settings.

Markers:

- `e2e`: launches `run.py` or the installed console command in a subprocess.
- `corpus`: requires IAMouflage or `DECNIQUE_CORPUS`; otherwise skips cleanly.

## Commit convention

Every commit is atomic and has one line:

```text
type(scope): lower-case description of what and why
```

Allowed types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`, and
`revert`. Headers are at most 100 characters, have no final full stop, and carry no trailers such
as `Co-authored-by:` or `Signed-off-by:`. `tools/commit_msg.py` is the executable specification.

## Start from the invariant, not the module

Before changing an engine or translator, identify which invariant the change touches:

1. Unsupported semantics remain unknown.
2. Symbolic witnesses are accepted only after concrete replay.
3. Method/account realism comes from explicit catalog facts.
4. `udm:` and `tags.` values have their required nested witness shape.
5. DSL formatting round-trips to the same AST.

Tests should name the product failure they prevent. A useful test docstring says, for example,
“a negated method test must not claim the exact opposite set of methods,” not merely “tests parser.”

## Add a native frontend idiom

1. Locate the frontend under `decnique/frontends/`.
2. Lower the construct into existing predicate/trace nodes when its semantics fit exactly.
3. Otherwise emit an `Unknown` or `CUnknown` with a stable, specific label and relevant fields.
4. Add the label to provenance `unsupported` so `rules inspect` explains it.
5. Add a focused test in the corresponding `tests/test_frontend_*.py` file.
6. Test both positive and negative cases through the concrete interpreter.

Never scrape a literal from a negated native test as though it were the positive firing set. Never
drop an unknown conjunct from a condition; that broadens a rule and can create a false proof.

Frontend entry points return a `Bundle` and convert parse/read failures into `LoadIssue` data so a
directory load continues.

## Add an event-model field

1. Add a `FieldSpec` in `decnique/model/event_fields.py` with sort, presence bit, repeat status,
   and source documentation.
2. Update raw event projection/export in `decnique/detections.py` if the field has a standard Cloud
   Audit Log location.
3. Update frontend field maps or the SecOps UDM map as appropriate.
4. Confirm `SymEvent` chooses the intended symbolic sort.
5. Add concrete evaluation, encode/decode, witness-shape, and round-trip tests.

Prefer `udm("...")` for vendor-specific fields that do not justify extending the closed vocabulary.

## Add or regenerate catalog data

For a hand-checked method fact, extend `_SEED` and, when justified, `SERVICE_PRODUCT`,
`METHOD_EVENT_TYPE`, `POLICY_DELTA_FIELDS`, or `EXAMPLE_VALUES` in `decnique/env/catalog.py`.

For the generated GCP surface:

```bash
python -m decnique.catalogs.build_gcp /path/to/iam-dataset/gcp
```

This writes compressed method/role catalogs and tag JSON. Generated method names must remain
unverified until explicit evidence attests them.

## Add an account importer shape

Importers normalize external data into schema version 1; `Account` should not need to know the
source format. Preserve unresolved or conditional meaning in `notes` and over-approximate Reach
only when the UI explicitly exposes that approximation. Add fixture and model-level tests for
scope, role expansion, logging, and denies.

For Terraform, stay within JSON state/plan or native JSON configuration. Adding ad hoc HCL parsing
would silently miss evaluated variables, modules, and `for_each` instances.

## Add a check type

1. Add the type to `CHECK_TYPES` in `decnique/dsl/ast.py`.
2. Add a `_type` engine in `decnique/checks.py` and dispatch it from `run_check`.
3. Add it to `IMPLEMENTED` only when it has an engine.
4. Add its question text to `_CHECK_QUESTION` in `decnique/ui/render.py`.
5. Add examples and tests for pass, fail, unknown, replay, and bad parameters.

Checks are defender-oriented: pass means the stated property holds. A missing engine or unsupported
mode must return unknown.

## Add a shell command

1. Add one `Verb` to the appropriate `Obj` in `decnique/ui/commands.py`.
2. Put solver-backed work under `ASK`; loading and browsing stay on their owned objects.
3. Implement rendering/behavior in `ui/render.py` or `ui/browse.py`.
4. Supply detailed help, an argument hint, path completion where applicable, and a settings prefix.
5. If it computes findings, wrap it in `with s.report(verb, args) as rep:` and call `rep.add` for
   structured findings.
6. Update tests. The suite verifies every verb has detailed help.

Because `OBJECTS` drives dispatch, help, and completion, do not add a parallel parser for a shell
verb.

## Add a setting

Add one `Setting` to `ui/config.py::REGISTRY`. Read it with `session.settings.get(key)`. Choices,
default, help, validation, display, and persistence all derive from the registry.

Batch flags should use `persist=False`; a CI invocation must not rewrite the user's configuration.

## Change the coverage engine

Keep these properties visible in code and tests:

- the library-wide `CoverageContext` is reusable across permissions;
- atom consistency clauses used for proof are logically valid;
- unproven blocked models force exhaustion rather than UNSAT proof;
- every returned event passes reach, logging, realization, and complete rule replay;
- approximate rules and unverified catalog names are surfaced;
- the legacy and atom engines agree in `tests/test_coverage_differential.py`.

Run at minimum:

```bash
pytest -q tests/test_smt_atoms.py tests/test_smt_coverage.py tests/test_coverage_differential.py
```

## Change stealth or chain analysis

For stealth, test feasibility, timing spread, distinct values, payload constraints, unlogged steps,
unknown footprint atoms, replay rejection, and UNSAT catching-rule cores.

For chains, test state transition guards/effects, shortest-path behavior, whole-path correlation
replay, patient-attacker delay, depth bounds, and approximate propagation.

```bash
pytest -q tests/test_smt_stealth.py tests/test_graph_search.py tests/test_ui_redteam.py
```

## Change the DSL

Update grammar, AST, parser, formatter, YAML/JSON representation, and tests as one contract. Add
positive syntax, semantic-error, canonical format, and serialization cases. Then run:

```bash
pytest -q tests/test_roundtrip.py tests/test_dsl_yaml_io.py tests/test_dsl_loader.py
```

The canonical invariant is structural equality after formatting and reparsing, not merely that both
texts happen to evaluate the same way.

## Change the UI or reports

The UI tests exercise object/verb registration, help, formatting, browse behavior, load merging,
checks, reporting, batch JSON, exit codes, and complete process workflows.

```bash
pytest -q tests/test_ui_objects.py tests/test_ui_verbs.py tests/test_ui_batch.py \
  tests/test_ui_report.py tests/e2e
```

Keep UI wording question-oriented: say what the command answers, distinguish observation from
firing, and expose exactness instead of hiding it behind visual styling.

## Debugging

Set `DECNIQUE_DEBUG=1` to make the interactive shell re-raise unexpected exceptions after printing
them. Without it, the shell reports the error and preserves session state.

Useful focused inspections:

```text
rules inspect ID
rules dsl ID
rules summary
events inspect N
events trace all
config blindspots.raw on
```

For a corpus-dependent failure, reproduce CI first by pointing `DECNIQUE_CORPUS` at a nonexistent
path, then run the corpus marker separately against the real corpus.

## Packaging constraints

`pyproject.toml` explicitly lists packages and package data. New Python packages must be added to
the setuptools package list. Grammar and catalog data need package-data entries. Validate with:

```bash
uv build
twine check dist/*
```

The installed-wheel e2e/package jobs are the authority for resources that happen to work only from
an editable checkout.
