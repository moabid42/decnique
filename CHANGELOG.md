# Changelog

All notable changes to decnique. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); entries are grouped by date, because the work
arrives that way. `v0.1.0` (2026-09-07) is the first tagged version and covers every entry below
it. `AGENTS.md` explains the concepts these changes touch.

## [Planned]

Coverage as a **measure**, not a yes/no — the next block of work (see the roadmap in
`README.md`). None of this touches the translation layer, so it can land alongside the
translation work below.

- **Holes as regions, not single witnesses.** After a gap is found, return the whole
  evading set over the technique's free variables (e.g. `window ∈ [600,899] ∧ method=PATCH`)
  instead of one example event. Projection + box subtraction in the small variable space.
- **Cost-weighted coverage measure.** Measure the safe region (volume for continuous axes,
  integer-point count for discrete ones), weighted by attacker cost, and report it as a
  number with an uncertainty band. Turns covered/not-covered into a quantity.
- **Escape distances / brittleness.** For an action a rule does catch, how small a change on
  each axis slips it out of every rule — flags fragile rules caught only by a hair.
- **Hole provenance tags.** Distinguish a hole caused by an under-specified candidate
  (`unknown` axis) from a genuine rule blind spot, so the report never calls the former a gap.
- **Reference lists as data.** Let the user load `%list` contents (watchlists, allow-lists)
  so `field in %list` becomes an exact membership test instead of `unknown`.
- **Evaluate IAM Conditions.** Parse and evaluate conditional bindings so `Reach` is exact
  instead of over-approximated.

## [2026-09-07] — tagged `v0.1.0`

### Added
- **The four front-ends are tested without the private rule corpus.** Every idiom below was
  previously exercised *only* by the vendored corpus, so on a clean checkout — CI, or a new
  contributor's machine — the translation layer ran nowhere and a front-end could stop reading a
  construct without a single test going red. One suite per front-end, each test naming what
  breaks in an *answer* when the translation is wrong (a rule that covers too much, a threshold
  that silently disappears, a GCP rule that never loads at all):
  `sigma` (modifiers, condition forms, the non-GCP filter) 320 lines → 99 %;
  `elastic` (the TOML rule types and the KQL subset) 264 → **100 %**;
  `panther` (the `.yml` rule file, thresholds, the literal scraper of last resort) 246 → 96 %;
  `panther_py` (the Python idioms the AST evaluator reads, one test per construct) 255 → 91 %;
  `secops` (what single-event lowering never reached: `match` windows, joins between two event
  variables, `outcome` aggregates and the `condition` atoms that read them) 343 → 84 / 87 %;
  and `dsl/loader` (file sniffing, the directory walk, rulesets) 209 → 94 %.
  396 → 677 tests; coverage **84 %** with the corpus hidden (86 % with it), against the 83 %
  the last entry measured *with* the corpus visible.
- **`corpus` pytest marker and `$DECNIQUE_CORPUS`.** The tests that need a native rule corpus
  are marked and skip cleanly without one; the environment variable says where it is, and
  pointing it at a path that does not exist reproduces CI exactly.

### Changed / Fixed
- **A negated Panther test claimed the exact opposite set of methods.** `method != "X"`,
  `method not in SET` and `not method.startswith(…)` name the methods a rule does **not** fire
  on; the scraper was reading those literals as the set it *does* fire on. `_same_statement`
  became `_receiver`, which returns the operand text *and* whether the test is negated, and
  `not ` is no longer cut out of the receiver — cutting there is what hid the negation. The
  method test now becomes `unknown("panther:negated_method_test")` instead of a wrong method
  set, and a negated *permission* test is dropped rather than claimed. This is honesty
  invariant #1 in the other direction: a definite "does not fire" is as dishonest as a
  definite "fires".
- **The push gate runs what CI runs, with the corpus hidden.** `tools/run_tests.sh` (was
  `run_fast_tests.sh`) is now four stages — ruff, the unit suite with the coverage floor and
  `$DECNIQUE_CORPUS` pointing nowhere, the `e2e` suite, then the corpus tests if this machine
  has a corpus. The corpus is what exercises the front-ends, so with it visible the floor passed
  locally and failed in CI; that is how a red run got pushed in the first place. The coverage
  floor itself moved into `pyproject.toml`, so the hook and the CI job cannot disagree about the
  number.
- **The file-fixing hooks no longer run at push time.** `trailing-whitespace`,
  `end-of-file-fixer` and `check-added-large-files` declare `pre-push` in their own manifest,
  which `default_stages` does not override — they were rewriting files in the middle of a
  `git push`.
- **The git hooks are required now, and both gates check that they are.** `pre-commit install`
  sets up all three hook types at once; installing one by hand does not — this repository had
  only a hand-written `pre-push`, so the commit convention was first checked in CI, minutes
  after a push. `tools/run_tests.sh` grew a gate in front of the others that refuses to run
  unless the `pre-commit` and `commit-msg` hooks are installed, and names the one command that
  fixes it; the CI `lint` job runs every hook over every file, which is what holds the line for
  a clone where nobody installed them.
- `uv.lock` is git-ignored.

## [2026-09-06]

### Added
- **CI pipeline** (`.github/workflows/ci.yml`), five gates, installing through `uv`: the commit
  convention over a pull request's commits; `ruff check` at the version pinned in the `dev` extra;
  the unit suite on Python 3.11 / 3.12 / 3.13 with an 80 % coverage floor;
  the `e2e` tests against an *installed* package (so the console script and the packaged
  `grammar.lark` / GCP catalogs are exercised); and a packaging job that builds the sdist + wheel,
  runs `twine check`, and parses a rule with the wheel in a clean virtualenv. Plus
  `dependabot.yml` (actions only) and a PR template.
- **Git hooks** (`.pre-commit-config.yaml`, installed with `pre-commit install`): `pre-commit`
  lints the staged files with `ruff --fix` and checks whitespace / YAML / TOML / JSON,
  `commit-msg` checks the message, `pre-push` runs the fast test suite.
- **`tools/commit_msg.py`**: `AGENTS.md` §8 as a program — the type list this repository uses, a
  lower-case subject with no full stop, one line, and no `Co-authored-by:`-style trailers. Merges,
  reverts and `fixup!` commits pass untouched, and the comments and diff `git commit -v` writes
  into the message file are not mistaken for a body. Standard library only, covered by
  `tests/test_commit_msg.py`, and the `commit-msg` hook and CI run the same script so they cannot
  disagree.
- **End-to-end tests** (`tests/e2e/`, 28): the two entry points run as real processes — argv,
  stdout/stderr, and the batch exit codes (0 clean · 2 finding · 3 input error · 4 inconclusive);
  and the whole pipeline from four SIEM formats on disk (YARA-L, Sigma, Elastic, Panther) plus a
  native `.decn`, through the front-ends into one library, to `blindspots` / `stealth` / `check`
  against an account. A reported gap's witness is replayed through the oracle *across the process
  boundary*, and rules exported with `import` are loaded back and compared.
- **Unit tests** for the parts that had none: `cli.py` (0 → 98 %), `dsl/yaml_io.py` (0 → 99 %),
  `answers.py` (60 → 100 %), `model/predicates.py` (71 → 100 %), `model/trace.py` (52 → 98 %),
  `ui/format.py` (29 → 100 %), and the Terraform importer's untaken branches. Overall 79 → 83 %
  with branch coverage on; 204 → 396 tests.
- **Property test for the NNF normaliser** (hypothesis): `normalize` may never change what a
  predicate *means*, checked against the interpreter in three-valued logic; it may never turn a
  don't-know into an answer; it is idempotent; and it leaves no negation above a connective. The
  encoders assume NNF, so a De Morgan slip there would make the solver answer a different question
  from the oracle. (Note that an `unknown` a constant absorbs — `unknown(…) and false` — *is*
  soundly dropped, so "every `Unknown` node survives" would be the wrong thing to assert.)
- **`tests/conftest.py`**: every test runs from the repository root, against a temporary
  `$DECNIQUE_CONFIG`, and with `GIT_*` cleared from the environment — so the suite is
  start-directory independent, cannot read or overwrite a developer's own shell settings, and
  cannot act on the repository it is running in. (That last one is not hypothetical: a git hook
  exports `GIT_DIR`, which overrides `cwd`, and the first `pre-push` run committed a test's
  throwaway fixture into the branch.) `run_cli` runs an entry point in a subprocess.
- **`CONTRIBUTING.md`**, a `dev` extra (ruff pinned / pre-commit / build / twine), ruff and
  coverage configuration in `pyproject.toml`, and the `e2e` / `corpus` pytest markers.

### Changed / Fixed
- **`yaml_io` could write an `InList` predicate but never read it back.** The node-type tag was
  stored under `kind`, and `InList` has a field of the same name (`string` / `regex` / `cidr`)
  that overwrote it, so `field in %list` failed to deserialise with `KeyError: 'regex'`. The tag
  moved to `node`; `kind` is still accepted when reading, so documents written earlier still load.
  Found by the round-trip test above.
- **Dead code removed** in `eval/trace_eval.py` (`_within_filter`'s unused `best` / `keep`) and
  `smt/encode_trace.py` (an unused step index); `zip()` calls are now explicit about `strict=`.
- `frontends/elastic.py`: a docstring with `\*` in it is now a raw string (it raised a
  `SyntaxWarning` on every import).
- `pyproject.toml` declares `readme`, so the built distributions carry a long description.

## [2026-09-01]

### Added
- **Terraform account import** (`env/terraform_import.py`): load an account from
  `terraform show -json` (state or plan, with vars/modules/`for_each` resolved) or a native
  `*.tf.json`. IAM resources map by suffix (`_iam_member`/`_binding`/`_policy` → grants,
  `_iam_custom_role` → role catalog, `_iam_audit_config` → Data Access logging); unresolved
  `${…}` values are kept and flagged approximate.
- **Loader de-duplication**: duplicate rules, candidates, checks, and events collapse on load.

### Changed / Fixed
- **Parser regex spans**: string scanning (comment stripping, section-header finding,
  rule-brace matching) now skips `/regex/` literals as a unit, so quotes, colons, and braces
  *inside* a regex no longer desync the scanners — fixed `//` comments leaking into `events:`,
  the `outcome:` header being swallowed, and the closing `}` leaking into `condition:`.
- **Examples restructured** into `examples/{rules,candidates,checks,events,accounts}/`; example
  paths and docs updated to match.

## [2026-08-31]

### Changed
- **`inspect`** now shows what was *read* from a rule (meta, methods, fields tested, and what
  did not translate) rather than re-dumping the DSL that `dsl` already prints; long meta no
  longer bleeds into the table.
- Further SecOps parser robustness fixes.

## [2026-08-30]

### Added
- **Object–verb shell.** Every command reads `<object> <verb> [args…]`:
  `rules`/`candidates`/`checks`/`events`/`account`/`catalog`/`reports` each get
  `load`/`list`/`inspect`/`dsl`; the solver questions live under `ask`
  (`blindspots`/`stealth`/`chains`/`check`/`suggest`).
- **Catalog browsing verbs** (`perms`/`roles`/`who`) and a per-method fact card, with capped
  listings, so the catalog is searchable without leaving the shell.
- **Batch / CI mode**: `run.py --rules … --account … [--json] [--report DIR]
  [--fail-on finding|unknown] [-f script] <object> <verb>`, exit codes 0/2/3/4; an error in a
  verb is reported and the interactive session survives.
- **Panther Python-AST evaluator**: `rule()` bodies are evaluated symbolically over the Python
  AST (control flow, reads, loops, helpers, the data model) instead of regex-scraping —
  50 of 102 corpus rules exact, up from 1.
- **`gains` clause for chains**: techniques advance via `candidate gains { … }`; `ask chains`
  derives the start principal/state from the account and takes `--from`/`--start`/`--goal`,
  shows a timed schedule, and exports.
- **`export`** writes the last run's witnesses as Cloud Audit Log JSON; **`suggest`** proposes
  DSL detections that close a blind spot (`define` adds them); **`reports diff`** compares two
  saved runs.
- **Raw gcloud account imports** (`get-iam-policy` with `auditConfigs`,
  `asset search-all-iam-policies`) converted on load, with notes for what is not modelled.
- **GCP catalog from the iam-dataset** (~10k methods, 4.4k permissions, 2.4k roles); generated
  method names stay unverified until a loaded rule attests them; account files expand
  predefined roles; a scoped grant is reachable on some resource.
- Seven commented example accounts (reach, logging, scoping, deny, escalation); medium and
  advanced technique libraries with a replayable event trace; audit-log timestamps parsed into
  the event time field.

### Changed / Fixed
- `stealth`/`check` name the rules that always catch a technique (from the UNSAT core).
- `blindspots`/`stealth` say which constructs made rules answer don't-know; `rules ~` lists
  only the approximate rules; `show <id>` prints the source file and line.
- `load` is additive (loading candidates no longer drops rules); a candidate-only library
  counts as loaded.
- Witness realism: a scoped principal's witness is pinned to a reachable resource, so rules
  that test the resource no longer exhaust the search.
- SIEM wildcard semantics for `like` (no character classes, escaped wildcards honoured); DSL
  strings keep regex escapes; Elastic derived ECS fields are `unknown` instead of free;
  untranslatable condition parts / same-event placeholder equalities / negated Panther method
  tests become `unknown` instead of silently broadening the rule.
- `report.py` renamed to `answers.py` (name collided with `ui/report.py`).

### Performance
- Grants indexed per principal (exact permission → resources + glob grants) so `Reach` is a
  dict lookup, not a scan — matters for owner-level accounts with thousands of grants.
- Incremental `=`-group exclusion, cached `determine()`, literal-method memo, cached glob
  regexes: whole-account `blindspots` ~2.5× faster.
- `blind_region` checks cubes under assumptions instead of rebuilding `Not()` per query
  (4.8 s → 0.7 s per gap).

## [2026-08-29]

### Added
- **Saved reports**: `config report.save/format/dir`; `blindspots`/`stealth`/`chains`/`check`
  collect findings + transcript and write Markdown (data embedded), JSON, or YAML;
  `reports list`/`reports show` browse and reopen them.
- **Per-verb help**: `help <verb>` / `config <verb>` explain one verb — its arguments, what
  each on-screen word means, and its settings (kept in sync with the command table by a test).
- **New check types**: `boundary` (event/allowed, mode `observed`|`fires_single`),
  `require_coverage`, `attempt_coverage` (a technique step, granted or denied), and
  `public_access` (`allUsers` grants on their own resources); `fires_bg` stays `unknown`.
- `find_gap` takes principals / granted / resource overrides (anonymous actors, denied
  attempts, resource-scoped grants).

### Fixed
- `chains` replays the whole path as one trace and waits out rule windows between hops, so a
  correlation rule across hops is no longer bypassed silently.
- `stealth` skips rules that fire on the empty trace, reports UNSAT after a don't-know block as
  `exhausted`, and hides unlogged steps from rules (listed as a logging gap).
- `blindspots` counts an exhausted search as inconclusive, not covered.
- A SecOps rule with no recognised event variable lowers to `unknown` instead of `true`;
  section headers may share a line with their content.
- Sigma/Elastic rules allow zero values, so a "field is missing" branch can fire.

## [2026-08-28]

### Added
- **Finite atom abstraction** replaces the z3 string-theory coverage solve (rules encoded once
  per library; propositional + bitvector/int only; CEGAR-learned atom consistency;
  MaxSAT-minimal witnesses) — `setIamPolicy` from >15 min to ~50 ms, 7k-rule probes to ~1 s.
- **`check` blocks**: `coverage`, `candidate`, `compare`, `dead_rules`, `redundant_rules`
  answered three-valued with replayed witnesses; unimplemented types answer `unknown`.
- **Interpreter-style DSL input**: type `detection`/`candidate`/`check` blocks at the prompt
  (read until braces close, same id replaces); `check`/`checks`/`show` run/list/print them.
- **Solver-derived coverage explanations**: rules that cover a change come from the UNSAT core;
  dodged conditions from leaf-level replay; `blind_region()` gives the whole blind set as
  proven prime implicants over the rules' own tests.
- **Blind region per kind of change** (`probe_atoms`: each atomic test and action-anchored
  combinations); seeded regex realization; an unverified method name can't be the reason a gap
  exists.
- `config` command with a persisted settings registry; `clear` command; plain-English wording
  (`config blindspots.explain=words`, GCP-IAM-only, isolated in `ui/words.py`);
  `--all`/`--deprecated` flags on the REPL `load`.
- `AGENTS.md` — the shared contributor/agent guide.

### Fixed
- Panther data-model standard rules translate exactly (e.g. `AdminRoleAssigned` = `SetIamPolicy`
  ADD of `roles/owner` or `roles/*Admin`), so a human granting themselves Owner is proven
  detected instead of `unknown`; a string test is a method test only when its receiver names
  the method; bare CamelCase v1 method names kept; `"X" in methodName` → `method contains`.
- Realistic witnesses: a policy-change witness carries its change list, prefers verified method
  names, and a gap reached only via an unverified method is flagged approximate.
- Method→field invariants pinned (`service`, `product_name`, `event_type`, binding-delta
  labels required present) so `blindspots`/`stealth` stop fabricating unrealistic witnesses.
- Elastic dataset/module fields imply the GCP audit dataset only when the value names GCP;
  a rule with no matched events and no count condition no longer fires on the empty trace
  (which had made three SAP rules "cover" every event).
- `define` no longer drops loaded candidates (test identity, not truth, of a 0-detection lib).

## [2026-08-27]

### Added
- **Foundation (M0–M5).**
  - M0: three-valued multi-event trace + footprint evaluator; `trace` subcommand.
  - M1: account model with `Reach`, `Log`, and the method↔permission catalog.
  - M2: symbolic single-event coverage with replay-verified gaps.
  - M3: symbolic stealth with exact rate-rule evasion and replay.
  - M4: stealthy privilege-escalation chain search over states.
  - M5: permission-signature bucketing with an equivalence guarantee.
- Top-level `blindspots`/`stealth`/`chains` reporting; coverage engine wired into `run.py`.
- **Interactive shell** with rich rendering, completion, a bottom input box + live status line,
  and a narrated reasoning log that replays the coverage math live; listing verbs and
  detections/candidates rendered as tables.
- Real-corpus soundness integration test; M0 trace/footprint/oracle-equivalence/round-trip
  tests.

### Fixed
- Single-event-trigger correlation rules (`#v>=1`) folded into the coverage formula so
  `blindspots` proves a permission covered instead of exhausting the refinement bound.
- Case-folded field arguments (`strings.to_lower`/`to_upper` nested in `contains`/`regex`)
  translate to exact case-insensitive matches — 40 corpus rules from approximate to exact.
- Seeded solvers for reproducible witnesses and verdict-level bucket equivalence; model-completion
  defaults hidden from the witness digest.

### Changed
- Migrated the DSL implementation and the language into this repository (initial import).
