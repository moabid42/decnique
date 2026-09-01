# decnique — guide for coding agents and new contributors

If you are an AI assistant opening this repository for the first time: read this file top to
bottom, then `README.md`. It is enough to explain the project to a person in two minutes and
to make safe changes. Nothing here needs the private data directory to be understood.

## 1. What this project is (explain-it-to-me version)

A security team writes **detection rules** for a SIEM (Google SecOps/YARA-L, Elastic, Sigma,
Panther). An attacker in a Google Cloud account performs **actions** (API calls) that land in
the audit log. This tool answers, for one concrete account and one rule corpus:

- **blindspots** — *for a permission, is there ANY action using it that is reachable by some
  principal, actually logged, and observed by NO rule?* If yes, it shows a concrete example
  event, and lists **which kinds of change are watched and which are not** (and by which rule).
- **stealth** — *can THIS technique (a specific payload, e.g. "add roles/owner to myself") be
  carried out so that no rule fires?* Answers with a proof ("always detected") or a concrete
  evading schedule.
- **chains** — stealthy privilege-escalation paths built from stealthy techniques.
- **check** — the DSL's own `check` blocks: named questions (`coverage`, `candidate`, `compare`,
  `dead_rules`, `redundant_rules`, `boundary`, `require_coverage`, `attempt_coverage`,
  `public_access`) answered pass / fail / unknown.  `checks load` loads them from a file (or
  type one at the prompt); `ask check` runs them.

The core idea: translate every rule into one shared language (the DSL), abstract each string
field to the finite set of tests the rules make on it (**atoms**), and ask a propositional
solver for an unobserved event. Every answer is **three-valued** (yes / no / don't-know) and
every symbolic witness is **replayed through a concrete oracle** before it is believed.

Formal question (single event): `∃ e : Reach_p(e) ∧ Log(e) ∧ ¬(⋁_R Observes(R, e))`.

## 2. Glossary

| term | meaning |
|---|---|
| **detection** | a rule; single-event or correlation (windows, counts, joins) |
| **candidate / technique** | what an attacker needs (`required` permissions), the trace it leaves (`footprint` steps, optionally with a `where` payload), and optionally what it `gains` (permissions added on success — how `ask chains` advances) |
| **Reach / Log / Observes** | account grants it / the method is audit-logged / rule R fires on event e |
| **unknown(...)** | an atom a front-end could not translate; anything touching it is **approximate** |
| **approximate vs exact** | a verdict is exact only if no `unknown` and no unverified assumption was involved |
| **atom** | one atomic test on a string field, `(field, kind, literal, nocase)`; rules become Boolean formulas over atoms |
| **check** | a DSL block `check NAME { type T … }` — one question about the loaded rules, answered pass / fail / unknown (`decnique/checks.py`) |
| **witness** | a concrete event the solver proposed and the oracle confirmed unobserved |
| **realize** | turn a solver model (atom assignment) back into a concrete string/event |
| **catalog** | facts about audit-log methods: permissions, service, product_name, event_type, required fields, whether the name is verified |
| **udm** | Google SecOps Unified Data Model field paths (`udm:target.resource.attribute.labels[...]`) |

## 3. Layout

```
decnique/
  dsl/          grammar.lark, parser, ast, format (round-trip), interpret (3-valued oracle), loader
  model/        event_fields (closed vocabulary), predicates (Pred tree, Unknown), trace (TraceSpec)
  frontends/    secops/ sigma elastic panther  -> DSL; untranslatable parts become unknown(...)
  env/          catalog (method facts; catalog.gcp() from the iam-dataset), model (Account:
                Reach/Log, grant-indexed), ingest (account.json), gcp_import (raw gcloud exports)
  eval/         trace_eval: fires(), matches_footprint()  <- THE ORACLE, arbiter of truth
  smt/          atoms (abstraction + realizer), coverage (blindspots engine; incremental atom
                consistency), encode_*/stealth (M3), answers.py at repo top = engine-level JSON,
                bucket (optional grouping), legacy_coverage (old engine, differential test only)
  graph/        chains: search over stealthy techniques
  checks.py     runs `check` blocks (one engine per check type, three-valued, replayed)
  ui/           commands (the object/verb table: single source for dispatch, help, completion),
                repl (prompt, help pages, batch/CI main), render (verbs), browse (catalog),
                session, config, report (saved runs: md/json/yaml), words (opt-in wording)
  catalogs/     UDM field map; gcp_methods/gcp_roles (built by catalogs/build_gcp.py), gcp_tags
answers.py      engine-level JSON (blindspots/stealth/chains) for the argparse CLI
examples/       account.json, candidates.decn
tests/          pytest; synthetic suites + corpus tests (skipped when the corpus is absent)
run.py          launcher for the interactive shell / one-shot commands
```

## 4. Running

```bash
python -m venv .venv && .venv/bin/pip install -e .[test]
.venv/bin/python -m pytest -q tests                      # ~10 s, must stay green
python3 run.py                                           # shell
python3 run.py ask blindspots resourcemanager.projects.setIamPolicy
```
Every shell command reads **`<object> <verb> [args…]`**.  The objects are the things the
session holds; their verbs only load or look at state.  The math lives under one object, `ask`.

| object | verbs |
|---|---|
| `rules` | `load [--all] [--deprecated] <paths…>` · `list [~][substr]` · `inspect <id>` · `dsl <id>` · `admits <method>` · `summary` |
| `candidates` | `load <paths…>` · `list` · `inspect <id>` · `dsl <id>` · `footprint [id]` |
| `checks` | `load <paths…>` · `list` · `inspect <id>` · `dsl <id>` (loading never runs a check) |
| `events` | `load <file.json>` · `list` · `inspect <n>` · `trace [all]` · `observe <file.json>` |
| `account` | `load <json \| raw gcloud export> [resource]` · `show` · `who [perm \| principal]` |
| `catalog` | `perms [filter]` · `methods <perm \| method>` · `roles [role \| --with perm]` |
| `ask` | `blindspots [perm…]` · `stealth [id]` · `chains [goal] [--from p] [--start p1,p2]` · `check [id…]` · `suggest <perm…> [define]` |
| `reports` | `list` · `show <file>` · `diff <a> <b>` · `export <file.json> [n]` |

Shell words: `config [key [value|reset]]`, `help [object [verb]]`, `clear`, `quit`.  An object
typed alone runs its default verb (`rules` = `rules list`, `account` = `account show`); `ask`
has no default, so the solver never runs by accident.  `inspect` shows an item with everything
around it (source file, untranslated parts, question, steps); `dsl` prints only the canonical
DSL as plain text, for copying into a `.decn` file.

`help <object> <verb>` explains one verb: its arguments, what every word on screen means, and
its settings.  With `config report.save on`, every `ask` run is written to `report.dir` as
Markdown (default; the data is embedded as JSON at the end), JSON, or YAML (`report.format`);
`reports list` lists them, `reports show <file>` reopens one, and `reports diff <a> <b>` shows
what changed between two runs.  `reports export <file.json>` writes the last run's witnesses as
Cloud Audit Log entries to replay in a SIEM; `ask suggest <perm> [define]` proposes DSL
detections that would close a blind spot.  The `catalog` verbs (`ui/browse.py`) look things up
without leaving the shell: `perms` (by service, then by name; `--tag`, `--reachable`,
`--unwatched`), `methods` (a permission's methods, or one method's fact card), `roles` (a role's
permissions, or the roles granting one); `account who` says who holds a permission and where.
Every listing is capped (`--limit N`, `--all`).

**Batch / CI mode.** `python3 run.py --rules DIR… --account a.json [--json] [--report DIR]
[--fail-on finding|unknown] [-f script] <object> <verb> …` runs one command (or a script of them) and
exits: 0 clean · 2 a finding (gap / evasive / stealthy / failed check) · 3 input error · 4
inconclusive (with `--fail-on unknown`).  In the interactive shell an error in a verb is reported
and the session survives (`DECNIQUE_DEBUG=1` re-raises).

**The account.** `account load` takes the tool's own JSON *or* a raw export, converted on load:
`gcloud projects get-iam-policy P --format=json` (bindings + Data Access `auditConfigs`) with a
`resource` scope, or `gcloud asset search-all-iam-policies --format=json` (grants scoped per
resource), or **Terraform** (`env/terraform_import.py`): `terraform show -json` of state or a
plan (vars/modules/`for_each` resolved) or a native `*.tf.json` config.  Terraform IAM resources
map by suffix — `google_*_iam_member`/`_binding`/`_policy` → grants scoped to their resource,
`google_*_iam_custom_role` → the role catalog, `google_*_iam_audit_config` → Data Access logging;
data sources are ignored and unresolved `${…}` values are kept and noted approximate.  Terraform
describes only the *account*, not detections (a `google_chronicle_rule` just wraps YARA-L the
`secops` front-end already reads), so rules keep loading through `rules load`.  Predefined roles
expand from the bundled catalog; conditional bindings are kept and listed as notes.  The method↔permission catalog is `Catalog.gcp()` — the whole GCP surface from
the iam-dataset (generated method names are *unverified* until a loaded rule attests them); it
falls back to the small hand-checked seed when the data files are absent.

The prompt also accepts DSL directly, like a Python interpreter: a line starting with
`detection`, `candidate`, `check`, or `ruleset` and containing `{` opens a block that is read
until its braces close, then parsed and merged into the loaded library (same id = replaced).
So `detection d { … }` → `candidate c { … }` → `check q { type candidate for c }` → `ask check q`
is a complete session without any file.  `examples/checks.decn` shows every implemented type.

Rule corpora are **not** in the repo. Point `rules load` at directories of native rules (YARA-L
`.yaral`, Elastic `.toml`, Sigma `.yml`, Panther `.yml`+`.py`). The loader keeps GCP-relevant
rules by default; `--all` loads every platform (only useful for scale tests).

New in this iteration (all replay-verified, tests in `tests/`): a Python-AST evaluator for
Panther `rule()` bodies (`frontends/panther_py.py` — control flow, reads, loops, helpers, the
`event.udm` data model) instead of regex-scraping; an `unknown("…")` **condition** atom so a
partly-translated correlation condition stays don't-know; the SIEM glob language (no `[]`
classes, escaped wildcards) in `interpret.glob_match`; chain paths replayed whole (a correlation
rule across hops is caught); stealth reports the rules that always catch a technique.

## 5. Invariants — do not break

1. **Honesty.** Never turn "cannot translate" into `true` or `false`. It becomes `unknown(...)`
   and the result is flagged approximate. (Silently lowering to `true` once made 13 rules
   "cover" every event.)
2. **Soundness by replay.** The solver proposes; `eval.fires` + `Account.reach/logged` decide.
   A returned witness has been replayed. UNSAT counts as a proof only when no unproven block
   occurred (otherwise the verdict is `exhausted`).
3. **Realism comes from the catalog.** Per method it pins `service`, `product_name`,
   `event_type`, forces `required_fields` present (values free), and marks unverified method
   names; an unverified name can never be the reason a gap exists.
4. **Witness shape.** `udm:`/`tags.` values live under `event["udm"]` / `event["tags"]` — that
   is where the oracle reads them.
5. **DSL round-trip:** `parse(format(x)) == x`.

## 6. How to extend (recipes)

- **New front-end idiom** → `decnique/frontends/<x>.py`; add a test in `tests/`; keep anything
  you cannot express as `unknown("<frontend>:<label>")`.
- **Regenerate the GCP catalog** → `python -m decnique.catalogs.build_gcp <iam-dataset>/gcp`
  writes `catalogs/gcp_methods.json.gz` / `gcp_roles.json.gz` / `gcp_tags.json` (data, not code).
- **New method / realism fact (seed)** → `decnique/env/catalog.py` (`_SEED`, `METHOD_EVENT_TYPE`,
  `POLICY_DELTA_FIELDS`, `EXAMPLE_VALUES`, `verified=`). Data, not code.
- **New setting** → one `Setting(...)` in `decnique/ui/config.py` `REGISTRY`; read it via
  `session.settings.get(key)`.
- **New check type** → one `_<type>` function in `decnique/checks.py`, dispatched from
  `run_check`, added to `IMPLEMENTED`, and a question line in `ui/render.py` `_CHECK_QUESTION`.
  Every type is implemented; the one option without an engine, `mode fires_bg` (against a
  background trace), answers `unknown` — never guess.
- **New shell verb** → one `Verb(...)` in the right `Obj` in `ui/commands.py` (name, hint,
  one-line help, `run`, `detail` page, `paths=` for path completion; a test checks every verb
  has a detail page), implemented in `ui/render.py` or `ui/browse.py`.  Anything that runs the
  solver goes under `ASK`; loading / listing / inspecting goes under the object it belongs to.
  A verb that computes something wraps its body in `with s.report(verb, args) as rep:` and
  calls `rep.add(label, verdict, detail, …)` per finding, so it can be saved and reopened.
- **Engine change in `smt/`** → keep `tests/test_coverage_differential.py` green (old vs new
  engine agree) and the soundness tests in `tests/test_smt_coverage.py`.

## 7. Traps that already cost time

- `ask blindspots` and `ask stealth` ask different questions and can both be right: a permission can
  have unwatched *kinds* of change while the specific attack payload is caught.
- The simplest unobserved event is often boring (e.g. a role *removal*). Use the per-change
  list or `config blindspots.explain formula` before concluding a rule is missing.
- Roughly half of the Panther GCP rules yield no method predicate (their logic is Python).
  Each is a place where a real detection hides behind `unknown`. Data-model "standard" rules
  are translated exactly; add more idioms to `frontends/panther.py` as you meet them.
- Real audit-log method for project IAM changes is `SetIamPolicy` (v1). The binding deltas
  (`action`/`role`/`member`) can be stripped in exported logs — a delta-less event is a real,
  rare blind spot, not a modelling error.
- A check that narrows `rules [...]` can get an odd-looking witness (a binding-delta label on
  a key-creation event): nothing ties free fields to a method, so scope the check with
  `permission` too. `allowed` needs its fields present — add `or <field> missing` when a
  field-less event should also be allowed.
- Plain-English wording (`config blindspots.explain words`) is a **hard-coded** IAM-only table
  (`ui/words.py`); the default modes derive their vocabulary from the rules themselves.

## 8. Conventions

- Commits: one line, `type(scope): what and why`; atomic; no trailers.
- No new dependencies (lark, pyyaml, z3-solver, rich, prompt_toolkit).
- Tests for every behaviour change; corpus-dependent tests must skip cleanly without the corpus.
- UI text says the *question* a verb answers, in plain words.
