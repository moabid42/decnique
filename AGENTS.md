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

The core idea: translate every rule into one shared language (the DSL), abstract each string
field to the finite set of tests the rules make on it (**atoms**), and ask a propositional
solver for an unobserved event. Every answer is **three-valued** (yes / no / don't-know) and
every symbolic witness is **replayed through a concrete oracle** before it is believed.

Formal question (single event): `∃ e : Reach_p(e) ∧ Log(e) ∧ ¬(⋁_R Observes(R, e))`.

## 2. Glossary

| term | meaning |
|---|---|
| **detection** | a rule; single-event or correlation (windows, counts, joins) |
| **candidate / technique** | what an attacker needs (`required` permissions) and the trace they leave (`footprint` steps, optionally with a `where` payload) |
| **Reach / Log / Observes** | account grants it / the method is audit-logged / rule R fires on event e |
| **unknown(...)** | an atom a front-end could not translate; anything touching it is **approximate** |
| **approximate vs exact** | a verdict is exact only if no `unknown` and no unverified assumption was involved |
| **atom** | one atomic test on a string field, `(field, kind, literal, nocase)`; rules become Boolean formulas over atoms |
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
  env/          catalog (method facts), model (Account: Reach/Log), ingest (account.json)
  eval/         trace_eval: fires(), matches_footprint()  <- THE ORACLE, arbiter of truth
  smt/          atoms (abstraction + realizer), coverage (blindspots engine), encode_*/stealth (M3),
                bucket (optional grouping), legacy_coverage (old engine, differential test only)
  graph/        chains: search over stealthy techniques
  ui/           repl (command table), render (verbs), session, config (settings), words (opt-in wording)
  catalogs/     UDM field map
examples/       account.json, candidates.decn
tests/          pytest; synthetic suites + corpus tests (skipped when the corpus is absent)
run.py          launcher for the interactive shell / one-shot commands
```

## 4. Running

```bash
python -m venv .venv && .venv/bin/pip install -e .[test]
.venv/bin/python -m pytest -q tests                      # ~10 s, must stay green
python3 run.py                                           # shell
python3 run.py blindspots resourcemanager.projects.setIamPolicy
```
In the shell: `load [--all] [--deprecated] <rule dirs…> <candidates.decn>`, `account <json>`,
`blindspots [perm…]`, `stealth [id]`, `chains`, `config`, `clear`, `help`.

Rule corpora are **not** in the repo. Point `load` at directories of native rules (YARA-L
`.yaral`, Elastic `.toml`, Sigma `.yml`, Panther `.yml`+`.py`). The loader keeps GCP-relevant
rules by default; `--all` loads every platform (only useful for scale tests).

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
- **New method / realism fact** → `decnique/env/catalog.py` (`_SEED`, `METHOD_EVENT_TYPE`,
  `POLICY_DELTA_FIELDS`, `EXAMPLE_VALUES`, `verified=`). Data, not code.
- **New setting** → one `Setting(...)` in `decnique/ui/config.py` `REGISTRY`; read it via
  `session.settings.get(key)`.
- **New shell verb** → add to `COMMANDS` in `ui/repl.py` (single source for help/completion),
  implement in `ui/render.py`.
- **Engine change in `smt/`** → keep `tests/test_coverage_differential.py` green (old vs new
  engine agree) and the soundness tests in `tests/test_smt_coverage.py`.

## 7. Traps that already cost time

- `blindspots` and `stealth` ask different questions and can both be right: a permission can
  have unwatched *kinds* of change while the specific attack payload is caught.
- The simplest unobserved event is often boring (e.g. a role *removal*). Use the per-change
  list or `config blindspots.explain formula` before concluding a rule is missing.
- Roughly half of the Panther GCP rules yield no method predicate (their logic is Python).
  Each is a place where a real detection hides behind `unknown`. Data-model "standard" rules
  are translated exactly; add more idioms to `frontends/panther.py` as you meet them.
- Real audit-log method for project IAM changes is `SetIamPolicy` (v1). The binding deltas
  (`action`/`role`/`member`) can be stripped in exported logs — a delta-less event is a real,
  rare blind spot, not a modelling error.
- Plain-English wording (`config blindspots.explain words`) is a **hard-coded** IAM-only table
  (`ui/words.py`); the default modes derive their vocabulary from the rules themselves.

## 8. Conventions

- Commits: one line, `type(scope): what and why`; atomic; no trailers.
- No new dependencies (lark, pyyaml, z3-solver, rich, prompt_toolkit).
- Tests for every behaviour change; corpus-dependent tests must skip cleanly without the corpus.
- UI text says the *question* a verb answers, in plain words.
