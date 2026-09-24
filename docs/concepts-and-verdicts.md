# Concepts and verdicts

decnique is useful only if its claims are read at the right level. This page defines that level.

## The three facts in a coverage question

For an event `e` and permission `p`, the blind-spot engine asks:

```text
Reach_p(e) and Log(e) and not ObservesAnyRule(e)
```

- **Reach** comes from the account model: a principal has the permission on the event's resource,
  after grant scope, hierarchy, wildcard permissions, and deny policies are applied.
- **Log** comes from the method catalog and account logging configuration. Admin Activity is on by
  default; Data Access is service-configured and may be disabled for named methods.
- **Observes** comes from the loaded detection library and the concrete rule evaluator.

A syntactically unobserved event is not a finding unless it is also reachable and logged.

## Detection, candidate, and check

A **detection** describes events that a SIEM rule observes. It can be a single event or a trace
pattern with variables, joins, grouping, timing, order, counts, and aggregates.

A **candidate** describes one attacker technique:

- `required`: permissions the same principal must hold;
- `footprint`: the event steps the technique leaves;
- `actor` and `context`: optional constraints shared by the technique;
- `share`: fields held equal across generated events;
- `gains`: permissions added to chain state after success.

A **check** is a named assertion over the loaded library and, usually, an account. Its defender-
oriented verdict is `pass`, `fail`, or `unknown`.

## Blindspots and stealth are deliberately different

`ask blindspots P` quantifies over **any catalogued action using permission P** and over fields not
fixed by the account/catalog. One unusual payload, change type, or method is enough to find a gap.

`ask stealth C` quantifies over **the footprint written in candidate C**. If the candidate says
“add `roles/owner` to a human user,” its `where` clause fixes that payload. A rule may always catch
this technique while a different use of the same permission remains a blind spot.

Use blindspots to audit a permission surface. Use stealth to test a threat hypothesis.

## Three-valued logic

Concrete predicate and trace evaluation returns:

| Value | Meaning |
|---|---|
| yes / `True` | the understood rule definitely matches or fires |
| no / `False` | the understood rule definitely does not match or fire |
| don't-know / `None` | an untranslated atom, missing reference list, unknown condition, or insufficient value prevents a definite result |

The Boolean connectives preserve uncertainty. For example, `false and unknown` is false, while
`true and unknown` remains unknown. This allows understood branches to decide a result without
pretending an unsupported branch has meaning.

Native frontends emit `unknown("frontend:reason")` when they cannot translate something. A rule
containing one is marked `~approximate`; `rules inspect <id>` shows the labels and source notes.

## Exact and approximate findings

An **exact witness** has been concretely replayed and no unknown rule could change the conclusion.

An **approximate witness** is still a concrete event that no understood rule definitely fires on,
but one or more rules returned don't-know, or the only available catalog method name was
unverified. It is a prioritized investigation lead, not proof that the real SIEM misses it.

Approximation is contagious only when relevant. A library may contain approximate rules while a
particular verdict remains exact because their understood predicates decide the result.

## Proofs, findings, and exhaustion

The main engines return these outcomes:

| Engine | Finding | Proof/clean | Inconclusive |
|---|---|---|---|
| blindspots | `gap` / **BLIND SPOT** | `all_covered` | `exhausted` |
| stealth | `evasive` | `always_detected` | `exhausted` |
| chains | `found: true` | `found: false`, reason `exhausted` over the modeled graph | `inconclusive: true`: `depth_bound`, `unknown_edge`, or `schedule_bound` |
| checks | `fail` | `pass` | `unknown` |

Other blind-spot non-findings are `unreachable` and `no_logged_method`. They are vacuous with
respect to rule coverage: the account cannot produce a qualifying logged event. An unlogged
technique step can make a candidate evasive, but the result explicitly calls it a logging gap,
not a rule gap.

`exhausted` in the SMT engines means the refinement bound was reached or an unproven model block
prevents a sound UNSAT claim. It does **not** mean covered.

## Why witnesses are replayed

The solver works over a compact abstraction. A proposed assignment may be inconsistent as a real
string, may violate the account scope, or may be caught by a rule feature outside the exact
symbolic subset. Therefore the solver proposes, but the concrete oracle decides:

1. Realize atom assignments as concrete field values.
2. Verify the account reaches the permission on the chosen resource.
3. Verify the selected method is logged.
4. Evaluate all relevant detections on the concrete event or trace.
5. Accept only a witness on which no rule definitely fires.

Inconsistent symbolic assignments are refined away. Only proven consistency clauses may support
an UNSAT coverage proof; unproven blocking turns the final outcome into `exhausted`.

## Realism supplied by the catalog

The method catalog ties permissions to possible audit-log method names and supplies invariants:

- method → service;
- method/service → UDM product name when known;
- IAM policy-change method → event type and required binding-delta fields;
- method → Admin Activity or Data Access logging class;
- realistic example values for witness realization.

Generated catalog method spellings are unverified until a seed fact or loaded rule attests them.
If verified spellings exist, blind-spot search uses only those. An unverified spelling is never
allowed to be the sole reason for claiming an exact gap.

## Observation versus firing

For a single event:

- a detection **observes** it when an event predicate accepts it;
- a single-event detection **fires** when that one event also satisfies its condition;
- a correlation detection can observe one event without firing until other events, timing, joins,
  or thresholds complete the trace.

This distinction appears in boundary-check modes and in `events observe`. For alert-level claims,
prefer firing semantics. For questions about whether a correlation rule is at least looking at a
class of events, observation semantics can be useful.

## Trust boundaries and known model limits

- Unsupported native syntax becomes unknown; it is never silently true or false.
- Reference-list tests remain unknown unless a caller supplies list contents through the library API.
- IAM Conditions and audit-log exempted members are preserved as notes but not evaluated.
- Terraform `*.tf.json` may contain unresolved interpolation; it is retained and noted. Resolved
  `terraform show -json` is the stronger input.
- Catalogued methods and field invariants model GCP Cloud Audit Logs; other clouds are not implemented.
- `boundary mode fires_bg` has no background-trace engine and therefore returns `unknown`.
- A witness is a model-backed test case, not evidence that an attacker already performed the action.

The design rule throughout the codebase is simple: uncertainty may reduce confidence, but it must
never be converted into an unjustified yes or no.
