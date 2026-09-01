"""The shell's command grammar: ``<object> <verb> [args…]``.

Every big thing the session holds is an *object* — ``rules``, ``candidates``, ``checks``,
``events``, ``account``, ``catalog``, ``reports`` — and each object has a few verbs
(``load``, ``list``, ``inspect``, ``dsl`` …) that only *look at* or *load* state.  The math
lives under one object, ``ask``: ``ask blindspots``, ``ask stealth``, ``ask chains``,
``ask check``, ``ask suggest``.  Loading a check is ``checks load``; running it is ``ask check``.

This module is the single source for dispatch, help, and completion: :data:`OBJECTS` is
walked by all three, so a verb added here is documented and completable at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import browse, render
from .session import Session
from .theme import console

Run = Callable[[Session, list[str]], None]


@dataclass(frozen=True)
class Verb:
    name: str
    hint: str            # argument hint, e.g. "<id>"
    help: str            # one line: what it answers
    run: Run
    detail: str = ""     # the `help <object> <verb>` page (plain words)
    paths: bool = False  # complete filesystem paths after the verb
    settings: str = ""   # settings prefix shown in help (e.g. "blindspots.")


@dataclass(frozen=True)
class Obj:
    name: str
    help: str
    verbs: dict[str, Verb] = field(default_factory=dict)
    default: str | None = None  # verb run when only the object is typed

    def verb(self, name: str) -> Verb | None:
        return self.verbs.get(name)


def _usage(text: str) -> None:
    console.print(f"[muted]usage:[/muted] {text}")


def _first(args: list[str]) -> str | None:
    return args[0] if args else None


# --- rules ---------------------------------------------------------------------------------


def _rules_load(s: Session, a: list[str]) -> None:
    s.load(a, want="detections")


def _rules_list(s: Session, a: list[str]) -> None:
    render.rules(s, _first(a))


def _rules_inspect(s: Session, a: list[str]) -> None:
    render.rule_inspect(s, _first(a))


def _rules_dsl(s: Session, a: list[str]) -> None:
    render.dsl(s, "detection", _first(a))


def _rules_admits(s: Session, a: list[str]) -> None:
    render.admits(s, _first(a))


def _rules_summary(s: Session, a: list[str]) -> None:
    render.summary(s)


RULES = Obj("rules", "the detections (translated to the DSL)", {
    "load": Verb("load", "[--all] [--deprecated] <paths…>", "load native rules or .decn files (additive)", _rules_load,
                 "rules load [--all] [--deprecated] <path…>\n"
                 "  paths: directories or files of native rules (.yaral, .toml, .yml) or DSL (.decn)\n"
                 "  --all         keep every platform (default keeps only GCP-relevant rules)\n"
                 "  --deprecated  also load rules under _deprecated/\n"
                 "  Loading is additive: a rule with the same id replaces the old one, the rest is kept.\n"
                 "  A .decn file may also carry candidates and checks; they are loaded too.", paths=True),
    "list": Verb("list", "[~][substr]", "list loaded detections (~ = only approximate ones)", _rules_list,
                 "rules list [~][substr]\n"
                 "  `~` in STATUS marks a rule with an untranslatable part (approximate).\n"
                 "  `rules list ~` shows only those — the rules a verdict can lean on as don't-know;\n"
                 "  `rules inspect <id>` says why."),
    "inspect": Verb("inspect", "<id>", "one detection: DSL, source file, what could not be translated", _rules_inspect,
                    "rules inspect <id>\n"
                    "  The canonical DSL, the original file and line, the rule's shape (type, events,\n"
                    "  window, condition) and every construct that became unknown(...) and why."),
    "dsl": Verb("dsl", "<id>", "only the canonical DSL, plain text (copy into a .decn)", _rules_dsl,
                "rules dsl <id>\n  Print the translated rule as plain DSL text, nothing else."),
    "admits": Verb("admits", "<method>", "which detections could involve a method (syntactic pre-filter)", _rules_admits,
                   "rules admits <method>\n  Which detections could involve an event with this method name."),
    "summary": Verb("summary", "", "corpus statistics", _rules_summary,
                    "rules summary\n  Rules per platform, approximate rules, candidates, checks."),
}, default="list")


# --- candidates ----------------------------------------------------------------------------


def _cands_load(s: Session, a: list[str]) -> None:
    s.load(a, want="candidates")


def _cands_list(s: Session, a: list[str]) -> None:
    render.candidates(s)


def _cands_inspect(s: Session, a: list[str]) -> None:
    render.candidate_inspect(s, _first(a))


def _cands_dsl(s: Session, a: list[str]) -> None:
    render.dsl(s, "candidate", _first(a))


def _cands_footprint(s: Session, a: list[str]) -> None:
    render.footprint(s, _first(a))


CANDIDATES = Obj("candidates", "the attacker techniques (required permissions + footprint)", {
    "load": Verb("load", "<paths…>", "load .decn files holding candidate blocks (additive)", _cands_load,
                 "candidates load <path…>\n"
                 "  .decn files (or directories) with `candidate { … }` blocks. Same loader as rules:\n"
                 "  detections and checks in the same file are loaded too.", paths=True),
    "list": Verb("list", "", "list loaded techniques and their footprints", _cands_list,
                 "candidates list\n  Every technique: the permissions it needs and the steps it leaves."),
    "inspect": Verb("inspect", "<id>", "one technique: DSL, required, steps, gains", _cands_inspect,
                    "candidates inspect <id>\n"
                    "  The DSL block, then one row per required permission, footprint step, order,\n"
                    "  span, and the `gains` clause (how `ask chains` advances)."),
    "dsl": Verb("dsl", "<id>", "only the canonical DSL, plain text", _cands_dsl,
                "candidates dsl <id>\n  Print the technique as plain DSL text, nothing else."),
    "footprint": Verb("footprint", "[id]", "does the loaded trace realize a technique's footprint?", _cands_footprint,
                      "candidates footprint [id]\n"
                      "  Match every technique's footprint (or one) against the loaded events (`events load`).\n"
                      "  Three-valued: yes / no / don't-know."),
}, default="list")


# --- checks --------------------------------------------------------------------------------


def _checks_load(s: Session, a: list[str]) -> None:
    s.load(a, want="checks")


def _checks_list(s: Session, a: list[str]) -> None:
    render.checks(s)


def _checks_inspect(s: Session, a: list[str]) -> None:
    render.check_inspect(s, _first(a))


def _checks_dsl(s: Session, a: list[str]) -> None:
    render.dsl(s, "check", _first(a))


CHECKS = Obj("checks", "the saved questions (`check` blocks); run them with `ask check`", {
    "load": Verb("load", "<paths…>", "load .decn files holding check blocks (additive)", _checks_load,
                 "checks load <path…>\n"
                 "  .decn files with `check NAME { type T … }` blocks. Loading never runs them:\n"
                 "  run with `ask check [id…]`.  You can also type a block at the prompt.", paths=True),
    "list": Verb("list", "", "list loaded check blocks and the question each asks", _checks_list,
                 "checks list\n  One row per check: type, options, and the question it asks in plain words."),
    "inspect": Verb("inspect", "<id>", "one check: DSL, question, options", _checks_inspect,
                    "checks inspect <id>\n  The DSL block, its type, the question it asks and its options."),
    "dsl": Verb("dsl", "<id>", "only the canonical DSL, plain text", _checks_dsl,
                "checks dsl <id>\n  Print the check as plain DSL text, nothing else."),
}, default="list")


# --- events --------------------------------------------------------------------------------


def _events_load(s: Session, a: list[str]) -> None:
    if not a:
        _usage("events load <file.json>")
        return
    s.events_load(a[0])


def _events_list(s: Session, a: list[str]) -> None:
    render.events_list(s)


def _events_inspect(s: Session, a: list[str]) -> None:
    render.event_inspect(s, _first(a))


def _events_trace(s: Session, a: list[str]) -> None:
    render.trace(s, show_all=bool(a) and a[0] == "all")


def _events_observe(s: Session, a: list[str]) -> None:
    render.event(s, _first(a))


EVENTS = Obj("events", "an ordered audit-log trace to run the rules over", {
    "load": Verb("load", "<file.json>", "load an ordered event trace", _events_load,
                 "events load <file.json>\n"
                 "  A list of audit-log entries (raw protoPayload form) or flat event dicts, in order.", paths=True),
    "list": Verb("list", "", "the loaded trace, one row per event", _events_list,
                 "events list\n  Number, time, method, principal, resource of every loaded event."),
    "inspect": Verb("inspect", "<n>", "one event of the trace, every field, who observes it", _events_inspect,
                    "events inspect <n>\n  Event n of the loaded trace as JSON, and the rules that observe it alone."),
    "trace": Verb("trace", "[all]", "run every detection over the loaded trace (three-valued)", _events_trace,
                  "events trace [all]\n"
                  "  Which detections fire over the whole trace (correlations included); `all` also\n"
                  "  lists the ones that do not fire."),
    "observe": Verb("observe", "<file.json>", "one event from a file: which detections observe it", _events_observe,
                    "events observe <file.json>\n"
                    "  A single event (not added to the trace): which detections match it, which single-\n"
                    "  event rules fire, which answer don't-know.", paths=True),
}, default="list")


# --- account -------------------------------------------------------------------------------


def _account_load(s: Session, a: list[str]) -> None:
    if not a:
        _usage("account load <file.json> [resource]")
        return
    s.account_load(a[0], a[1] if len(a) > 1 else "*")


def _account_show(s: Session, a: list[str]) -> None:
    render.account_show(s)


def _account_who(s: Session, a: list[str]) -> None:
    browse.who(s, a)


ACCOUNT = Obj("account", "the GCP account model: who can do what (Reach) and what is logged (Log)", {
    "load": Verb("load", "<file.json> [resource]", "load the account model, or a raw gcloud / terraform export", _account_load,
                 "account load <file.json> [resource]\n"
                 "  The tool's own account JSON, or a raw export converted on load:\n"
                 "    gcloud projects get-iam-policy PROJECT --format=json > policy.json\n"
                 "      → account load policy.json projects/PROJECT   (bindings + Data Access audit config)\n"
                 "    gcloud asset search-all-iam-policies --scope=projects/PROJECT --format=json > cai.json\n"
                 "      → account load cai.json                        (grants scoped per resource)\n"
                 "    terraform show -json > infra.json               (resolved state / plan — vars & modules expanded)\n"
                 "      → account load infra.json                      (google_*_iam_* grants, custom roles, audit configs)\n"
                 "      a native *.tf.json config also loads (unresolved ${...} refs kept and noted).\n"
                 "  Predefined roles expand from the built-in catalog; conditional bindings are kept\n"
                 "  unconditionally and listed as notes.", paths=True),
    "show": Verb("show", "", "the loaded account on one card", _account_show,
                 "account show\n  Principals, grants, which audit logs are on, deny rules, resources."),
    "who": Verb("who", "[permission | principal [filter]] [--limit N | --all]", "who holds a permission and where, or what a principal holds", _account_who,
                "account who [permission | principal [filter]] [--limit N | --all]\n"
                "  `account who` lists principals; `account who <permission>` who holds it, through which\n"
                "  grant, on which resource; `account who <principal> [filter]` the grants that principal holds."),
}, default="show")


# --- catalog -------------------------------------------------------------------------------


def _catalog_perms(s: Session, a: list[str]) -> None:
    browse.perms(s, a)


def _catalog_methods(s: Session, a: list[str]) -> None:
    browse.methods(s, a)


def _catalog_roles(s: Session, a: list[str]) -> None:
    browse.roles(s, a)


CATALOG = Obj("catalog", "the GCP method / permission / role catalog (browse without leaving the shell)", {
    "perms": Verb("perms", "[filter] [--tag T] [--reachable] [--unwatched] [--limit N|--all]", "permissions: by service, then by name", _catalog_perms,
                  "catalog perms [filter] [--tag PrivEsc|CredentialExposure|DataAccess] [--reachable] [--unwatched] [--limit N | --all]\n"
                  "  No filter: one row per service (how many permissions, how many reachable / watched / tagged).\n"
                  "  A filter (substring or glob: `iam.`, `*.setIamPolicy`): one row per permission — its methods,\n"
                  "  how it is logged, how many rules name a method of it, who holds it, its attack tag.\n"
                  "  --reachable  only permissions someone in the account holds      --unwatched  only ones no rule names\n"
                  "  Listings stop at 20 rows and say how many were hidden (--limit N, --all)."),
    "methods": Verb("methods", "<permission | method> [--limit N]", "a permission's audit-log methods, or one method's fact card", _catalog_methods,
                    "catalog methods <permission | method> [--limit N]\n"
                    "  A permission: the audit-log methods that exercise it, each with its service, whether it is\n"
                    "  logged in this account, whether the name is verified, how many rules name it, and the\n"
                    "  fields a real event carries — what you need for a candidate's footprint and `where`.\n"
                    "  A method: its facts on one card (service, log, permissions, pinned fields, rules naming it)."),
    "roles": Verb("roles", "[filter | role [filter]] [--with perm] [--limit N]", "what a role grants, which roles grant a permission", _catalog_roles,
                  "catalog roles [filter | roles/x [filter]] [--with permission] [--limit N | --all]\n"
                  "  `catalog roles` / `catalog roles storage` lists roles with how many tagged permissions each\n"
                  "  carries; `catalog roles roles/owner iam.` lists a role's permissions; `--with p` lists the\n"
                  "  roles that grant p, smallest first."),
}, default="perms")


# --- ask: the math -------------------------------------------------------------------------


def _ask_blindspots(s: Session, a: list[str]) -> None:
    render.blindspots(s, a)


def _ask_stealth(s: Session, a: list[str]) -> None:
    render.stealth(s, _first(a))


def _ask_chains(s: Session, a: list[str]) -> None:
    render.chains(s, a)


def _ask_check(s: Session, a: list[str]) -> None:
    render.check(s, a)


def _ask_suggest(s: Session, a: list[str]) -> None:
    render.suggest(s, a)


ASK = Obj("ask", "the questions that need the solver (every answer is replayed through the oracle)", {
    "blindspots": Verb("blindspots", "[perm…]", "reachable+logged events no rule observes  (SMT)", _ask_blindspots,
                       "ask blindspots [perm…]\n"
                       "  QUESTION: for each permission, is there ANY logged action using it that no rule catches?\n"
                       "  Per permission you see:\n"
                       "    Reach        who can exercise it          Log   which methods are audit-logged\n"
                       "    example      the simplest event nobody catches (replayed through the oracle)\n"
                       "    watched:     a kind of change some rule catches — and by which rule\n"
                       "    UNWATCHED:   a kind of change no rule catches — and the nearest rule's missing condition\n"
                       "    the attack…  the verdict of `ask stealth` for techniques needing this permission\n"
                       "  Verdicts: BLIND SPOT / covered (proof) / inconclusive (refinement bound).\n"
                       "  exact vs ~approx: approx means an untranslatable rule part was involved.",
                       settings="blindspots."),
    "stealth": Verb("stealth", "[id]", "can a technique evade every rule?  (SMT)", _ask_stealth,
                    "ask stealth [id]\n"
                    "  QUESTION: can THIS technique be run so that no rule fires?\n"
                    "  Verdicts: evasive (a concrete schedule, replayed) / always_detected (proof) /\n"
                    "            not_feasible (no principal holds the permissions) / exhausted.",
                    settings="stealth."),
    "chains": Verb("chains", "[goal] [--from p] [--start p1,p2]", "stealthy privilege-escalation paths  (graph+SMT)", _ask_chains,
                   "ask chains [goal] [--from <principal>] [--start <p1,p2,…>]\n"
                   "  Stealthy privilege-escalation paths: every hop is a technique that evades every rule,\n"
                   "  and the whole path is replayed so a correlation rule across hops still catches it.\n"
                   "  Techniques advance the chain via their `gains { … }` clause.  The start defaults to the\n"
                   "  account's most capable principal and what they already hold; override with the flags or\n"
                   "  an `attack` block (principal, initial_state, goal, effects) in the account file.",
                   settings="chains."),
    "check": Verb("check", "[id…]", "run loaded check blocks (all, or the named ones)  (SMT)", _ask_check,
                  "ask check [id…]\n"
                  "  Run the loaded check blocks: all of them, or only the named ones.  Load them first with\n"
                  "  `checks load <file.decn>` or type a block at the prompt.\n"
                  "  Types: coverage, candidate, compare, dead_rules, redundant_rules, boundary,\n"
                  "         require_coverage, attempt_coverage, public_access.\n"
                  "  Every answer is pass / fail / unknown; a fail shows a witness replayed through the oracle.",
                  settings="check."),
    "suggest": Verb("suggest", "<perm…> [define]", "DSL detections that would close a permission's blind spot", _ask_suggest,
                    "ask suggest <permission> [permission …] [define]\n"
                    "  For a permission with a blind spot: DSL `detection` blocks that would close it — one per\n"
                    "  unwatched kind of change (built from the rules' own tests) and one catch-all over every\n"
                    "  logged method.  `define` adds them to the session; then `ask blindspots <permission>` or\n"
                    "  an `ask check` shows the gap closed.  Suggestions are starting points, not tuned rules."),
})


# --- reports -------------------------------------------------------------------------------


def _reports_list(s: Session, a: list[str]) -> None:
    render.reports(s)


def _reports_show(s: Session, a: list[str]) -> None:
    render.report(s, _first(a))


def _reports_diff(s: Session, a: list[str]) -> None:
    if len(a) != 2:
        _usage("reports diff <a> <b>")
        return
    render.report_diff(s, a[0], a[1])


def _reports_export(s: Session, a: list[str]) -> None:
    render.export(s, a)


REPORTS = Obj("reports", "saved runs of the `ask` verbs (config report.save on)", {
    "list": Verb("list", "", "list saved report files", _reports_list,
                 "reports list\n  The files in report.dir with the verb, time, and summary of each run."),
    "show": Verb("show", "<file>", "reopen a saved run: loaded, summary, findings", _reports_show,
                 "reports show <file>\n  Re-render a saved run (md / json / yaml): what was loaded, the summary, every finding.",
                 paths=True),
    "diff": Verb("diff", "<a> <b>", "what changed between two runs of the same verb", _reports_diff,
                 "reports diff <a> <b>\n"
                 "  Findings that appeared (new), closed (gone) or changed verdict — the before/after of a\n"
                 "  rule edit or a corpus update.", paths=True),
    "export": Verb("export", "<file.json> [n]", "write the last run's witnesses as Cloud Audit Log JSON", _reports_export,
                   "reports export <file.json> [n]\n"
                   "  Write the last run's witness events (or only finding n) as Cloud Audit Log entries\n"
                   "  (protoPayload form, one list) — replay them in the SIEM to confirm the gap for real.\n"
                   "  Each entry carries `_decnique` (finding number, label, verdict).", paths=True),
}, default="list", )

# settings prefix for the whole object (shown by `help reports`)
_OBJECT_SETTINGS = {"reports": "report."}

OBJECTS: dict[str, Obj] = {o.name: o for o in (RULES, CANDIDATES, CHECKS, EVENTS, ACCOUNT, CATALOG, ASK, REPORTS)}

# the shell's own words (not objects): name -> (hint, one line, detail)
SHELL: dict[str, tuple[str, str, str]] = {
    "config": ("[key [value|reset]]", "show or change settings",
               "config                      list every setting\n"
               "config <key>                show one value\n"
               "config <key> <value>        set (persisted)      config <key> reset   back to default\n"
               "config <object> [verb]      the help page for an object or verb, with its settings"),
    "help": ("[object [verb]]", "the object list, an object's verbs, or everything about one verb",
             "help                 every object and its verbs\n"
             "help <object>        the verbs of one object\n"
             "help <object> <verb> everything about one verb: arguments, what each word on screen means, settings"),
    "clear": ("", "clear the screen (session state is kept)", "clear\n  Clear the screen; nothing loaded is lost."),
    "quit": ("", "leave the shell", "quit\n  Leave the shell."),
}


def settings_prefix(obj: Obj, verb: Verb | None) -> str:
    if verb is not None and verb.settings:
        return verb.settings
    return _OBJECT_SETTINGS.get(obj.name, "")
