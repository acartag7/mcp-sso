# Corpus

Public PRs whose extra hosted rounds minted an eval. Gold is
the **empty cell**, not the exploit write-up.

| Eval | Class | Empty cell | Seed PRs (public) |
|---|---|---|---|
| `leftover-claim` | leftover guarantee | M3 — contract/threat/status still states the old rule | #140, #201, #231, #238, #240 |
| `one-call-site` | wrap one call | M1 — `find` wrapped; create/CAS/getters not | #243, #244 |
| `stored-not-rechecked` | policy vs stored | M2 — prepare changed; approve / in-flight consent not | #183, #231, #245 |
| `guard-after-open` | guard after write | M4 — ack/validate after store, secrets, or discovery | #190, #191, #217, #227 |
| `name-not-shape` | schema by name | M6 — `UNIQUE`+column name; prefix/FK/trigger still in | #188, #191, #193 |
| `starter-not-library` | composition root | M1 — library+example fixed; `templates.ts` still old | #231, #242 |
| `class-closed` | control | none — PASS, no invented P1 | (synthetic closed head) |

Same-class grinders that should become **new** cases if they
recur after this skill is in use (do not duplicate tonight):

- wire-form / snapshot-once (M5) — #187, #216, #224
- ClockPort vs `Date.now()` leftover (M2/M4) — #227
- test bites helper not shipped function (M7) — #214, #206

## How to run a case

Isolated: `evals/run-isolated.sh` (or `CCR_PARALLEL=1` for
all seven). Grade with `evals/<id>/graders/<id>.md`. Score:
`evals/RESULTS.md`. A pleasing CLEAN must fail the six;
`class-closed` must pass. Do not ship a skill change that
drops the isolated suite below 6/7.

Interactive: fresh session, this skill active. Paste
`evals/<id>/prompt.md`. Grade with the matching grader.

Live SHA check (2026-08-16): nine first leftover-sibling
rounds scored against the Codex inline on that SHA. First
isolated pass 7/9; after the M2/M5 clarifications, 9/9.
Method and table: `evals/RESULTS.md`.

## Other repos

Do not copy these matrices. Mine that repo’s PRs and write
its own axes. The method is the repo-local review-eval guide
in the skills marketplace docs, not this tree.
