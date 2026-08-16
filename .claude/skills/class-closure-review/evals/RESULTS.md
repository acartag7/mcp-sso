# Isolated eval results

Recipe: `evals/run-isolated.sh` — skill + matrices + output
contract inlined as `--system-prompt`, `--tools ""`,
`--permission-mode dontAsk`, `claude -p` (not `--bare`; bare
skips keychain login here). Model: `claude-opus-4-8`,
`--effort high`. Grade with `evals/<id>/graders/<id>.md`,
not the VERDICT line alone.

Do not treat `/tmp/ccr-eval-*` as durable. Re-run the script.

## Score

| Round | Date | Skill change | Score |
|---|---|---|---|
| r2 | 2026-08-16 | first isolated suite | 6/7 (86%) — control invented a FAIL |
| r3 | 2026-08-16 | M7: extra same-wrapper mutation is P3 | control still FAIL — treated `openSqliteStore` as an M1 wrap sibling |
| r4 | 2026-08-16 | M1: Port methods vs factory-open (M4) | 7/7 — **cwd not isolated** |
| r5 | 2026-08-16 | same skill; empty workdir + no project settings | **7/7 (100%)** |

r4 artifacts: `/tmp/ccr-eval-r4/*.review.md`. **Do not treat r4 as isolated.**
The runner did not `cd` out of the workspace, so Claude could still
auto-discover `mcp-sso/CLAUDE.md`, `AGENTS.md`, and
`.claude/skills/`. `--tools ""` blocked file reads; it did not
block project-context injection. r1 did `cd /tmp`, but `/tmp` is
full of leftover mcp-sso worktrees with their own `CLAUDE.md`.

r5 artifacts: `/tmp/ccr-eval-r5/*.review.md`. Workdir
`/tmp/ccr-iso-empty` (no `.git`, no `CLAUDE.md`, no `AGENTS.md`,
no `.claude`). Flags: `--setting-sources user`
`--no-session-persistence` `--tools ""`. `--bare` still unused
(keychain login). User-level `~/.claude` settings can still load;
project/local sources cannot.

Codex family (same skill, `codex exec --ephemeral -C /tmp
-s read-only`, skill inlined in the user prompt):
`/tmp/ccr-eval-codex-r1/*.review.md` — **7/7**. `codex -p` is
a config profile flag, not prompt mode.

## r5 per case (the isolated score)

| Case | Gold | Isolated VERDICT | Grader |
|---|---|---|---|
| leftover-claim | FAIL (M3 leftover 200/swallow) | FAIL | PASS |
| one-call-site | FAIL (unwrapped `remove`/`create`) | FAIL | PASS |
| stored-not-rechecked | FAIL (`approveStored` ignores allowlist) | FAIL | PASS |
| guard-after-open | FAIL (ack after `openSqliteStore` + starter writes) | FAIL | PASS |
| name-not-shape | FAIL (prefix UNIQUE admits) | FAIL | PASS |
| starter-not-library | FAIL (`templates.ts` still `req.body`) | FAIL | PASS |
| class-closed | PASS (closed class, no invented P1/P2) | PASS | PASS |

## Tweaks that the runs forced

1. Missing files in a pasted excerpt are `n/a`, not empty cells.
2. A second mutation of the **same** wrapper is P3, not FAIL,
   when the claimed guarantee already has a biting test.
3. "Every store call is wrapped" = Port **methods** on an
   already-open store. `openSqliteStore` is M4 (guard before
   the factory) unless the claim names sanitizing store-open
   errors.
4. Re-parsing stored slots / re-applying grammar is not
   revalidation against the **new** global policy (M2).
5. Passing `this.headers` (or any live object) into
   `fetchImpl` is not a snapshot (M5).

## What is being compared

Not “does the review look thorough.”

| Piece | What it is |
|---|---|
| Input | Exact head: files at the **hosted-review SHA**, pasted as an excerpt. Prior local CLEAN. Implementer claim. No Codex comments in the prompt. |
| Gold | The leftover **cell** Codex named on that SHA (M1–M7), after a CLEAN-looking named instance. |
| Score | Isolated review FAILs and names that same cell. PASS on a closed head must not invent a blocking P1/P2. Extra findings are allowed. |

Frozen suite = synthetic tiny heads distilled from those cells.
Live suite = real files at the real reviewed SHA.

## Live PR heads (isolated, empty workdir)

Nine first leftover-sibling rounds. Gold is the Codex inline
on that SHA (`/tmp/ccr-live/gold.json`). Artifacts:
`/tmp/ccr-eval-live1` then `/tmp/ccr-eval-live2` for the two
misses after the M2/M5 tweak.

| Case | PR / SHA | Gold cell | First isolated | After tweak |
|---|---|---|---|---|
| pr243-wrap-siblings | #243 `62fff35bc8` | M1 unwrapped CAS | FAIL / hit | — |
| pr183-stored-loopback | #183 `e4c2b2e1ed` | M2 stored vs new allowlist | **PASS (miss)** | FAIL / hit |
| pr188-prefix-after-ddl | #188 `aac04ec385` | M6 prefix UNIQUE | FAIL / hit | — |
| pr190-guard-after-open | #190 `9b0cdb7f16` | M4 open before guard | FAIL / hit | — |
| pr187-header-snapshot | #187 `491235a4c4` | M5 live `this.headers` | **PASS (miss)** | FAIL / hit |
| pr227-sqlite-scheduler | #227 `91208db69d` | M1/M4 SQLite sibling | FAIL / hit | — |
| pr231-leftover-empty | #231 `67204411b2` | M3 leftover threat row | FAIL / hit | — |
| pr140-leftover-guest | #140 `172a2415cb` | M3 leftover unverified | FAIL / hit | — |
| pr224-dup-content-type | #224 `12e38cf408` | M5 ambiguous Content-Type | FAIL / hit | — |

First pass: **7/9 (78%)**. After naming “re-parse ≠ new
policy” (M2) and “live object to transport ≠ snapshot” (M5):
**9/9**. Frozen `class-closed` still PASS on the same skill.

## What this is not

A full-tree `git switch --detach` with tools. These are
focused excerpts of the files Codex commented on, run from
`/tmp/ccr-iso-empty` with `--setting-sources user` and
`--tools ""`. A hosted round that still finds a leftover
sibling after this skill said CLEAN should be frozen the
same day (`references/freeze-a-case.md`).
