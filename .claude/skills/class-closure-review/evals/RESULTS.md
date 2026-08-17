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

## Model bakeoff (2026-08-16)

Same isolated recipe as r5. Five runners.
Frozen suite = skill calibration (does the method hold).
Live suite = the bakeoff (does the runner close leftover
siblings on real hosted-review SHAs). Grade with the frozen
graders / live gold cells, not the `VERDICT` line alone.

Do not treat `/tmp/ccr-bakeoff/` as durable.

### Runners

| Label | Invocation | Effort |
|---|---|---|
| GLM 5.3 | local `glmcode` alias → `claude -p --model glm-5.3[1m]` (z.ai Anthropic-compatible). Claude Code may print `unrecognized_model`; the alias still serves GLM 5.3. Do not wrap the alias in `/usr/bin/time` — `time` cannot see a shell alias. | high |
| Opus 5 | `claude -p --model claude-opus-5` | high |
| Terra xhigh | `codex exec --ephemeral -C /tmp/ccr-iso-empty -s read-only --skip-git-repo-check -m gpt-5.6-terra -c 'model_reasoning_effort="xhigh"'` | xhigh |
| Sol medium | same Codex flags, `-m gpt-5.6-sol -c 'model_reasoning_effort="medium"'` | medium |
| Grok 4.6 | `grok --cwd /tmp/ccr-iso-empty -m grok-4.6 --effort high --permission-mode dontAsk --disable-web-search --no-subagents --tools "" --prompt-file …` | high |

Shared isolation: empty `/tmp/ccr-iso-empty` (no `.git`, no
`CLAUDE.md`, no `AGENTS.md`, no `.claude`). Skill + matrices +
output contract inlined. `--tools ""`. `--setting-sources user`
and `--no-session-persistence` on Claude. Codex inlines the
skill in the user prompt (`codex -p` is a profile flag, not
prompt mode). `claude -p --bare` still unused (skips keychain
login here).

Opus 5 often writes `VERDICT: **FAIL**` (markdown bold).
Graders must accept that form.

### Combined score

| Runner | Frozen 7 | Live 9 | Combined | Live median | Live mean |
|---|---|---|---|---:|---:|
| Sol medium | 7/7 | **9/9** | **16/16** | 49s | 50s |
| Terra xhigh | 7/7 | **9/9** | **16/16** | 83s | 70s |
| Opus 5 | 7/7 | **9/9** | **16/16** | 133s | 127s |
| Grok 4.6 | 7/7 | **9/9** | **16/16** | 168s | 166s |
| GLM 5.3 | 7/7 | **7/9** | **14/16** | 181s | 174s |

The frozen suite does **not** separate these runners. All five
scored 7/7, including the closed-class control (P3 nits only,
no invented P1/P2). The live heads separate leftover-cell
recovery on **pasted excerpts**. That is not a real-review
ranking and does not pick a local runner.

### What this bakeoff measured

Leftover-cell thrash on pasted snippets. It does **not**
answer the objective (fewer hosted rounds on a real
`merge-base...HEAD`). Do not pin Sol — or any runner —
from this table. Hosted Codex remains the merge gate.

GLM 5.3 / `glmcode` PASSed two leftover-sibling shapes
this skill exists to catch. That is a statement about this
exam, not a general ranking. Those misses match the first
Opus 4.8 live pass *before* the M5 wording, and the
"factory path is clean so the public constructor is P3"
pattern.

### Live leftover-sibling matrix

Gold = Codex inline on that SHA. `hit` = FAIL and names the
gold cell. `miss` = PASS or wrong cell.

| Case | PR / SHA | Gold | GLM 5.3 | Opus 5 | Terra | Sol | Grok 4.6 |
|---|---|---|---|---|---|---|---|
| pr243-wrap-siblings | #243 `62fff35bc8` | M1 | hit | hit | hit | hit | hit |
| pr183-stored-loopback | #183 `e4c2b2e1ed` | M2 | hit | hit | hit | hit | hit |
| pr188-prefix-after-ddl | #188 `aac04ec385` | M6 | hit | hit | hit | hit | hit |
| pr190-guard-after-open | #190 `9b0cdb7f16` | M4 | hit | hit | hit | hit | hit |
| pr187-header-snapshot | #187 `491235a4c4` | M5 | **PASS (miss)** | hit | hit | hit | hit |
| pr227-sqlite-scheduler | #227 `91208db69d` | M1/M4 | **PASS (miss)** | hit | hit | hit | hit |
| pr231-leftover-empty | #231 `67204411b2` | M3 | hit | hit | hit | hit | hit |
| pr140-leftover-guest | #140 `172a2415cb` | M3 | hit | hit | hit | hit | hit |
| pr224-dup-content-type | #224 `12e38cf408` | M5 | hit | hit | hit | hit | hit |

### GLM 5.3 misses (the bakeoff findings)

Both misses are the skill's unit of work: the named instance
looks closed, the class is not. GLM wrote the sibling as a
P3 and PASSed.

**pr187 — live object ≠ snapshot (M5).** Gold: `this.headers`
is passed into `fetchImpl` and reread at catch time for the
scrub list; a transport that mutates the object can drop the
secret from redaction. GLM treated the constructor
`{ ...options.headers }` spread as closing the class, then
downgraded the live `this.headers` alias to P3 ("latent;
default `fetch` does not mutate; custom `fetchImpl` is
deployer-trusted"). Opus 5 / Terra / Sol / Grok 4.6 FAILed
the same lines as an open M5 cell. This is the same miss as
the first isolated live pass on this SHA, which forced skill
tweak 5.

**pr227 — public constructor vs factory path (M1/M4).** Gold:
MySQL now arms the expiry scheduler after migrate; SQLite
still constructs `StoreExpiryScheduler` in a field
initializer, so `new SqliteStore` starts collection without
a migrate gate. GLM closed the class on the two factory
paths that migrate first, and called the public constructor
P3 ("invariant held by call-site convention… no violating
path visible in this excerpt"). The other four FAILed
`src/store/sqlite.ts:30` as the empty sibling of the MySQL
fix. The implementer claim was "expiry collection is safe,"
not "the shown factories migrate first."

### Frozen suite (all 7/7, wall time)

| Runner | leftover | one-call | stored | guard | name | starter | control | median |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| GLM 5.3 | 142s | 56s | 95s | 128s | 165s | 93s | 98s | 98s |
| Opus 5 | 93s | 78s | 90s | 72s | 112s | 100s | 115s | 93s |
| Terra xhigh | 31s | 41s | 46s | 111s | 54s | 52s | 62s | 52s |
| Sol medium | 33s | 32s | 31s | 49s | 48s | 37s | 47s | 37s |
| Grok 4.6 | 108s | 96s | 93s | 120s | 124s | 104s | 181s | 108s |

### Live suite wall time

| Runner | #243 | #183 | #188 | #190 | #187 | #227 | #231 | #140 | #224 | median |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GLM 5.3 | 151s | 197s | 190s | 239s | 188s | 129s | 181s | 117s | 174s | 181s |
| Opus 5 | 119s | 146s | 161s | 140s | 133s | 79s | 152s | 95s | 116s | 133s |
| Terra xhigh | 55s | 89s | 88s | 97s | 93s | 54s | 83s | 36s | 37s | 83s |
| Sol medium | 51s | 69s | 67s | 49s | 53s | 37s | 42s | 36s | 48s | 49s |
| Grok 4.6 | 160s | 168s | 216s | 221s | 165s | 133s | 169s | 93s | 168s | 168s |

### What this bakeoff is not

A claim that any of these runners is the best reviewer in
general, or a reason to pin one. Hosted Codex remains the
merge-gate reviewer. A leftover sibling after a local CLEAN
should be frozen the same day.

## What this is not

A full-tree `git switch --detach` with tools. These are
focused excerpts of the files Codex commented on, run from
`/tmp/ccr-iso-empty` with `--setting-sources user` and
`--tools ""`. A hosted round that still finds a leftover
sibling after this skill said CLEAN should be frozen the
same day (`references/freeze-a-case.md`).
