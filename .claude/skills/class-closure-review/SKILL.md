---
name: class-closure-review
description: Exact-head local PR review for mcp-sso that refuses PASS until a defective behavior is closed across every sibling cell, not just the named instance. Use when reviewing a pull request locally, after a Codex finding, before requesting another hosted review round, or when leftover claims, unswept adapters/stores, stored-state, pairing, or generated-starter misses keep surviving a CLEAN pass.
---

# Class-closure review (mcp-sso)

Exact-head local review. The unit of work is a **behavior**, not a
`file:line`. PASS requires a filled matrix. An empty applicable cell
is FAIL, even if the named instance looks fixed.

A prior CLEAN is not evidence. "Swept siblings" with no cells is FAIL.
This skill is how AGENTS.md items 1–4 are **executed**, not restated.

Do not edit the reviewed tree. Do not implement the fix in this pass.
Mutations belong under `/tmp`.

## Runner

Keep the matrices. Starve the ceremony. Full rules:
[runner.md](references/runner.md).

1. After one environmental full-suite failure, classify the
   common shape (`EPERM` on bind, sandbox, …) and **stop
   rerunning** it.
2. Command output is summaries first. Full logs only for an
   unexpected failure.
3. No web, personal memory, or live-document lookup unless
   the diff leaves a factual question unresolved.
4. Budget **40k–60k tokens**. Exceed it only after a genuine
   open class. Classify irrelevant axes `n/a` immediately.

Emit the output contract once. Hosted Codex remains the merge
gate.

## When

- Local review of a PR or exact commit **before** Codex.
- After a hosted finding, **before** the next push or re-request.
- Follow-up PRs that are the next sibling of the last merge
  (Windows warning trilogies, sanitization then the `{ ok: false }`
  leftover, redirect replace then prepare-vs-approve).

## Rules

1. Review the exact named commit. Print the full SHA. Any later
   push makes the result stale.
2. Name the defective **behavior** in one sentence (what still
   works that the change says cannot). Then fill cells.
3. Load [matrices.md](references/matrices.md). Mark every cell
   `hit` / `n/a` / `clean`. `n/a` = that axis is not a sibling
   of **this** behavior (one-line reason). Empty = it **is** a
   sibling in this tree and you skipped it. Do not invent a
   P1/P2 for a file the tree does not contain. Do not walk
   stores or schema because they exist in the checkout.
   "Every store call is wrapped" means Port **methods** on an
   already-open store (`find` / `remove` / `create` / CAS /
   getters / `destroy`). `openSqliteStore` / MySQL open / a
   store constructor is M4 (guard before the factory), not an
   empty M1 wrap cell, unless the claim literally says
   store-*open* errors are sanitized.
4. Guarantee verbs need enforcing code **and** a test that goes
   red if that code is removed. Softening the sentence is not
   the fix. Grep is in AGENTS.md §7.1 — run it.
5. After any finding, do not push until the **class** is closed.
   Fixing the named instance and re-requesting Codex is the
   round multiplier this skill exists to stop.
6. If review discovers an edge the contract never named,
   **STOP**. Amend the contract or re-cut. See
   [output-contract.md](references/output-contract.md).

## Steps

```
- [ ] 1. Pin REVIEWED_SHA (full) and origin/main (or the PR base)
- [ ] 2. Read the whole diff
- [ ] 3. Name the behavior; mark non-sibling axes n/a immediately
- [ ] 4. Fill remaining M1–M7 cells
- [ ] 5. Claims grep across contracts, threat-model, verification, AGENTS, CLAUDE, README, identity guides
- [ ] 6. Mutation under /tmp: revert the shipped function, not a helper.
   One environmental full-suite failure is enough — classify
   and stop. A missing *extra* test for a sibling already
   wrapped by the same function is P3, not a FAIL, when each
   **claimed** guarantee already names a test that goes red.
   FAIL M7 only when the guarantee has **zero** biting test,
   or the test would stay green if the shipped function were
   reverted.
- [ ] 7. Emit the output contract once — no PASS with an empty applicable cell
```

If this head answers a prior finding, **CLASS CLOSURE** must list
the other cells of that behavior. "Fixed the reported line" is
not closure.

## Output

[output-contract.md](references/output-contract.md)

## Evals

Frozen heads and the PR corpus:
[evals/CORPUS.md](evals/CORPUS.md).
When Codex finds a leftover sibling after this skill said CLEAN,
freeze it the same day: [freeze-a-case.md](references/freeze-a-case.md).
