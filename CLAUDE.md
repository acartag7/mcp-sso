@AGENTS.md

# Claude Code session notes (mcp-sso)

`AGENTS.md` is the canonical source for this repo's rules, structure, commands,
invariants, and always-check list. This file keeps only context that is
specific to Claude Code sessions here and does not belong in the portable
`AGENTS.md`.

## Build/extraction context (lives in Claude memory, not in the repo)

- The build/extraction plan is **not** kept in this repo (no handoff artifacts
  in repos — repo docs are durable-only). It lives in this project's Claude
  memory and in session prompts from the owner.
- Extraction source is `~/project/smart-fetch` (Captatum) — read-only
  reference. Never copy deployment-specific details (hostnames, infra) or any
  `security-audit*` document into this repo.

## This repo is governed (Engineering OS)

The canonical copy of this block lives in [`AGENTS.md`](AGENTS.md) (which this
file includes via `@AGENTS.md`); it is repeated here for tools and readers that
open `CLAUDE.md` directly. It is complementary to the house rules — where they
overlap, they agree. `docs/contracts.md` remains the contract source of truth.

tier: S
Reference: https://github.com/acartag7/engineering-os

Non-negotiables — CI enforces these; this block just saves you a red build:

- Acceptance tests under `test/acceptance/` are FROZEN. Editing any of them turns
  CI red (hash check). Turn finished phases on via `test/acceptance/phases.json`
  only. If a test looks wrong: STOP and report. That's a contract change, not a
  patch. *(No acceptance suite exists yet — the repo carries a
  `.process-guard-exempt` marker that suppresses only the stage-artifact check
  until the first frozen suite lands; `freeze-hash` and `mixed-diff` run now.)*
- Contract first: `docs/contracts.md` wins over the code and over your inference.
  Never implement while the contract has open decisions or points at files
  outside this repo.
- Trust-boundary decisions are allowlists, never blocklists. Empty config counts
  as missing config: fail closed. Type-check every externally-sourced value
  before using it. Malformed input fails closed, never best-effort.
- Build the least machinery the contract asks for. No unrequested parsers,
  validators, or abstractions. If the simple approach feels insufficient, stop
  and ask — don't build.
- After fixing any defect, sweep sibling code paths BEFORE re-requesting review.
  Partial fixes are the top review-round multiplier.
- Never weaken a check to get green. Never push to protected branches. PRs carry
  a `Spec: <path>` trailer and conventional commit subjects.
- Review verifies; it never discovers. If review is teaching us what the spec
  should have said, say so — that's a process failure to record, not a grind to
  endure.
