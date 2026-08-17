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

## Repository quality rules

The canonical rules live in [`AGENTS.md`](AGENTS.md), which this file includes
via `@AGENTS.md`. In short: keep the 16 manifest-frozen acceptance tests and all
five active phases intact; keep `freeze-hash`, `mixed-diff`, and
`stage-artifact` active; define product and security contracts before new trust
boundaries; fail closed with allowlists; and run the existing repository gates.

Sweep all adapters, stores, examples, and mutable-state exit paths for sibling
defects. Never weaken checks or push directly to protected branches. Use
conventional commits with the required `Spec: <path>` trailer, and prove each
regression test fails without its fix. Codex Reviewer must review the exact
final PR head, and every review object and inline thread must be read before
merge. After more than two unsuccessful review cycles, split or redesign the
PR.

Local review before Codex is
[class-closure-review](.claude/skills/class-closure-review/SKILL.md), not a
prose “sibling sweep.” Empty matrix cell = do not push.
