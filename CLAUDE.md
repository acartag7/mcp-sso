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
