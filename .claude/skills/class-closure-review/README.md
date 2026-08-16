# class-closure-review

Repo-local exact-head review. Empty matrix cell = do not push.
This is how AGENTS.md items 1–4 are executed before Codex.

- `SKILL.md` — rules
- `references/matrices.md` — mcp-sso axes (adapters, stores,
  pairing, starter, stored vs in-flight)
- `evals/` — six CLEAN-must-fail heads, one closed-class
  control, and `CORPUS.md` (which public PRs minted which case)

Run a case: fresh session, this skill active, paste
`evals/<id>/prompt.md`, grade with the matching grader.

Isolated (no repo walk): `evals/run-isolated.sh`. Measured
score lives in `evals/RESULTS.md`. Do not ship a skill change
that drops the isolated suite below 6/7.

Model bakeoff (2026-08-16): frozen 7/7 on GLM 5.3, Opus 5,
Terra xhigh, Sol medium, and Grok 4.6. Live leftover-sibling
heads separate them — Sol / Terra / Opus 5 / Grok 4.6 are
16/16; GLM 5.3 is 14/16. Default local runner: Sol medium.
Do not use GLM 5.3 as the only reviewer. Table and miss
write-ups: `evals/RESULTS.md`.
