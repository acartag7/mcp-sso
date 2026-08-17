# class-closure-review

Repo-local exact-head review. Empty matrix cell = do not push.
This is how AGENTS.md items 1–4 are executed before Codex.

- `SKILL.md` — rules
- `references/matrices.md` — mcp-sso axes (adapters, stores,
  pairing, starter, stored vs in-flight)
- `references/runner.md` — budget, no-rerun, no extra corpora
- `evals/` — six CLEAN-must-fail heads, one closed-class
  control, and `CORPUS.md` (which public PRs minted which case)

Run a case: fresh session, this skill active, paste
`evals/<id>/prompt.md`, grade with the matching grader.

Isolated (no repo walk): `evals/run-isolated.sh`. Measured
score lives in `evals/RESULTS.md`. Do not ship a skill change
that drops the isolated suite below 6/7.

Keep the matrices. Do not pick a reviewer from the excerpt
bakeoff. Hosted Codex is still the merge gate.
