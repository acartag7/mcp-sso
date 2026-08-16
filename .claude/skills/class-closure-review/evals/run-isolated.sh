#!/bin/bash
# Isolated exact-head eval: skill files inlined, no repo exploration.
# Usage: ./evals/run-isolated.sh [case-id ...]
# Do not pass --bare: it skips keychain login in this environment.
# Parallel: CCR_PARALLEL=1 ./evals/run-isolated.sh
# Isolation: run from an empty workdir (not mcp-sso, not /tmp root —
# /tmp is full of leftover mcp-sso worktrees). Skip project/local
# setting sources so CLAUDE.md / AGENTS.md / .claude/skills do not load.
set -euo pipefail
SKILL="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${CCR_EVAL_OUT:-/tmp/ccr-eval}"
WORKDIR="${CCR_WORKDIR:-/tmp/ccr-iso-empty}"
MODEL="${CCR_MODEL:-claude-opus-4-8}"
EFFORT="${CCR_EFFORT:-high}"
PARALLEL="${CCR_PARALLEL:-0}"
mkdir -p "$OUT"
mkdir -p "$WORKDIR"
# Refuse to run inside a git checkout or a dir that already has
# CLAUDE.md / AGENTS.md / .claude (those pollute auto-discovery).
if [ -e "$WORKDIR/.git" ] || [ -e "$WORKDIR/CLAUDE.md" ] || [ -e "$WORKDIR/AGENTS.md" ] || [ -e "$WORKDIR/.claude" ]; then
  echo "WORKDIR $WORKDIR is not empty of project context" >&2
  exit 1
fi
{
  echo 'You are running the class-closure-review skill. Follow it exactly. Do not edit files. Do not use tools. Review only the exact head in the user message. The tree is those pasted files. Surfaces not in the paste are n/a, not findings.'
  echo
  echo '===== SKILL.md ====='
  cat "$SKILL/SKILL.md"
  echo
  echo '===== references/matrices.md ====='
  cat "$SKILL/references/matrices.md"
  echo
  echo '===== references/output-contract.md ====='
  cat "$SKILL/references/output-contract.md"
} > "$OUT/system.md"

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
  cases=(leftover-claim one-call-site stored-not-rechecked guard-after-open name-not-shape starter-not-library class-closed)
fi

run_one() {
  local id="$1"
  echo "RUN $id"
  (
    cd "$WORKDIR"
    claude -p \
      --system-prompt "$(cat "$OUT/system.md")" \
      --setting-sources user \
      --no-session-persistence \
      --model "$MODEL" \
      --effort "$EFFORT" \
      --tools "" \
      --permission-mode dontAsk \
      --output-format text \
      "$(cat "$SKILL/evals/$id/prompt.md")"
  ) > "$OUT/$id.review.md" 2>"$OUT/$id.err"
  echo "DONE $id exit:$? lines:$(wc -l < "$OUT/$id.review.md")"
}

if [ "$PARALLEL" = "1" ]; then
  for id in "${cases[@]}"; do
    run_one "$id" &
  done
  wait
else
  for id in "${cases[@]}"; do
    run_one "$id"
  done
fi
echo "Wrote $OUT"
for id in "${cases[@]}"; do
  echo -n "$id: "
  grep -E '^VERDICT:' "$OUT/$id.review.md" || echo "(no VERDICT line)"
done
