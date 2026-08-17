# Output contract

Emit every block **once**. Silence is not PASS. Do not
repeat VERDICT, FINDINGS, or the matrix after this block.

```text
REVIEWED_SHA: <full exact head>
BASE: <full origin/main or PR base>
VERDICT: PASS | FAIL | STOP

MATRICES:
- M1: <hit|n/a|clean per occupied cell, or n/a — reason>
- M2: …
- M3: …
- M4: …
- M5: …
- M6: …
- M7: …

CLAIM TRACE:
- "<guarantee sentence>" → <file:line> + <test that goes red if removed>
  (or: leftover / unbacked — FAIL)

CLASS CLOSURE:
- Behavior: <one sentence>
- Cells checked: <list>
- Still open: <list or none>

FINDINGS:
- [P1|P2|P3] <file:line> — <title> — <empty cell + impact + smallest fix>

CLEAN:
- <named areas traced and clean>

CONFIDENCE: high | medium | low — <reason>
```

## Verdicts

- **PASS** — every applicable cell is `hit` or `clean`, every new
  guarantee traces to code and a biting test, no P1/P2. A P3
  “add another mutation of the same wrapper” does **not** flip
  PASS to FAIL.
- **FAIL** — empty applicable cell that is a **sibling of this
  behavior** in this tree, leftover claim, guard after a side
  effect, tautological test, or unwrapped Port-method sibling
  that exists in this tree. Do not FAIL because the store
  factory itself is unwrapped unless the claim names
  sanitizing store-*open* errors. Do not FAIL an irrelevant
  axis you correctly marked `n/a`.
- Do not FAIL a pasted excerpt for adapters, stores, or files
  the excerpt does not contain. Those are `n/a`.
- **STOP** — new edge class the contract never named. Do not
  start another Codex round. Owner amends the contract or
  re-cuts.

P1 and P2 block. The merge marker is “Reviewed commit: \<head
sha\>” on this SHA, never a silence window.

## After a Codex finding

The next local pass is not “did we change the reported line?”
Name the behavior, fill the matrix that finding belongs to,
close every occupied cell, re-review **this** SHA, then push.

A follow-up PR whose whole job is the next sibling of the last
merge means this skill was not used. Freeze that miss:
[freeze-a-case.md](freeze-a-case.md).
