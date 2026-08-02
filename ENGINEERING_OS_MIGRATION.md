# Engineering OS migration

This repository is in Phase 1 of the move from the older fixed Engineering OS
pipeline to the configurable process. Phase 1 adds and proves the new path while
every old protection remains active. It does not authorize product work or cleanup.

## Phase 1 invariant

The following old machinery remains active until Phase 2 classifies it:

- the frozen acceptance suite, manifest, and phase flags;
- the `process-guard` pull-request job and local pre-commit hook;
- the existing `typecheck · lines · test · build` check;
- the existing CodeQL, publish, and Scorecard workflows;
- the existing verification, packaging, dependency-policy, line, and seam commands;
- `docs/verification.md` and the contract-change protocol.

The new `verify` job deliberately overlaps the existing full-suite job during
Phase 1. That duplication is temporary migration safety, not the final workflow.

## Phase 2 gate

Phase 2 is blocked until all of these are true:

1. the Phase 1 pull request is merged;
2. the new check is green on the exact current `main` commit;
3. GitHub evidence shows branch protection requires the exact emitted check context;
4. every old-test batch has a recorded keep-normal, keep-protected, rewrite, or
   remove decision;
5. the owner has approved every proposed deletion.

After merge, read the actual check context emitted on `main`; do not infer it from
the workflow job key or display name. Phase 2 must remove the duplicated full-suite
execution and may remove only old machinery that has been separately classified
and approved.

This file is repository guidance, not package documentation. The npm artifact must
continue to contain only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`.
