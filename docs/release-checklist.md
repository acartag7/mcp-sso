# Release checklist

Use this checklist for a release candidate. The [release verification reference](verification.md) defines each test row. The [Tier 3 evidence reference](verification-live.md) defines live evidence.

## Merge the version bump

1. Push the final versioned runtime tree on a feature branch and open or update its pull request.
8. Add or update the matching Tier 1 rows in [the release verification reference](verification.md).
3. Wait for the hosted `typecheck · lines · test · build` and `process-guard` checks to pass on that commit.
4. Read every review and inline thread.
5. Confirm that the Codex review contains `Reviewed commit: <head sha>` for the pull request's current head. A reaction or an older review does not satisfy this step.
6. Merge the version-bump pull request into `main`.

## Run the source and package gates

1. Fetch `origin/main` and create an evidence branch from it. Do not change a runtime, build, publication, or evidence-defining input on this branch.
2. Record the reachable runtime commit:

   ```bash
   git rev-parse HEAD
   ```

3. Run the source checks:

   ```bash
   pnpm run typecheck
   pnpm run check:lines
   pnpm run check:seams
   pnpm run check:deps
   pnpm test
   pnpm run build
   ```

4. Confirm that `test/e2e-mcp-sdk.test.ts` completes registration, authorization, token exchange, the protected `/mcp` call, and refresh. It must replay the first family's consumed token and confirm that the successor is dead. It must then create a second family, revoke that family while it is active, and confirm that its refresh token is refused.
5. Start disposable MySQL and Redis services.
6. Run the release matrix with their connection URLs:

   ```bash
   RUN_INTEGRATION=true MYSQL_URL='mysql://…' REDIS_URL='redis://…' pnpm run test:release
   ```

   The command rebuilds the current tree after checking the required service variables and before running any matrix row.

7. Confirm that every `RM.N` row passes. A missing service variable, missing evidence file, skipped selected test, undocumented row, removed export, or removed example makes the command fail.
8. Run `npm pack --dry-run`.
9. Confirm that the tarball root contains only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`.

## Record live compatibility claims

Run the release rehearsal from the merged `main` commit:

```bash
gh workflow run live.yml --ref main -f record=true
gh run watch
```

The `live` workflow runs the release matrix against MySQL and Redis, every provider probe, the headless sign-ins, and the client flows against the served legs, and, when dispatched with `record=true` from `main`, records the passing receipt as release evidence and uploads it as the `evidence-<sha>` artifact.


Do not use a live result as the only evidence for a security property.

Run the evidence gates after recording both sets of results:

```bash
pnpm run check:release-matrix
pnpm run check:release-ready
```

The commands name a malformed matrix row, non-ancestor runtime commit, missing export row, stale evidence commit, or version mismatch.

A receipt goes stale when something that changes what a client would observe moved after its commit: `src/`, `examples/`, the TypeScript configuration, the lockfiles, the publish workflow, a runtime field of `package.json`, or the composition of the leg a client is driven against, which is `scripts/live/run.sh`, `scripts/live/serve.sh`, and `scripts/live/run-support.mjs`. The code that produces a receipt ages that receipt and no other. A change under `test/`, `scripts/live/`, the release-matrix scripts, `docs/verification.md`, or `.github/workflows/live.yml` ages `rehearsal.json`, so landing one means dispatching a recorded run before the tag; one dispatch rewrites it. It never ages `operator.json`, which records what a real client did against a served leg and which no probe produced. For stale evidence, the default output shows changed-input counts and categories. Run `pnpm run check:release-ready --verbose` to list every changed input. Do not create the tag while either command fails.

## Merge the evidence record

1. Commit the receipt under `docs/evidence/` from the `evidence-<sha>` artifact, and open the pull request from an account rather than a workflow token.
2. Update [`docs/client-compatibility.md`](client-compatibility.md) in the same pull request. Nothing generates it, so nothing will notice it going stale: `record-receipt.mjs` prints what the campaign observed, in the words that page uses, and the receipt is the source for the runtime commit and the client versions.
3. Wait for the hosted `typecheck · lines · test · build` and `process-guard` checks to pass on that commit.
4. Read every review and inline thread.
5. Confirm that the Codex review contains `Reviewed commit: <head sha>` for the pull request's current head. A reaction or an older review does not satisfy this step.
6. Merge the pull request that adds the receipt into `main`.
7. Fetch `origin/main` and run `pnpm run check:release-matrix` and `pnpm run check:release-ready` on that exact commit.
8. Confirm that the commit selected for the tag is on `origin/main`. Do not tag an unmerged branch or a local-only commit.

## Verify the publish controls

1. Read the `publish` GitHub Environment through the repository API.
2. Confirm that the owner is a required reviewer.
3. Confirm that administrator bypass is disabled.
4. Confirm that `v*.*.*` is the only custom deployment branch or tag pattern.
5. Run the `workflow_dispatch` dry run.
6. Confirm that the dry run builds the artifact but does not run the OIDC publish job or the GitHub Release job.

## Publish

1. Confirm that the tag is `v${package.version}`.
2. Push the tag. Do not create the GitHub Release first.
3. Confirm that the build job creates one tarball and one SHA-256 file.
4. Confirm that the OIDC job publishes that digest-verified tarball without a checkout, dependency installation, or repository scripts.
5. Confirm that the GitHub Release job starts only after npm publication succeeds.
6. Edit the generated GitHub Release with hand-written release notes.
