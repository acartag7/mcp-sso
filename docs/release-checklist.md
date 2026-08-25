# Release checklist

Use this checklist for a release candidate. The [release verification reference](verification.md) defines each test row. The [Tier 3 evidence reference](verification-live.md) defines live evidence.

## Merge the version bump

1. Push the final versioned runtime tree on a feature branch and open or update its pull request.
2. Add or update the matching Tier 1 rows in [the release verification reference](verification.md).
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

Run the release rehearsal from the merged `main` commit and let it open the evidence pull request:

```bash
gh workflow run live.yml --ref main -f record=true
gh run watch
```

The `live` workflow runs the release matrix against MySQL and Redis, every provider probe, the headless sign-ins, and the client flows against the served legs, and, when every row passes on a clean tree, renders the receipt into the [client compatibility reference](client-compatibility.md) and opens a pull request on an `evidence/<sha>` branch. `scripts/live/README.md` lists the rows and what each proves. A run with a failed or blocked row opens nothing; fix the cause and run it again.

Record the completed export rows and the commit used for the release-matrix run in the [public export evidence table](client-compatibility.md#public-export-live-evidence): the workflow's `record` job writes them from the receipt's `release-matrix` row. For a client the rehearsal does not drive (Claude Code, Codex CLI, the ChatGPT and claude.ai connectors, the Google sign-in), complete the matching Tier 3 row by hand after the source and package gates pass, on the same evidence branch, in the [client compatibility reference](client-compatibility.md#current-matrix).

Do not use a live result as the only evidence for a security property.

Run the evidence gates after recording both sets of results:

```bash
pnpm run check:release-matrix
pnpm run check:release-ready
```

The commands name a malformed matrix row, non-ancestor runtime commit, missing export row, stale evidence commit, or version mismatch. For stale evidence, the default output shows changed-input counts and categories. Run `pnpm run check:release-ready --verbose` to list every changed input. Do not create the tag while either command fails.

## Merge the evidence record

1. Commit only `docs/client-compatibility.md` on the evidence branch. The workflow's `record` job does this and opens the pull request; close and reopen that pull request once so the hosted checks start, because a branch pushed by the workflow token starts none on its own.
2. Wait for the hosted `typecheck · lines · test · build` and `process-guard` checks to pass on that commit.
3. Read every review and inline thread.
4. Confirm that the Codex review contains `Reviewed commit: <head sha>` for the pull request's current head. A reaction or an older review does not satisfy this step.
5. Merge the evidence pull request into `main`.
6. Fetch `origin/main` and run `pnpm run check:release-matrix` and `pnpm run check:release-ready` on that exact commit.
7. Confirm that the commit selected for the tag is on `origin/main`. Do not tag an unmerged branch or a local-only commit.

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
