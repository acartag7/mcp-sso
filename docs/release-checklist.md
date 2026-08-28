# Release checklist

Use this checklist for a release candidate. The [release verification reference](verification.md) defines each test row. The [Tier 3 evidence reference](verification-live.md) defines live evidence.

## Run the campaign, then open the release pull request

One pull request carries the version bump and the campaign that proves it. The order matters, and it is the one thing about this flow that is not obvious.

The receipt names the commit the campaign ran against, and the gate requires that commit to be an ancestor of the release commit. A squash merge does not put a branch commit into `main`'s history, so a campaign run on the release branch records a commit the release can never contain. The campaign therefore runs against `origin/main` itself, before the branch exists.

> [!IMPORTANT]
> The release pull request must change no evidence input. It changes `package.json:version`, which is exempt, plus `docs/evidence/`, `docs/evidence/archive/`, and `docs/client-compatibility.md`, none of which is an input. A Tier 1 row in [the release verification reference](verification.md) is an input, so it lands with the change that introduced the surface, never in the release pull request.

1. Fetch `origin/main` and check it out with a clean tree. This is the commit the campaign proves and the commit the branch will start from.

## Run the source and package gates

Still on that clean `origin/main` checkout.

1. Record the commit the campaign will name:

   ```bash
   git rev-parse HEAD
   ```

2. Run the source checks:

   ```bash
   pnpm run typecheck
   pnpm run check:lines
   pnpm run check:seams
   pnpm run check:deps
   pnpm test
   pnpm run build
   ```

3. Confirm that `test/e2e-mcp-sdk.test.ts` completes registration, authorization, token exchange, the protected `/mcp` call, and refresh. It must replay the first family's consumed token and confirm that the successor is dead. It must then create a second family, revoke that family while it is active, and confirm that its refresh token is refused.
4. Start disposable MySQL and Redis services.
5. Run the release matrix with their connection URLs:

   ```bash
   RUN_INTEGRATION=true MYSQL_URL='mysql://…' REDIS_URL='redis://…' pnpm run test:release
   ```

   The command rebuilds the current tree after checking the required service variables and before running any matrix row.

6. Confirm that every `RM.N` row passes. A missing service variable, missing evidence file, skipped selected test, undocumented row, removed export, or removed example makes the command fail.
7. Run `npm pack --dry-run`.
8. Confirm that the tarball root contains only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`.

## Record the campaign

The rehearsal checks its 19 rows. Seven rows of [`scripts/live/CHECKLIST.md`](../scripts/live/CHECKLIST.md) it may not drive, because their web applications forbid an automated browser: the Google sign-ins A3 and B3, and the hosted connectors C1, C2, and F1 to F3. You drive those yourself, after the rehearsal has finished and released its tunnel.

Start the services and run the rehearsal:

```bash
docker run -d --rm --name rehearsal-mysql -e MYSQL_ROOT_PASSWORD=rootpw -e MYSQL_DATABASE=mcp_sso -e MYSQL_USER=mcp -e MYSQL_PASSWORD=mcppw -p 127.0.0.1:3306:3306 mysql:8.4
docker run -d --rm --name rehearsal-redis -p 127.0.0.1:6379:6379 redis:7-alpine
RUN_INTEGRATION=true MYSQL_URL='mysql://mcp:mcppw@127.0.0.1:3306/mcp_sso' REDIS_URL='redis://127.0.0.1:6379' \
  node scripts/live/rehearsal.mjs
```

> [!IMPORTANT]
> The three service variables are required. The `release-matrix` row reads them from the environment, and without them it is `BLOCKED release_services_absent`, the run exits 1, and nothing it produced is evidence.

`rehearsal.mjs` brings up each leg through `serve.sh`, runs its 19 rows, and writes `.live-state/receipt.json`. It exits 0 only when every row passed on a clean tree. It stops every leg it started before it exits, and it never serves the Google leg, so the rows you drive need their own.

Serve all three legs and drive the seven rows from `CHECKLIST.md`:

```bash
scripts/live/serve.sh cloudflare_access entra google
```

> [!WARNING]
> Do not start this while the rehearsal is running. Two `serve.sh` invocations on one tunnel split the traffic, and the rehearsal refuses a generation as `BLOCKED tunnel_already_served` when a public hostname already answers.

Stop it when the seven rows pass, then record the campaign. Recording needs no leg:

```bash
node scripts/live/record-receipt.mjs --receipt .live-state/receipt.json \
  --row A3 --row B3 --row C1 --row C2 --row F1 --row F2 --row F3 --write
```

> [!IMPORTANT]
> A `--row` names a row you drove and that passed. All seven are required, because they are the whole of what no probe may drive. Recording fewer is refused, and so is a row the rehearsal already checked or a row that is not on the checklist at all.

`record-receipt.mjs` writes `docs/evidence/release.json` naming the `origin/main` commit you are standing on, moves the receipt it supersedes to `docs/evidence/archive/`, and prints what the campaign observed in the words [`docs/client-compatibility.md`](client-compatibility.md) uses. It refuses to write a receipt whose commit is not an ancestor of `origin/main`, so a campaign run on a branch fails here rather than after the squash merge has thrown that commit away.

Do not use a live result as the only evidence for a security property.

## Open the release pull request

1. Branch from the commit the campaign just named.
2. Bump the version.
3. Commit `docs/evidence/release.json`, the receipt it superseded under `docs/evidence/archive/`, and the [`client-compatibility.md`](client-compatibility.md) update.
4. Change nothing else. Every other evidence input would age the receipt you just recorded, and the pull request would refuse its own release.
5. Push the branch and open the pull request.

Do not use a live result as the only evidence for a security property.

Run the evidence gates after recording the campaign:

```bash
pnpm run check:release-matrix
pnpm run check:release-ready
```

The commands name a malformed matrix row, non-ancestor runtime commit, missing export row, or stale evidence commit. Neither reads a version out of a document: tag and package agreement is checked at publish time against the tag you push.

A receipt goes stale when something that changes what a client would observe, or what produced the evidence, moved after its commit: `src/`, `examples/`, `test/`, `scripts/live/`, the release-matrix scripts, `docs/verification.md`, the TypeScript configuration, the lockfiles, the publish workflow, or a runtime field of `package.json`. The version is the exception, and it is why the bump and the campaign proving it ride in one pull request: nothing a client observes over the OAuth and MCP endpoints changes when the version string changes. For stale evidence, the default output shows changed-input counts and categories. Run `pnpm run check:release-ready --verbose` to list every changed input. Do not create the tag while either command fails.

## Merge the release pull request

1. Confirm the pull request carries the version bump, `docs/evidence/release.json`, the receipt it superseded under `docs/evidence/archive/`, and the [`client-compatibility.md`](client-compatibility.md) update.
2. Wait for the hosted `typecheck · lines · test · build` and `process-guard` checks to pass on the current head.
3. Read every review and inline thread.
4. Confirm that the Codex review contains `Reviewed commit: <head sha>` for the pull request's current head. A reaction or an older review does not satisfy this step.
5. Merge it into `main`.
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

1. Confirm that the tag is `v${package.version}`. `.github/workflows/publish.yml` re-checks this in its `build` job and fails the run before any install, build, pack, or publish step, so a mismatched tag cannot reach npm. Confirming it here avoids a failed run and a tag you then have to delete and re-push.
2. Push the tag. Do not create the GitHub Release first.
3. Confirm that the build job creates one tarball and one SHA-256 file.
4. Confirm that the OIDC job publishes that digest-verified tarball without a checkout, dependency installation, or repository scripts.
5. Confirm that the GitHub Release job starts only after npm publication succeeds.
6. Edit the generated GitHub Release with hand-written release notes.
