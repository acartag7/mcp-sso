import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { verifyLocalDependencyPolicy } from "../scripts/check-dependency-policy.mjs";
import { FAST_URI_PIN, fixture, NOW, replace } from "./dependency-policy-fixtures.mjs";

/** Any stable version that is not the recorded pin, for stale-resolution drift. */
const STALE_VERSION = "0.0.1";

test("ordinary transitive pin binds the workspace override and lockfile resolution", async () => {
  const root = await fixture();
  await verifyLocalDependencyPolicy(root, NOW);
});

test("ordinary transitive pin rejects a disconnected workspace override", async () => {
  const root = await fixture();
  await replace(join(root, "pnpm-workspace.yaml"), `  fast-uri: ${FAST_URI_PIN}\n`, "");
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    new RegExp(`fast-uri: workspace override undefined != transitive pin ${FAST_URI_PIN}`),
  );
});

test("ordinary transitive pin rejects a stale lockfile resolution", async () => {
  const root = await fixture();
  const lockfile = join(root, "pnpm-lock.yaml");
  await replace(lockfile, `  fast-uri@${FAST_URI_PIN}:\n`, `  fast-uri@${STALE_VERSION}:\n`);
  await replace(lockfile, `  fast-uri@${FAST_URI_PIN}: {}`, `  fast-uri@${STALE_VERSION}: {}`);
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    new RegExp(`fast-uri: lockfile resolutions ${STALE_VERSION} != transitive pin ${FAST_URI_PIN}`),
  );
});
