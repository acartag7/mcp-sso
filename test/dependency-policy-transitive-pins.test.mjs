import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { verifyLocalDependencyPolicy } from "../scripts/check-dependency-policy.mjs";
import { fixture, NOW, replace } from "./dependency-policy-fixtures.mjs";

test("ordinary transitive pin binds the workspace override and lockfile resolution", async () => {
  const root = await fixture();
  await verifyLocalDependencyPolicy(root, NOW);
});

test("ordinary transitive pin rejects a disconnected workspace override", async () => {
  const root = await fixture();
  await replace(join(root, "pnpm-workspace.yaml"), "  fast-uri: 3.1.5\n", "");
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    /fast-uri: workspace override undefined != transitive pin 3\.1\.5/,
  );
});

test("ordinary transitive pin rejects a stale lockfile resolution", async () => {
  const root = await fixture();
  const lockfile = join(root, "pnpm-lock.yaml");
  await replace(lockfile, "  fast-uri@3.1.5:\n", "  fast-uri@3.1.4:\n");
  await replace(lockfile, "  fast-uri@3.1.5: {}", "  fast-uri@3.1.4: {}");
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    /fast-uri: lockfile resolutions 3\.1\.4 != transitive pin 3\.1\.5/,
  );
});
