import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { verifyLocalDependencyPolicy } from "../scripts/check-dependency-policy.mjs";
import { FAST_URI_PIN, fixture, makeTransitiveException, makeTransitivePinYoung, NOW, replace, stripTransitiveException } from "./dependency-policy-fixtures.mjs";

/** Any stable version that is not the recorded pin, for stale-resolution drift. */
const STALE_VERSION = "0.0.1";

test("ordinary transitive pin binds the workspace override and lockfile resolution", async () => {
  const root = await fixture();
  await verifyLocalDependencyPolicy(root, NOW);
});

test("ordinary transitive pin rejects a disconnected workspace override", async () => {
  const root = await fixture();
  await replace(join(root, "pnpm-workspace.yaml"), `  fast-uri: ${FAST_URI_PIN}\n`, "");
  await assert.rejects(verifyLocalDependencyPolicy(root, NOW), (error) => {
    assert.ok(error.message.includes(`fast-uri: workspace override undefined != transitive pin ${FAST_URI_PIN}`));
    return true;
  });
});

test("ordinary transitive pin rejects a stale lockfile resolution", async () => {
  const root = await fixture();
  const lockfile = join(root, "pnpm-lock.yaml");
  await replace(lockfile, `  fast-uri@${FAST_URI_PIN}:\n`, `  fast-uri@${STALE_VERSION}:\n`);
  await replace(lockfile, `  fast-uri@${FAST_URI_PIN}: {}`, `  fast-uri@${STALE_VERSION}: {}`);
  await assert.rejects(verifyLocalDependencyPolicy(root, NOW), (error) => {
    assert.ok(error.message.includes(`fast-uri: lockfile resolutions ${STALE_VERSION} != transitive pin ${FAST_URI_PIN}`));
    return true;
  });
});

// Ledger rule 2: "Published-advisory fixes do not wait", for a package this
// repository resolves "directly pinned or transitive". The direct half was
// enforced; the transitive half was not, so a validated transitive advisory
// exception could never actually waive the floor it exists to waive.
test("a transitive advisory exception waives the age floor", async () => {
  const root = await fixture();
  await makeTransitivePinYoung(root);
  await makeTransitiveException(root);
  await verifyLocalDependencyPolicy(root, NOW);
});

test("a young transitive pin without an advisory exception still fails the age floor", async () => {
  const root = await fixture();
  await stripTransitiveException(root);
  const { youngPublished } = await makeTransitivePinYoung(root);
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    (error) => {
      assert.match(error.message, /^- fast-uri: .* is younger than 15 days$/m);
      assert.ok(error.message.includes(`fast-uri: ${youngPublished} `));
      return true;
    },
  );
});
