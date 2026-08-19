// StorePort conformance — refresh rotation, replay revocation, and exact resource binding.
// One section of the suite in `store-conformance.ts` (contracts §12); adapters
// run every section through `runStoreConformance`, never a section alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import { StoreInputError, UNBOUND_REFRESH_RESOURCE } from "../ports/store.ts";
import type { SaveRefreshTokenInput } from "../ports/store.ts";
import { FUTURE, LATER, NOW, RESOURCE_A, RESOURCE_B, refresh, sha256Hex, type MakeStore } from "./store-conformance-fixtures.ts";

export function registerRefreshRows(label: string, make: MakeStore): void {
  test(`${label}: rotates refresh tokens and replay revokes the family`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("one", "fam-1", null, FUTURE));
    const rotated = await store.rotateRefreshToken(sha256Hex("one"), refresh("two", "fam-1", sha256Hex("one"), FUTURE), NOW);
    assert.equal(rotated?.tokenHash, sha256Hex("one"));
    // replay of the consumed token -> null (and revokes the family)
    assert.equal(await store.rotateRefreshToken(sha256Hex("one"), refresh("three", "fam-1", sha256Hex("one"), FUTURE), LATER), null);
    // the rotated successor can no longer rotate either (family revoked) -> null
    assert.equal(await store.rotateRefreshToken(sha256Hex("two"), refresh("four", "fam-1", sha256Hex("two"), FUTURE), LATER), null);
    await store.close();
  });

  test(`${label}: an omitted untyped resource persists unbound and cannot rotate`, async () => {
    const store = await make();
    const legacy = refresh("unbound-source", "fam-unbound", null, FUTURE) as { resource?: string } & Omit<SaveRefreshTokenInput, "resource">;
    delete legacy.resource;
    await store.saveRefreshToken(legacy as SaveRefreshTokenInput);
    assert.equal((await store.findRefreshToken(sha256Hex("unbound-source")))?.resource, UNBOUND_REFRESH_RESOURCE);
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("unbound-source"),
        refresh("unbound-successor", "fam-unbound", sha256Hex("unbound-source"), FUTURE),
        NOW,
        undefined,
        RESOURCE_A,
      ),
      null,
      "the compatibility marker cannot be rebound through a live bridge resource",
    );
    assert.equal((await store.findRefreshToken(sha256Hex("unbound-source")))?.resource, UNBOUND_REFRESH_RESOURCE);
    await store.close();
  });

  test(`${label}: an omitted untyped successor resource is normalized and cannot replace the stored resource`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("untyped-next-source", "fam-untyped-next", null, FUTURE));
    const next = refresh("untyped-next-successor", "fam-untyped-next", sha256Hex("untyped-next-source"), FUTURE) as { resource?: string } & Omit<SaveRefreshTokenInput, "resource">;
    delete next.resource;
    const rotated = await store.rotateRefreshToken(
      sha256Hex("untyped-next-source"),
      next as SaveRefreshTokenInput,
      NOW,
      undefined,
      RESOURCE_A,
    );
    assert.equal(rotated?.resource, RESOURCE_A);
    assert.equal((await store.findRefreshToken(sha256Hex("untyped-next-successor")))?.resource, RESOURCE_A);
    await store.close();
  });

  test(`${label}: refresh resource binding rejects substitution without mutating the family`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("resource-source", "fam-resource", null, FUTURE, undefined, RESOURCE_A));
    const wrong = await store.rotateRefreshToken(
      sha256Hex("resource-source"),
      refresh("resource-wrong", "fam-resource", sha256Hex("resource-source"), FUTURE, undefined, RESOURCE_B),
      NOW,
      undefined,
      RESOURCE_B,
    );
    assert.equal(wrong, null, "wrong resource is indistinguishable from invalid_grant");
    assert.equal((await store.findRefreshToken(sha256Hex("resource-source")))?.resource, RESOURCE_A);
    const correct = await store.rotateRefreshToken(
      sha256Hex("resource-source"),
      refresh("resource-correct", "fam-resource", sha256Hex("resource-source"), FUTURE, undefined, RESOURCE_A),
      NOW,
      undefined,
      RESOURCE_A,
    );
    assert.equal(correct?.resource, RESOURCE_A, "correct resource rotates once");
    assert.equal((await store.findRefreshToken(sha256Hex("resource-correct")))?.resource, RESOURCE_A, "successor copied stored resource");
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("resource-source"),
        refresh("resource-replay", "fam-resource", sha256Hex("resource-source"), FUTURE, undefined, RESOURCE_A),
        LATER,
        undefined,
        RESOURCE_A,
      ),
      null,
      "correct-resource replay still revokes the family",
    );
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("resource-correct"),
        refresh("resource-after-replay", "fam-resource", sha256Hex("resource-correct"), FUTURE, undefined, RESOURCE_A),
        LATER,
        undefined,
        RESOURCE_A,
      ),
      null,
      "replay revocation still disables the successor",
    );
    await store.close();
  });

  test(`${label}: family and token resource strings cannot diverge`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("resource-family-a", "fam-resource-invariant", null, FUTURE, undefined, RESOURCE_A));
    await assert.rejects(
      store.saveRefreshToken(refresh("resource-family-b", "fam-resource-invariant", null, FUTURE, undefined, RESOURCE_B)),
      (error: unknown) => error instanceof StoreInputError,
    );
    assert.equal((await store.findRefreshToken(sha256Hex("resource-family-a")))?.resource, RESOURCE_A);
    assert.equal(await store.findRefreshToken(sha256Hex("resource-family-b")), null, "divergent token row was not inserted");
    await store.close();
  });

  test(`${label}: rotation copies the exact stored resource string over a successor input`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("resource-copy-source", "fam-resource-copy", null, FUTURE, undefined, RESOURCE_A));
    const rotated = await store.rotateRefreshToken(
      sha256Hex("resource-copy-source"),
      refresh("resource-copy-successor", "fam-resource-copy", sha256Hex("resource-copy-source"), FUTURE, undefined, RESOURCE_B),
      NOW,
      undefined,
      RESOURCE_A,
    );
    assert.equal(rotated?.resource, RESOURCE_A);
    assert.equal((await store.findRefreshToken(sha256Hex("resource-copy-successor")))?.resource, RESOURCE_A);
    await store.close();
  });

  test(`${label}: concurrent resource A/B rotation permits only the bound resource`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("resource-race", "fam-resource-race", null, FUTURE, undefined, RESOURCE_A));
    const [wrong, correct] = await Promise.all([
      store.rotateRefreshToken(
        sha256Hex("resource-race"),
        refresh("resource-race-b", "fam-resource-race", sha256Hex("resource-race"), FUTURE, undefined, RESOURCE_B),
        NOW,
        undefined,
        RESOURCE_B,
      ),
      store.rotateRefreshToken(
        sha256Hex("resource-race"),
        refresh("resource-race-a", "fam-resource-race", sha256Hex("resource-race"), FUTURE, undefined, RESOURCE_A),
        NOW,
        undefined,
        RESOURCE_A,
      ),
    ]);
    assert.equal(wrong, null, "wrong resource cannot win the race");
    assert.equal(correct?.resource, RESOURCE_A, "bound resource wins the race");
    assert.ok(await store.rotateRefreshToken(
      sha256Hex("resource-race-a"),
      refresh("resource-race-a2", "fam-resource-race", sha256Hex("resource-race-a"), FUTURE, undefined, RESOURCE_A),
      LATER,
      undefined,
      RESOURCE_A,
    ), "wrong-resource contender did not revoke the correctly rotated family");
    await store.close();
  });
}
