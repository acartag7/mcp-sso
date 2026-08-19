// StorePort conformance — timestamp validation and the sweep-retention boundaries (addenda 8 and 10).
// One section of the suite in `store-conformance.ts` (contracts §12); adapters
// run every section through `runStoreConformance`, never a section alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import { StoreInputError } from "../ports/store.ts";
import { NOW, refresh, sha256Hex, type MakeStore } from "./store-conformance-fixtures.ts";

export function registerSweepRows(label: string, make: MakeStore): void {
  test(`${label}: consumeConsentJti rejects a non-3-ms timestamp (addendum 10)`, async () => {
    const store = await make();
    await assert.rejects(store.consumeConsentJti("jti", "not-a-timestamp"), (e: unknown) => e instanceof StoreInputError);
    await assert.rejects(store.consumeConsentJti("jti", "2026-07-03T13:00:00Z"), (e: unknown) => e instanceof StoreInputError); // no ms
    await assert.rejects(store.consumeConsentJti("jti", "2026-07-03T13:00:00.00Z"), (e: unknown) => e instanceof StoreInputError); // 2 digits
    assert.equal(await store.consumeConsentJti("ok", "2026-07-03T13:00:00.000Z"), true); // 3 ms accepted
    await store.close();
  });

  test(`${label}: sweep retains a consumed predecessor while its successor is valid (addendum 8)`, async () => {
    const store = await make();
    const early = "2026-07-03T12:30:00.000Z"; // predecessor expiry
    const late = "2026-07-03T13:00:00.000Z"; // successor expiry (outlives predecessor)
    await store.saveRefreshToken(refresh("pred", "fam-succ", null, early));
    const rotated = await store.rotateRefreshToken(sha256Hex("pred"), refresh("succ", "fam-succ", sha256Hex("pred"), late), NOW);
    assert.ok(rotated, "rotation succeeds");
    // sweep AFTER the predecessor expired but BEFORE the successor -> predecessor retained
    await store.sweepExpired("2026-07-03T12:45:00.000Z");
    assert.ok(await store.findRefreshToken(sha256Hex("pred")), "predecessor directly verified retained after sweep");
    const replay = await store.rotateRefreshToken(sha256Hex("pred"), refresh("p2", "fam-succ", sha256Hex("pred"), late), "2026-07-03T12:45:00.000Z");
    assert.equal(replay, null, "predecessor replay detected -> family revoked");
    const after = await store.rotateRefreshToken(sha256Hex("succ"), refresh("s2", "fam-succ", sha256Hex("succ"), late), "2026-07-03T12:45:00.000Z");
    assert.equal(after, null, "successor is dead after the family was revoked");
    await store.close();
  });

  test(`${label}: sweep deletes a family only once every member is past validity`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("only", "fam-only", null, "2026-07-03T12:30:00.000Z"));
    await store.sweepExpired("2026-07-03T12:45:00.000Z"); // past the only token's expiry
    // Directly verify sweep actually deleted the row — `rotate ... === null` alone cannot
    // distinguish "swept (row gone)" from "not swept (row expired, rotate rejected)".
    assert.equal(await store.findRefreshToken(sha256Hex("only")), null, "swept token must be deleted");
    // family fully GC'd -> a later replay is undetected (accepted boundary, addendum 8)
    const replay = await store.rotateRefreshToken(sha256Hex("only"), refresh("o2", "fam-only", sha256Hex("only"), "2026-07-03T13:00:00.000Z"), "2026-07-03T12:45:00.000Z");
    assert.equal(replay, null, "post-validity replay is undetected (rows GC'd) — accepted boundary");
    await store.close();
  });

  test(`${label}: sweep treats expires_at == now as still-valid (boundary, addendum 8)`, async () => {
    const store = await make();
    // a token expiring EXACTLY at the sweep instant is a still-valid family member
    await store.saveRefreshToken(refresh("edge", "fam-edge", null, NOW));
    await store.sweepExpired(NOW);
    assert.ok(await store.findRefreshToken(sha256Hex("edge")), "expires_at == now survives (>= now is still-valid)");
    await store.close();
  });
}
