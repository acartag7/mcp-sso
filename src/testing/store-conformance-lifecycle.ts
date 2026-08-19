// StorePort conformance — expiry collection, configured-clock binding, close, and store-instance identity.
// One section of the suite in `store-conformance.ts` (contracts §12); adapters
// run every section through `runStoreConformance`, never a section alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FUTURE, NOW, PAST, refresh, settleUntil, startExpiryCollection, STORE_EXPIRY_SWEEP_INTERVAL_MS, type MakeStore, type StoreConformanceOptions,
} from "./store-conformance-fixtures.ts";

export function registerLifecycleRows(label: string, make: MakeStore, options: StoreConformanceOptions = {}): void {
  test(`${label}: expiry collection starts after configured-clock binding`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.parse(NOW) });
    const store = await make();
    const expiredJti = `scheduled-expired-${label}`;
    const activeJti = `scheduled-active-${label}`;
    const expiredToken = refresh(`scheduled-expired-token-${label}`, `scheduled-expired-family-${label}`, null, PAST);
    const activeToken = refresh(`scheduled-active-token-${label}`, `scheduled-active-family-${label}`, null, FUTURE);
    try {
      assert.equal(await store.consumeConsentJti(expiredJti, PAST), true);
      assert.equal(await store.consumeConsentJti(activeJti, FUTURE), true);
      await store.saveRefreshToken(expiredToken);
      await store.saveRefreshToken(activeToken);
      startExpiryCollection(store, { nowMs: () => Date.now() }, options);

      t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
      let expiredJtiCollected = false;
      let expiredFamilyCollected = false;
      for (let attempt = 0; attempt < 100 && (!expiredJtiCollected || !expiredFamilyCollected); attempt++) {
        if (!expiredJtiCollected) expiredJtiCollected = await store.consumeConsentJti(expiredJti, FUTURE);
        expiredFamilyCollected = await store.findRefreshToken(expiredToken.tokenHash) === null;
        if (!expiredJtiCollected || !expiredFamilyCollected) {
          await new Promise<void>((resolve) => setImmediate(resolve));
        }
      }
      assert.equal(expiredJtiCollected, true, "the store never self-collected an expired consent JTI");
      assert.equal(expiredFamilyCollected, true, "the store never self-collected an expired refresh family");
      assert.equal(await store.consumeConsentJti(activeJti, FUTURE), false, "the scheduler collected a live JTI");
      assert.equal((await store.findRefreshToken(activeToken.tokenHash))?.tokenHash, activeToken.tokenHash);
    } finally {
      await store.close();
    }
  });

  test(`${label}: host time cannot collect a tombstone still valid to the configured clock`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.parse(NOW) });
    const store = await make();
    let configuredNow = Date.parse(NOW);
    const signedExpiry = new Date(configuredNow + STORE_EXPIRY_SWEEP_INTERVAL_MS + 1).toISOString();
    const jti = `scheduled-boundary-${label}`;
    const sweepExpired = store.sweepExpired.bind(store);
    let sweeps = 0;
    store.sweepExpired = async (nowIso) => {
      await sweepExpired(nowIso);
      sweeps += 1;
    };
    try {
      assert.equal(await store.consumeConsentJti(jti, signedExpiry), true);
      startExpiryCollection(store, { nowMs: () => configuredNow }, options);
      t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
      await settleUntil(() => sweeps === 1);
      assert.equal(
        await store.consumeConsentJti(jti, signedExpiry),
        false,
        "the first scheduled sweep collected a tombstone while its signed JWT was still valid",
      );

      // The MySQL target resolves across multiple microtasks. Let the scheduler's
      // finally block install the next timer after the wrapped sweep increments.
      await new Promise<void>((resolve) => setImmediate(resolve));
      configuredNow += STORE_EXPIRY_SWEEP_INTERVAL_MS * 2 + 2;
      t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
      await settleUntil(() => sweeps === 2);
      assert.equal(
        await store.consumeConsentJti(jti, FUTURE),
        true,
        "a later sweep did not collect the expired tombstone",
      );
    } finally {
      await store.close();
    }
  });

  test(`${label}: close waits for an active expiry sweep and prevents later runs`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.parse(NOW) });
    const store = await make();
    let releaseSweep: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => { releaseSweep = resolve; });
    let calls = 0;
    store.sweepExpired = async () => { calls += 1; await blocked; };
    startExpiryCollection(store, { nowMs: () => Date.now() }, options);
    t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
    await settleUntil(() => calls === 1);

    let closed = false;
    const closing = store.close().then(() => { closed = true; });
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(closed, false, "close returned before its active sweep settled");
    releaseSweep?.();
    await closing;
    t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
    assert.equal(calls, 1, "a closed store began another sweep");
    await assert.rejects(store.findRefreshToken("unused"), /Store is closed/);
  });

  test(`${label}: store instance binding is stable for one logical store`, async () => {
    const store = await make();
    const getStoreInstanceId = store.getStoreInstanceId?.bind(store);
    assert.ok(getStoreInstanceId);
    const first = await getStoreInstanceId();
    const second = await getStoreInstanceId();
    assert.match(first, /^[A-Za-z0-9_-]{22,128}$/u);
    assert.equal(second, first);
    await store.close();
  });

  test(`${label}: store instance binding rotation is atomic and durable`, async () => {
    const store = await make();
    const get = store.getStoreInstanceId?.bind(store);
    const rotate = store.rotateStoreInstanceId?.bind(store);
    assert.ok(get);
    assert.ok(rotate);
    const before = await get();
    const rotated = await rotate();
    assert.match(rotated, /^[A-Za-z0-9_-]{22,128}$/u);
    assert.notEqual(rotated, before);
    assert.equal(await get(), rotated);
    await store.close();
  });
}
