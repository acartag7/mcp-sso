// StorePort conformance — consent approval, authorization codes, and single-use consent JTIs.
// One section of the suite in `store-conformance.ts` (contracts §12); adapters
// run every section through `runStoreConformance`, never a section alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError,
} from "../ports/store.ts";
import { authCode, FUTURE, NOW, PAST, sha256Hex, type MakeStore, type StoreConformanceOptions, } from "./store-conformance-fixtures.ts";

export function registerGrantRows(label: string, make: MakeStore, _options: StoreConformanceOptions = {}): void {
  test(`${label}: consent approval atomically binds JTI and authorization code`, async () => {
    const store = await make();
    const binding = await store.getStoreInstanceId();
    const input = authCode("atomic-consent-code", FUTURE);
    assert.equal(await store.commitConsentApproval(binding, "atomic-jti", FUTURE, input), "stored");
    assert.equal(await store.commitConsentApproval(binding, "atomic-jti", FUTURE, authCode("replay-code", FUTURE)), "replayed");
    assert.equal((await store.consumeAuthCode(input.codeHash, NOW))?.codeHash, input.codeHash);
    const staleBinding = binding;
    await store.rotateStoreInstanceId();
    const rejected = authCode("stale-binding-code", FUTURE);
    assert.equal(
      await store.commitConsentApproval(staleBinding, "stale-binding-jti", FUTURE, rejected),
      "binding_mismatch",
    );
    assert.equal(await store.consumeAuthCode(rejected.codeHash, NOW), null, "binding rejection stores no code");
    assert.equal(await store.consumeConsentJti("stale-binding-jti", FUTURE), true, "binding rejection consumes no JTI");
    await store.close();
  });

  test(`${label}: auth codes are hashed, single-use, expire`, async () => {
    const store = await make();
    const raw = "raw-auth-code-secret";
    await store.saveAuthCode(authCode(raw, FUTURE));
    const consumed = await store.consumeAuthCode(sha256Hex(raw), NOW);
    assert.equal(consumed?.codeHash, sha256Hex(raw));
    assert.deepEqual(consumed?.scopes, ["mcp:read"]);
    assert.equal(await store.consumeAuthCode(sha256Hex(raw), NOW), null); // single-use
    await store.saveAuthCode(authCode("expired-raw", PAST));
    assert.equal(await store.consumeAuthCode(sha256Hex("expired-raw"), NOW), null); // expired
    await assert.rejects(
      store.saveAuthCode({ ...authCode("bad", FUTURE), codeHash: "not-a-hash" }),
      (e: unknown) => e instanceof StoreInputError,
    );
    await store.close();
  });

  // §12.2 invariant 13: stored rows own their scopes array on write and on read.
  test(`${label}: stored rows own their scopes array against the caller and the returned record`, async () => {
    const store = await make();
    const input = authCode("detached-auth-code", FUTURE);
    const callerScopes = input.scopes;
    await store.saveAuthCode(input);
    callerScopes.push("mcp:late");
    const consumed = await store.consumeAuthCode(input.codeHash, NOW);
    assert.ok(consumed, "the code was stored");
    assert.deepEqual(consumed.scopes, ["mcp:read"], "caller mutation after save must not reach the stored code");
    consumed.scopes.push("mcp:late");
    assert.equal(await store.consumeAuthCode(input.codeHash, NOW), null, "single-use semantics unchanged");

    const binding = await store.getStoreInstanceId();
    const consentInput = authCode("detached-consent-code", FUTURE);
    const consentScopes = consentInput.scopes;
    assert.equal(
      await store.commitConsentApproval(binding, "detached-consent-jti", FUTURE, consentInput), "stored");
    consentScopes.push("mcp:late");
    const consented = await store.consumeAuthCode(consentInput.codeHash, NOW);
    assert.ok(consented, "the consented code was stored");
    assert.deepEqual(consented.scopes, ["mcp:read"], "caller mutation after consent must not reach the stored code");
    await store.close();
  });

  test(`${label}: stored-DCR generation rejects and burns legacy auth codes`, async () => {
    const store = await make();
    assert.equal(store.storedDcrGrantGeneration, STORED_DCR_GRANT_GENERATION);
    assert.equal(store.storedDcrResourceBinding, STORED_DCR_RESOURCE_BINDING);
    await store.saveAuthCode(authCode("generation-current", FUTURE, STORED_DCR_GRANT_GENERATION));
    assert.equal(
      (await store.consumeAuthCode(sha256Hex("generation-current"), NOW, STORED_DCR_GRANT_GENERATION))?.grantGeneration,
      STORED_DCR_GRANT_GENERATION,
    );
    await store.saveAuthCode(authCode("generation-legacy", FUTURE, null));
    assert.equal(await store.consumeAuthCode(sha256Hex("generation-legacy"), NOW, STORED_DCR_GRANT_GENERATION), null);
    assert.equal(await store.consumeAuthCode(sha256Hex("generation-legacy"), NOW), null, "legacy code was burned");
    await store.saveAuthCode(authCode("generation-other", FUTURE, 2));
    assert.equal(await store.consumeAuthCode(sha256Hex("generation-other"), NOW, STORED_DCR_GRANT_GENERATION), null);
    await store.close();
  });

  test(`${label}: auth-code resource mismatch returns null without consuming the code`, async () => {
    const store = await make();
    const raw = "resource-bound-code";
    const resourceA = "https://resource-a.test/mcp";
    const resourceB = "https://resource-b.test/mcp";
    await store.saveAuthCode({ ...authCode(raw, FUTURE), resource: resourceA });
    assert.equal(
      await store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceB),
      null,
      "wrong resource is rejected",
    );
    assert.equal(
      (await store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceA))?.resource,
      resourceA,
      "the legitimate resource can still consume the code",
    );
    assert.equal(await store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceA), null, "replay fails");
    await store.close();
  });

  test(`${label}: concurrent matching and mismatching resource consumes allow only the matching call`, async () => {
    const store = await make();
    const raw = "resource-race-code";
    const resourceA = "https://resource-a.test/mcp";
    const resourceB = "https://resource-b.test/mcp";
    await store.saveAuthCode({ ...authCode(raw, FUTURE), resource: resourceA });
    const [wrong, right] = await Promise.all([
      store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceB),
      store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceA),
    ]);
    assert.equal(wrong, null, "wrong resource never wins");
    assert.equal(right?.resource, resourceA, "matching resource consumes exactly once");
    assert.equal(await store.consumeAuthCode(sha256Hex(raw), NOW, undefined, resourceA), null, "winner consumed the code");
    await store.close();
  });

  test(`${label}: consent jti is single-use`, async () => {
    const store = await make();
    assert.equal(await store.consumeConsentJti("jti-1", FUTURE), true);
    assert.equal(await store.consumeConsentJti("jti-1", FUTURE), false); // replay
    assert.equal(await store.consumeConsentJti("jti-2", FUTURE), true);
    await store.close();
  });

  test(`${label}: consent jti survives sweep through its supplied signed expiry`, async () => {
    const store = await make();
    const expiresAt = "2026-07-03T12:30:00.000Z";
    assert.equal(await store.consumeConsentJti("signed-exp-jti", expiresAt), true);
    await store.sweepExpired("2026-07-03T12:29:59.999Z");
    assert.equal(await store.consumeConsentJti("signed-exp-jti", expiresAt), false, "pre-expiry sweep retains replay signal");
    await store.sweepExpired(expiresAt);
    assert.equal(await store.consumeConsentJti("signed-exp-jti", expiresAt), false, "expiry-boundary sweep retains replay signal");
    await store.sweepExpired("2026-07-03T12:30:00.001Z");
    assert.equal(await store.consumeConsentJti("signed-exp-jti", expiresAt), false, "sweep fence rejects the collected replay expiry");
    assert.equal(await store.consumeConsentJti("signed-exp-jti", FUTURE), true, "post-expiry sweep collected the tombstone");
    await store.close();
  });

  test(`${label}: sweep fence blocks approval after physical JTI collection`, async () => {
    const store = await make();
    const consentExpiry = "2026-07-03T12:30:00.000Z";
    const code = authCode(`sweep-fence-code-${label}`, FUTURE);
    const binding = await store.getStoreInstanceId();
    await store.sweepExpired("2026-07-03T12:30:00.001Z");
    assert.equal(
      await store.commitConsentApproval(binding, `sweep-fence-jti-${label}`, consentExpiry, code),
      "replayed",
    );
    assert.equal(await store.consumeAuthCode(code.codeHash, NOW), null, "fenced approval stored no code");
    await store.close();
  });
}
