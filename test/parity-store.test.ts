// Class-level behavior of the fixture store: what the composition adds over the
// pure operations it delegates to. The instance binding, the shared consent
// replay watermark, the expiry lifecycle, the closed guard, and the projection
// a full flow leaves behind.

import assert from "node:assert/strict";
import test from "node:test";
import type { SaveAuthCodeInput, SaveRefreshTokenInput } from "../src/ports/store.ts";
import { StoreInputError } from "../src/ports/store.ts";
import { STORE_EXPIRY_SWEEP_INTERVAL_MS } from "../src/store/expiry-scheduler.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";

const SUBJECT = "fixture-subject";
const CLIENT_ID = "fixture-client";
const RESOURCE = "https://api.example.com/mcp";
const REDIRECT = "http://127.0.0.1:8123/callback";
const REGISTERED = "mcpdc_0123456789abcdef0123456789abcdef";
const BOUND_INSTANCE = "Kd9tR2wLxQ7pZm4Vb1Ns6A";
const T0 = "2026-09-01T09:00:00.000Z";
const T1 = "2026-09-01T10:00:00.000Z";
const T2 = "2026-09-01T11:00:00.000Z";
const T3 = "2026-09-01T12:00:00.000Z";

function hash(prefix: string): string { return prefix.padEnd(64, "0"); }
const CODE_HASH = hash("aa");
const TOKEN_HASH = hash("bb");
const SUCCESSOR_HASH = hash("cc");

function approval(): SaveAuthCodeInput {
  return {
    codeHash: CODE_HASH, clientId: CLIENT_ID, subject: SUBJECT, redirectUri: REDIRECT,
    resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: "fixture-challenge",
    codeChallengeMethod: "S256", expiresAt: T2,
  };
}

function firstToken(): SaveRefreshTokenInput {
  return {
    tokenHash: TOKEN_HASH, familyId: "fixture-family", previousTokenHash: null,
    clientId: CLIENT_ID, subject: SUBJECT, resource: RESOURCE, scopes: ["mcp:read"], expiresAt: T3,
  };
}

function successor(): SaveRefreshTokenInput {
  return {
    tokenHash: SUCCESSOR_HASH, familyId: "fixture-family", previousTokenHash: TOKEN_HASH,
    clientId: CLIENT_ID, subject: SUBJECT, resource: RESOURCE, scopes: ["mcp:write"], expiresAt: T3,
  };
}

test("rotation changes the instance binding and invalidates approvals under the old one", async () => {
  const store = new FixtureStore({}, new SeededRandom("instance-rotation"));
  try {
    const initial = await store.getStoreInstanceId();
    assert.match(initial, /^[A-Za-z0-9_-]{22,128}$/u);
    const rotated = await store.rotateStoreInstanceId();
    assert.notEqual(rotated, initial);
    assert.equal(await store.getStoreInstanceId(), rotated);
    assert.deepEqual(store.snapshot().store_instance, [{ instance_id: rotated }]);
    assert.equal(
      await store.commitConsentApproval(initial, "fixture-jti", T1, approval()),
      "binding_mismatch",
    );
  } finally { await store.close(); }
});

test("an approval naming a malformed instance id is rejected before the binding is compared", async () => {
  const store = new FixtureStore({}, new SeededRandom("instance-admission"));
  try {
    await assert.rejects(
      store.commitConsentApproval("short", "fixture-jti", T1, approval()),
      (error: unknown) => error instanceof StoreInputError,
    );
    assert.equal(await store.consumeConsentJti("fixture-jti", T1), true, "the rejected approval consumed its jti");
  } finally { await store.close(); }
});

test("a hydrated instance id outside the StorePort shape fails at construction", () => {
  assert.throws(
    () => new FixtureStore({ store_instance: [{ instance_id: "short" }] }, new SeededRandom("instance-shape")),
    (error: unknown) => error instanceof StoreInputError,
  );
});

test("a hydrated instance binding is kept until it is rotated", async () => {
  const store = new FixtureStore(
    { store_instance: [{ instance_id: BOUND_INSTANCE }] },
    new SeededRandom("instance-kept"),
  );
  try {
    assert.equal(await store.getStoreInstanceId(), BOUND_INSTANCE);
    assert.deepEqual(store.snapshot().store_instance, [{ instance_id: BOUND_INSTANCE }]);
  } finally { await store.close(); }
});

test("a closed store rejects every StorePort and ClientStore method", async () => {
  const store = new FixtureStore({}, new SeededRandom("closed-store"));
  await store.close();
  await assert.rejects(store.getStoreInstanceId(), /Store is closed/);
  await assert.rejects(store.rotateStoreInstanceId(), /Store is closed/);
  await assert.rejects(store.commitConsentApproval(BOUND_INSTANCE, "fixture-jti", T1, approval()), /Store is closed/);
  await assert.rejects(store.saveAuthCode(approval()), /Store is closed/);
  await assert.rejects(store.consumeAuthCode(CODE_HASH, T0), /Store is closed/);
  await assert.rejects(store.consumeConsentJti("fixture-jti", T1), /Store is closed/);
  await assert.rejects(store.saveRefreshToken(firstToken()), /Store is closed/);
  await assert.rejects(store.rotateRefreshToken(TOKEN_HASH, successor(), T0), /Store is closed/);
  await assert.rejects(store.revokeRefreshTokenFamily("fixture-family", T0), /Store is closed/);
  await assert.rejects(store.findRefreshToken(TOKEN_HASH), /Store is closed/);
  await assert.rejects(store.findGrantedScopes(SUBJECT, CLIENT_ID, T0), /Store is closed/);
  await assert.rejects(store.sweepExpired(T1), /Store is closed/);
  assert.throws(() => store.startExpiryCollection({ nowMs: () => 0 }), /Store is closed/);
  await assert.rejects(store.save({
    clientId: REGISTERED, redirectUris: [REDIRECT], applicationType: "native", issuedAtEpoch: 0,
  }), /Store is closed/);
  await assert.rejects(store.find(REGISTERED), /Store is closed/);
  assert.deepEqual(store.snapshot().store_instance.length, 1, "snapshot serves cleanup diagnostics after close");
  await store.close();
});

test("close is idempotent and stops expiry collection", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.parse(T0) });
  const store = new FixtureStore({}, new SeededRandom("close-stops-collection"));
  const scheduled = store.sweepExpired.bind(store);
  let sweeps = 0;
  store.sweepExpired = async (nowIso) => { sweeps += 1; await scheduled(nowIso); };
  try {
    store.startExpiryCollection({ nowMs: () => Date.now() });
    t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
    for (let turn = 0; turn < 10 && sweeps === 0; turn += 1) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(sweeps, 1, "the scheduled sweep never ran");
    await store.close();
    await store.close();
    t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
    for (let turn = 0; turn < 10 && sweeps === 1; turn += 1) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(sweeps, 1, "a closed store kept collecting expired rows");
  } finally { await store.close(); }
});

test("sweepExpired raises the replay watermark a swept consent jti cannot pass", async () => {
  const store = new FixtureStore({}, new SeededRandom("sweep-watermark"));
  try {
    const instance = await store.getStoreInstanceId();
    assert.equal(await store.consumeConsentJti("fixture-jti", T1), true);
    await store.sweepExpired(T2);
    assert.equal(await store.consumeConsentJti("fixture-jti", T1), false);
    assert.equal(await store.consumeConsentJti("fixture-jti-later", T2), true);
    assert.equal(
      await store.commitConsentApproval(instance, "fixture-jti-swept", T1, approval()),
      "replayed",
    );
    assert.equal(
      await store.commitConsentApproval(instance, "fixture-jti-live", T2, approval()),
      "stored",
    );
  } finally { await store.close(); }
});

test("a chained fixture inherits the sweep an earlier member performed", async () => {
  const preState = { store_instance: [{ instance_id: BOUND_INSTANCE, swept_through: T2 }] };
  const store = new FixtureStore(preState, new SeededRandom("chain-fence"));
  try {
    assert.equal(await store.getStoreInstanceId(), BOUND_INSTANCE);
    assert.equal(await store.consumeConsentJti("jti-swept", T1), false,
      "a jti expiring before the inherited sweep is replayed");
    assert.equal(
      await store.commitConsentApproval(BOUND_INSTANCE, "jti-swept", T1, approval()),
      "replayed",
    );
    assert.equal(await store.consumeConsentJti("jti-live", T2), true);

    await store.sweepExpired(T3);
    const carried = store.snapshot().store_instance[0];
    assert.equal(carried?.swept_through, T3, "the member's own sweep is projected for the next member");
  } finally { await store.close(); }
});

test("the snapshot reflects a full authorize-to-refresh flow driven through the public methods", async () => {
  const store = new FixtureStore({}, new SeededRandom("authorize-to-refresh"));
  try {
    const instance = await store.getStoreInstanceId();
    await store.save({
      clientId: REGISTERED, redirectUris: [REDIRECT], applicationType: "native", issuedAtEpoch: 0,
    });
    assert.equal(await store.commitConsentApproval(instance, "fixture-jti", T1, approval()), "stored");
    assert.deepEqual(await store.consumeAuthCode(CODE_HASH, T0), {
      codeHash: CODE_HASH, clientId: CLIENT_ID, subject: SUBJECT, redirectUri: REDIRECT,
      resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: "fixture-challenge",
      codeChallengeMethod: "S256", expiresAt: T2, grantGeneration: 1,
    });
    await store.saveRefreshToken(firstToken());
    const rotated = await store.rotateRefreshToken(TOKEN_HASH, successor(), T0);
    assert.equal(rotated?.tokenHash, TOKEN_HASH);
    assert.deepEqual(await store.findGrantedScopes(SUBJECT, CLIENT_ID, T0), ["mcp:read"]);
    assert.deepEqual(store.snapshot(), {
      authorization_code: [],
      consent_jti: [{ jti: "fixture-jti", expires_at: T1 }],
      refresh_token: [
        {
          token_hash: TOKEN_HASH, family_id: "fixture-family", client_id: CLIENT_ID,
          subject: SUBJECT, resource: RESOURCE, scopes: ["mcp:read"], expires_at: T3,
          consumed_at: T0, grant_generation: 1,
        },
        {
          token_hash: SUCCESSOR_HASH, family_id: "fixture-family", previous_token_hash: TOKEN_HASH,
          client_id: CLIENT_ID, subject: SUBJECT, resource: RESOURCE, scopes: ["mcp:read"],
          expires_at: T3, grant_generation: 1,
        },
      ],
      revoked_family: [],
      client_registration: [{
        client_id: REGISTERED, redirect_uris: [REDIRECT], application_type: "native", issued_at_epoch: 0,
      }],
      store_instance: [{ instance_id: instance }],
    });
  } finally { await store.close(); }
});

test("granted scopes derive the same union whatever order the logical rows carry", async () => {
  const rows = [
    {
      token_hash: hash("dd"), family_id: "fixture-family-b", client_id: CLIENT_ID, subject: SUBJECT,
      resource: RESOURCE, scopes: ["mcp:write"], expires_at: T3,
    },
    {
      token_hash: hash("ee"), family_id: "fixture-family-a", client_id: CLIENT_ID, subject: SUBJECT,
      resource: RESOURCE, scopes: ["mcp:read"], expires_at: T3,
    },
  ];
  const results: string[][] = [];
  for (const refresh_token of [rows, [...rows].reverse()]) {
    const store = new FixtureStore({ refresh_token }, new SeededRandom("scope-order"));
    try {
      results.push(await store.findGrantedScopes(SUBJECT, CLIENT_ID, T0));
    } finally { await store.close(); }
  }
  assert.deepEqual(results, [["mcp:write", "mcp:read"], ["mcp:write", "mcp:read"]]);
});
