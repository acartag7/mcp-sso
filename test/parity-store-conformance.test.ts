import assert from "node:assert/strict";
import { test } from "node:test";
import { StoreInputError } from "../src/ports/store.ts";
import { runClientStoreConformance } from "../src/testing/client-store-conformance.ts";
import { runStoreConformance } from "../src/testing/store-conformance.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";

runStoreConformance("fixture store", async () =>
  new FixtureStore({}, new SeededRandom("fixture-store-conformance")));

runClientStoreConformance("fixture store", () =>
  new FixtureStore({}, new SeededRandom("fixture-client-store-conformance")));

test("fixture store validates identity subjects before mutation and lookup", async () => {
  const invalidSubjects = [" fixture-subject ", "x".repeat(385)];
  const invalidSubject = invalidSubjects[0]!;
  const codeHash = "d".repeat(64), refreshHash = "e".repeat(64), nextHash = "f".repeat(64);
  const resource = "https://api.example.com/mcp", expiresAt = "2026-08-31T13:00:00.000Z";
  const stored = new FixtureStore({ authorization_code: [{
    code_hash: codeHash, client_id: "fixture-client", subject: invalidSubject,
    redirect_uri: "https://client.example.com/callback", resource, scopes: ["mcp:read"],
    code_challenge: "fixture-challenge", code_challenge_method: "S256", expires_at: expiresAt,
  }], refresh_token: [{
    token_hash: refreshHash, family_id: "fixture-family", client_id: "fixture-client",
    subject: invalidSubject, resource, scopes: ["mcp:read"], expires_at: expiresAt,
    consumed_at: "2026-08-31T11:00:00.000Z",
  }] }, new SeededRandom("stored-subject"));
  try {
    const before = stored.snapshot();
    await assert.rejects(stored.consumeAuthCode(codeHash, "2026-08-31T12:00:00.000Z"), StoreInputError);
    await assert.rejects(stored.findRefreshToken(refreshHash), StoreInputError);
    await assert.rejects(stored.rotateRefreshToken(refreshHash, {
      tokenHash: nextHash, familyId: "fixture-family", previousTokenHash: refreshHash,
      clientId: "ignored-client", subject: "", resource, scopes: [], expiresAt,
    }, "2026-08-31T12:00:00.000Z"), StoreInputError);
    assert.deepEqual(stored.snapshot(), before);
  } finally { await stored.close(); }

  const writes = new FixtureStore({}, new SeededRandom("written-subject"));
  try {
    const instanceId = await writes.getStoreInstanceId();
    for (const subject of invalidSubjects) {
      const code = { codeHash, clientId: "fixture-client", subject,
        redirectUri: "https://client.example.com/callback", resource, scopes: ["mcp:read"],
        codeChallenge: "fixture-challenge", codeChallengeMethod: "S256" as const, expiresAt };
      await assert.rejects(writes.saveAuthCode(code), StoreInputError);
      await assert.rejects(writes.commitConsentApproval(instanceId, "fixture-jti", expiresAt, code), StoreInputError);
      await assert.rejects(writes.saveRefreshToken({
        tokenHash: refreshHash, familyId: "fixture-family", previousTokenHash: null,
        clientId: "fixture-client", subject, resource, scopes: ["mcp:read"], expiresAt,
      }), StoreInputError);
      await assert.rejects(writes.findGrantedScopes(subject, "fixture-client", expiresAt), StoreInputError);
    }
    assert.deepEqual(writes.snapshot(), { authorization_code: [], consent_jti: [], refresh_token: [],
      revoked_family: [], client_registration: [], store_instance: [{ instance_id: instanceId }] });
  } finally { await writes.close(); }
});

test("fixture store derives scopes independently of refresh row order", async () => {
  const resource = "https://api.example.com/mcp", expires_at = "2026-08-31T13:00:00.000Z";
  const rows = [{ token_hash: "a".repeat(64), family_id: "fixture-family-a",
    client_id: "fixture-client", subject: "fixture-subject", resource,
    scopes: ["mcp:write"], expires_at },
  { token_hash: "b".repeat(64), family_id: "fixture-family-b",
    client_id: "fixture-client", subject: "fixture-subject", resource,
    scopes: ["mcp:read"], expires_at }];
  const results: string[][] = [];
  for (const refresh_token of [rows, [...rows].reverse()]) {
    const store = new FixtureStore({ refresh_token }, new SeededRandom("row-order"));
    try {
      results.push(await store.findGrantedScopes("fixture-subject", "fixture-client",
        "2026-08-31T12:00:00.000Z"));
    } finally { await store.close(); }
  }
  assert.deepEqual(results, [["mcp:write", "mcp:read"], ["mcp:write", "mcp:read"]]);
});

test("fixture store hydrates an omitted authorization-code generation as legacy null", async () => {
  const codeHash = "a".repeat(64);
  const resource = "https://api.example.com/mcp", expiresAt = "2026-08-31T13:00:00.000Z";
  const store = new FixtureStore({ authorization_code: [{
    code_hash: codeHash, client_id: "fixture-client", subject: "fixture-subject",
    redirect_uri: "https://client.example.com/callback", resource, scopes: ["mcp:read"],
    code_challenge: "fixture-challenge", code_challenge_method: "S256", expires_at: expiresAt,
  }] }, new SeededRandom("legacy-code-generation"));
  try {
    const code = await store.consumeAuthCode(codeHash, "2026-08-31T12:00:00.000Z");
    assert.equal(code?.grantGeneration, null);
  } finally { await store.close(); }
});

test("fixture store preserves an omitted refresh generation through rotation", async () => {
  const tokenHash = "b".repeat(64), nextHash = "c".repeat(64);
  const resource = "https://api.example.com/mcp", expiresAt = "2026-08-31T13:00:00.000Z";
  const store = new FixtureStore({ refresh_token: [{
    token_hash: tokenHash, family_id: "fixture-family", client_id: "fixture-client",
    subject: "fixture-subject", resource, scopes: ["mcp:read"], expires_at: expiresAt,
  }] }, new SeededRandom("legacy-refresh-generation"));
  try {
    const rotated = await store.rotateRefreshToken(tokenHash, {
      tokenHash: nextHash, familyId: "fixture-family", previousTokenHash: tokenHash,
      clientId: "ignored-client", subject: "ignored-subject", resource,
      scopes: ["ignored"], expiresAt,
    }, "2026-08-31T12:00:00.000Z");
    assert.equal(rotated?.grantGeneration, null);
    assert.deepEqual(store.snapshot().refresh_token.map((row) => row.grant_generation), [undefined, undefined]);
  } finally { await store.close(); }
});

test("fixture store agrees on omitted refresh and revocation generations", async () => {
  const resource = "https://api.example.com/mcp", family_id = "fixture-family";
  const store = new FixtureStore({ refresh_token: [{
    token_hash: "d".repeat(64), family_id, client_id: "fixture-client",
    subject: "fixture-subject", resource, scopes: ["mcp:read"],
    expires_at: "2026-08-31T13:00:00.000Z",
  }], revoked_family: [{
    family_id, resource, revoked_at: "2026-08-31T12:00:00.000Z",
  }] }, new SeededRandom("legacy-revocation-generation"));
  try {
    assert.deepEqual(store.snapshot().revoked_family, [{
      family_id, resource, revoked_at: "2026-08-31T12:00:00.000Z",
    }]);
  } finally { await store.close(); }
});
