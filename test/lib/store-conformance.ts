// Shared StorePort conformance suite (contracts §12). Invoked once per adapter
// (MemoryStore, SqliteStore) so both — and any downstream SQL adapter — are
// validated against the SAME invariants, including the rotation backfill (fix #3)
// and findGrantedScopes. `runStoreConformance` only registers tests when called,
// so downstream adapters import and invoke it without side effects.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import type { SaveAuthCodeInput, SaveRefreshTokenInput, StorePort } from "../../src/ports/store.ts";
import { StoreInputError } from "../../src/ports/store.ts";

const NOW = "2026-07-03T12:00:00.000Z";
const LATER = "2026-07-03T12:05:00.000Z";
const FUTURE = "2026-07-03T13:00:00.000Z";
const PAST = "2026-07-03T11:00:00.000Z";

export function runStoreConformance(label: string, make: () => StorePort): void {
  test(`${label}: auth codes are hashed, single-use, expire`, async () => {
    const store = make();
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

  test(`${label}: consent jti is single-use`, async () => {
    const store = make();
    assert.equal(await store.consumeConsentJti("jti-1", FUTURE), true);
    assert.equal(await store.consumeConsentJti("jti-1", FUTURE), false); // replay
    assert.equal(await store.consumeConsentJti("jti-2", FUTURE), true);
    await store.close();
  });

  test(`${label}: rotates refresh tokens and replay revokes the family`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("one", "fam-1", null, FUTURE));
    const rotated = await store.rotateRefreshToken(sha256Hex("one"), refresh("two", "fam-1", sha256Hex("one"), FUTURE), NOW);
    assert.equal(rotated?.tokenHash, sha256Hex("one"));
    // replay of the consumed token -> null (and revokes the family)
    assert.equal(await store.rotateRefreshToken(sha256Hex("one"), refresh("three", "fam-1", sha256Hex("one"), FUTURE), LATER), null);
    // the rotated successor can no longer rotate either (family revoked) -> null
    assert.equal(await store.rotateRefreshToken(sha256Hex("two"), refresh("four", "fam-1", sha256Hex("two"), FUTURE), LATER), null);
    await store.close();
  });

  test(`${label}: rotation backfill ignores caller-supplied identity (fix #3)`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("m1", "fam-m", null, FUTURE));
    // attacker rotates a stolen token, supplying a DIFFERENT client/subject/scopes
    await store.rotateRefreshToken(sha256Hex("m1"), {
      ...refresh("m2", "fam-m", sha256Hex("m1"), FUTURE),
      clientId: "attacker", subject: "attacker", scopes: ["mcp:admin"],
    }, NOW);
    const second = await store.rotateRefreshToken(sha256Hex("m2"), refresh("m3", "fam-m", sha256Hex("m2"), FUTURE), LATER);
    // the successor carries the STORED identity, not the attacker's
    assert.equal(second?.clientId, "client-1");
    assert.equal(second?.subject, "subject-1");
    assert.deepEqual(second?.scopes, ["mcp:read"]);
    await store.close();
  });

  test(`${label}: rejects expired refresh tokens and closes idempotently`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("exp", "fam-e", null, PAST));
    assert.equal(await store.rotateRefreshToken(sha256Hex("exp"), refresh("next", "fam-e", sha256Hex("exp"), FUTURE), NOW), null);
    await store.close();
    await store.close(); // idempotent
    await assert.rejects(store.saveRefreshToken(refresh("closed", "fam-c", null, FUTURE)));
  });

  test(`${label}: findGrantedScopes derives the union from active refresh records`, async () => {
    const store = make();
    assert.deepEqual(await store.findGrantedScopes("subject-1", "client-1", NOW), []); // none yet
    await store.saveRefreshToken(refresh("g1", "fam-g1", null, FUTURE)); // subject-1/client-1/mcp:read
    assert.deepEqual(await store.findGrantedScopes("subject-1", "client-1", NOW), ["mcp:read"]);
    await store.saveRefreshToken({ ...refresh("g2", "fam-g2", null, FUTURE), scopes: ["mcp:write"] });
    assert.deepEqual((await store.findGrantedScopes("subject-1", "client-1", NOW)).sort(), ["mcp:read", "mcp:write"]);
    assert.deepEqual(await store.findGrantedScopes("subject-1", "client-2", NOW), []); // other client
    await store.saveRefreshToken({ ...refresh("g3", "fam-g3", null, PAST), scopes: ["mcp:admin"] }); // expired -> excluded
    assert.deepEqual((await store.findGrantedScopes("subject-1", "client-1", NOW)).sort(), ["mcp:read", "mcp:write"]);
    await store.revokeRefreshTokenFamily("fam-g2", NOW); // revoked -> excluded
    assert.deepEqual((await store.findGrantedScopes("subject-1", "client-1", NOW)).sort(), ["mcp:read"]);
    await store.close();
  });

  test(`${label}: consumeConsentJti rejects a non-3-ms timestamp (addendum 10)`, async () => {
    const store = make();
    await assert.rejects(store.consumeConsentJti("jti", "not-a-timestamp"), (e: unknown) => e instanceof StoreInputError);
    await assert.rejects(store.consumeConsentJti("jti", "2026-07-03T13:00:00Z"), (e: unknown) => e instanceof StoreInputError); // no ms
    await assert.rejects(store.consumeConsentJti("jti", "2026-07-03T13:00:00.00Z"), (e: unknown) => e instanceof StoreInputError); // 2 digits
    assert.equal(await store.consumeConsentJti("ok", "2026-07-03T13:00:00.000Z"), true); // 3 ms accepted
    await store.close();
  });

  test(`${label}: sweep retains a consumed predecessor while its successor is valid (addendum 8)`, async () => {
    const store = make();
    const early = "2026-07-03T12:30:00.000Z"; // predecessor expiry
    const late = "2026-07-03T13:00:00.000Z"; // successor expiry (outlives predecessor)
    await store.saveRefreshToken(refresh("pred", "fam-succ", null, early));
    const rotated = await store.rotateRefreshToken(sha256Hex("pred"), refresh("succ", "fam-succ", sha256Hex("pred"), late), NOW);
    assert.ok(rotated, "rotation succeeds");
    // sweep AFTER the predecessor expired but BEFORE the successor -> predecessor retained
    await store.sweepExpired("2026-07-03T12:45:00.000Z");
    const replay = await store.rotateRefreshToken(sha256Hex("pred"), refresh("p2", "fam-succ", sha256Hex("pred"), late), "2026-07-03T12:45:00.000Z");
    assert.equal(replay, null, "predecessor replay detected -> family revoked");
    const after = await store.rotateRefreshToken(sha256Hex("succ"), refresh("s2", "fam-succ", sha256Hex("succ"), late), "2026-07-03T12:45:00.000Z");
    assert.equal(after, null, "successor is dead after the family was revoked");
    await store.close();
  });

  test(`${label}: sweep deletes a family only once every member is past validity`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("only", "fam-only", null, "2026-07-03T12:30:00.000Z"));
    await store.sweepExpired("2026-07-03T12:45:00.000Z"); // past the only token's expiry
    // family fully GC'd -> a later replay is undetected (accepted boundary, addendum 8)
    const replay = await store.rotateRefreshToken(sha256Hex("only"), refresh("o2", "fam-only", sha256Hex("only"), "2026-07-03T13:00:00.000Z"), "2026-07-03T12:45:00.000Z");
    assert.equal(replay, null, "post-validity replay is undetected (rows GC'd) — accepted boundary");
    await store.close();
  });

  test(`${label}: sweep treats expires_at == now as still-valid (boundary, addendum 8)`, async () => {
    const store = make();
    // a token expiring EXACTLY at the sweep instant is a still-valid family member
    await store.saveRefreshToken(refresh("edge", "fam-edge", null, NOW));
    await store.sweepExpired(NOW);
    assert.ok(await store.findRefreshToken(sha256Hex("edge")), "expires_at == now survives (>= now is still-valid)");
    await store.close();
  });
}

function authCode(rawCode: string, expiresAt: string): SaveAuthCodeInput {
  return {
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "subject-1",
    redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
    scopes: ["mcp:read"], codeChallenge: "pkce-challenge", codeChallengeMethod: "S256", expiresAt,
  };
}

function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string): SaveRefreshTokenInput {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", scopes: ["mcp:read"], expiresAt,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
