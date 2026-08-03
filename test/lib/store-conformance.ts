// Shared StorePort conformance suite (contracts §12). Invoked once per adapter
// (MemoryStore, SqliteStore) so both — and any downstream SQL adapter — are
// validated against the SAME invariants, including the rotation backfill (fix #3)
// and findGrantedScopes. `runStoreConformance` only registers tests when called,
// so downstream adapters import and invoke it without side effects.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import type { SaveAuthCodeInput, SaveRefreshTokenInput, StorePort } from "../../src/ports/store.ts";
import { STORED_DCR_GRANT_GENERATION, StoreInputError, UNBOUND_REFRESH_RESOURCE } from "../../src/ports/store.ts";

const NOW = "2026-07-03T12:00:00.000Z";
const LATER = "2026-07-03T12:05:00.000Z";
const FUTURE = "2026-07-03T13:00:00.000Z";
const PAST = "2026-07-03T11:00:00.000Z";
const RESOURCE_A = "https://api-a.test/mcp";
const RESOURCE_B = "https://api-b.test/mcp";

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

  test(`${label}: stored-DCR generation rejects and burns legacy auth codes`, async () => {
    const store = make();
    assert.equal(store.storedDcrGrantGeneration, STORED_DCR_GRANT_GENERATION);
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
    const store = make();
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
    const store = make();
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

  test(`${label}: an omitted untyped resource persists unbound and cannot rotate`, async () => {
    const store = make();
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
    const store = make();
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
    const store = make();
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

  test(`${label}: concurrent resource A/B rotation permits only the bound resource`, async () => {
    const store = make();
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

  test(`${label}: explicit family revocation is idempotent and disables a rotated successor`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("comp-one", "fam-comp", null, FUTURE));
    const rotated = await store.rotateRefreshToken(
      sha256Hex("comp-one"),
      refresh("comp-two", "fam-comp", sha256Hex("comp-one"), FUTURE),
      NOW,
    );
    assert.ok(rotated, "control rotation succeeds");
    await store.revokeRefreshTokenFamily("fam-comp", NOW);
    await store.revokeRefreshTokenFamily("fam-comp", LATER);
    assert.deepEqual(await store.findGrantedScopes("subject-1", "client-1", LATER), []);
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("comp-two"),
        refresh("comp-three", "fam-comp", sha256Hex("comp-two"), FUTURE),
        LATER,
      ),
      null,
      "the compensated successor stays inactive",
    );
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

  test(`${label}: refresh generation is checked before rotation and copied from durable state`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("gen-current", "fam-gen", null, FUTURE, STORED_DCR_GRANT_GENERATION));
    const rotated = await store.rotateRefreshToken(
      sha256Hex("gen-current"),
      refresh("gen-successor", "fam-gen", sha256Hex("gen-current"), FUTURE, 2),
      NOW,
      STORED_DCR_GRANT_GENERATION,
    );
    assert.equal(rotated?.grantGeneration, STORED_DCR_GRANT_GENERATION);
    assert.equal((await store.findRefreshToken(sha256Hex("gen-successor")))?.grantGeneration, STORED_DCR_GRANT_GENERATION);

    await store.saveRefreshToken(refresh("gen-legacy", "fam-legacy", null, FUTURE, null));
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("gen-legacy"),
        refresh("legacy-successor", "fam-legacy", sha256Hex("gen-legacy"), FUTURE, STORED_DCR_GRANT_GENERATION),
        NOW,
        STORED_DCR_GRANT_GENERATION,
      ),
      null,
    );
    assert.ok(await store.findRefreshToken(sha256Hex("gen-legacy")), "legacy predecessor was not consumed");
    assert.equal(await store.findRefreshToken(sha256Hex("legacy-successor")), null, "no successor became live");
    await store.saveRefreshToken(refresh("gen-other", "fam-other", null, FUTURE, 2));
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("gen-other"),
        refresh("other-successor", "fam-other", sha256Hex("gen-other"), FUTURE),
        NOW,
        STORED_DCR_GRANT_GENERATION,
      ),
      null,
    );
    await store.close();
  });

  test(`${label}: a successor-hash collision returns null and leaves the predecessor unconsumed (§12.2 invariant 8)`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("col-orig", "fam-col", null, FUTURE));
    await store.saveRefreshToken(refresh("col-existing", "fam-col-other", null, FUTURE)); // hash collides with the successor below
    // Rotate "col-orig" but supply a successor tokenHash that already exists -> null.
    const rotated = await store.rotateRefreshToken(sha256Hex("col-orig"), {
      ...refresh("col-next", "fam-col", sha256Hex("col-orig"), FUTURE), tokenHash: sha256Hex("col-existing"),
    }, NOW);
    assert.equal(rotated, null, "collision -> null");
    // The predecessor must STILL be consumable: the failed rotation did not consume it.
    const retry = await store.rotateRefreshToken(sha256Hex("col-orig"), refresh("col-ok", "fam-col", sha256Hex("col-orig"), FUTURE), LATER);
    assert.ok(retry, "predecessor survives the failed rotation");
    await store.close();
  });

  test(`${label}: saveRefreshToken rejects a duplicate tokenHash — never a silent overwrite (§12.2 invariant 8)`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("dup", "fam-dup", null, FUTURE));
    await store.rotateRefreshToken(sha256Hex("dup"), refresh("dup-2", "fam-dup", sha256Hex("dup"), FUTURE), NOW);
    // Re-saving the consumed hash must reject; an overwrite would rebuild the row
    // with consumedAt:null, resurrecting it and erasing the replay signal.
    await assert.rejects(store.saveRefreshToken(refresh("dup", "fam-dup", null, FUTURE)));
    // The replay signal survived: replaying the consumed token still revokes the family.
    assert.equal(await store.rotateRefreshToken(sha256Hex("dup"), refresh("dup-3", "fam-dup", sha256Hex("dup"), FUTURE), LATER), null);
    assert.equal(await store.rotateRefreshToken(sha256Hex("dup-2"), refresh("dup-4", "fam-dup", sha256Hex("dup-2"), FUTURE), LATER), null, "family revoked by the replay");
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

  test(`${label}: findGrantedScopes excludes legacy and non-current generations`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("scope-current", "fam-scope-current", null, FUTURE, STORED_DCR_GRANT_GENERATION));
    await store.saveRefreshToken({
      ...refresh("scope-legacy", "fam-scope-legacy", null, FUTURE, null),
      scopes: ["mcp:write"],
    });
    await store.saveRefreshToken({
      ...refresh("scope-other", "fam-scope-other", null, FUTURE, 2),
      scopes: ["mcp:admin"],
    });
    assert.deepEqual(
      await store.findGrantedScopes("subject-1", "client-1", NOW, STORED_DCR_GRANT_GENERATION),
      ["mcp:read"],
    );
    assert.deepEqual(
      (await store.findGrantedScopes("subject-1", "client-1", NOW)).sort(),
      ["mcp:admin", "mcp:read", "mcp:write"],
      "control: omission preserves stateless/non-cutover behavior",
    );
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
    assert.ok(await store.findRefreshToken(sha256Hex("pred")), "predecessor directly verified retained after sweep");
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
    // Directly verify sweep actually deleted the row — `rotate ... === null` alone cannot
    // distinguish "swept (row gone)" from "not swept (row expired, rotate rejected)".
    assert.equal(await store.findRefreshToken(sha256Hex("only")), null, "swept token must be deleted");
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

function authCode(rawCode: string, expiresAt: string, grantGeneration?: number | null): SaveAuthCodeInput {
  return {
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "subject-1",
    redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
    scopes: ["mcp:read"], codeChallenge: "pkce-challenge",
    codeChallengeMethod: "S256", expiresAt, grantGeneration,
  };
}

function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string, grantGeneration?: number | null, resource = RESOURCE_A): SaveRefreshTokenInput {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", resource,
    scopes: ["mcp:read"], expiresAt, grantGeneration,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
