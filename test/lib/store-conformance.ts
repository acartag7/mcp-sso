// Shared StorePort conformance suite (contracts §12). Invoked once per adapter
// (MemoryStore, SqliteStore, MysqlStore) so all — and any downstream SQL adapter —
// are validated against the SAME invariants, including the rotation backfill
// (fix #3) and findGrantedScopes. `runStoreConformance` only registers tests when
// called, so downstream adapters import and invoke it without side effects.
//
// `runResourceBindingConformance` (contracts §12.2 invariant 11) is the SAME kind
// of shared parity source, but capability-gated: it is invoked only against stores
// that advertise `resourceBinding: 1`. The SQL adapters gain that marker in their
// own slice and then invoke this function; until then it runs against MemoryStore.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import type {
  RefreshRotationResult, RefreshTokenRecord, ResourceBindingExpectation,
  SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../../src/ports/store.ts";
import { STORED_DCR_GRANT_GENERATION, StoreInputError } from "../../src/ports/store.ts";

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
    assert.ok(isRefreshRecord(rotated));
    assert.equal(rotated.tokenHash, sha256Hex("one"));
    // replay of the consumed token -> null (and revokes the family)
    assert.equal(await store.rotateRefreshToken(sha256Hex("one"), refresh("three", "fam-1", sha256Hex("one"), FUTURE), LATER), null);
    // the rotated successor can no longer rotate either (family revoked) -> null
    assert.equal(await store.rotateRefreshToken(sha256Hex("two"), refresh("four", "fam-1", sha256Hex("two"), FUTURE), LATER), null);
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
    assert.ok(isRefreshRecord(second));
    // the successor carries the STORED identity, not the attacker's
    assert.equal(second.clientId, "client-1");
    assert.equal(second.subject, "subject-1");
    assert.deepEqual(second.scopes, ["mcp:read"]);
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
    assert.ok(isRefreshRecord(rotated));
    assert.equal(rotated.grantGeneration, STORED_DCR_GRANT_GENERATION);
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

// §12.2 invariant 11 — resource lineage. Capability-gated: invoked only against
// stores advertising `resourceBinding: 1` (currently MemoryStore; the SQL adapters
// invoke the same function once they add the marker). The store treats resource as
// an opaque canonical string — equality only, no URL parsing (one parser, §5.1).
export function runResourceBindingConformance(label: string, make: () => StorePort): void {
  const RES_A = "https://api-a.test/mcp";
  const RES_B = "https://api-b.test/mcp";
  const expectA = (): ResourceBindingExpectation => ({ resource: RES_A, allowLegacySingletonBinding: false });
  const expectB = (): ResourceBindingExpectation => ({ resource: RES_B, allowLegacySingletonBinding: false });

  test(`${label}: advertises the resourceBinding capability marker`, () => {
    assert.equal(make().resourceBinding, 1);
  });

  test(`${label}: replaying an OLDER consumed member of a bound legacy chain still revokes the family`, async () => {
    // A pre-0.4 chain rotated under the old binary: T1 consumed, T2 current, both
    // resource NULL. The 0.4 upgrade rotates T2 under the singleton attestation,
    // which stamps the FAMILY and the rotated token — but NOT older consumed rows.
    // T1 therefore keeps resource NULL while the family reads RES_A. Replay
    // detection must still fire: if the resource-equality check ran first, a stolen
    // T1 would return null WITHOUT revoking, leaving the live family usable.
    const store = make();
    const attest = (): ResourceBindingExpectation => ({ resource: RES_A, allowLegacySingletonBinding: true });
    await store.saveRefreshToken(refresh("lc-1", "fam-lc", null, FUTURE));
    // Old-binary rotation: no expectation passed, so T1 is consumed while still NULL.
    assert.ok(await store.rotateRefreshToken(sha256Hex("lc-1"), refresh("lc-2", "fam-lc", sha256Hex("lc-1"), FUTURE), NOW));
    // 0.4 upgrade rotation of the CURRENT token binds the family to RES_A.
    const bound = await store.rotateRefreshToken(sha256Hex("lc-2"), refresh("lc-3", "fam-lc", sha256Hex("lc-2"), FUTURE), NOW, undefined, attest());
    assert.ok(bound && !("status" in bound), "attested legacy rotation binds the family");
    // Replay the OLDER consumed predecessor, whose own row is still NULL.
    assert.equal(
      await store.rotateRefreshToken(sha256Hex("lc-1"), refresh("lc-4", "fam-lc", sha256Hex("lc-1"), FUTURE), LATER, undefined, attest()),
      null, "older consumed legacy predecessor is invalid_grant");
    // The whole family MUST now be dead — this is the assertion that fails if the
    // equality check is ordered before replay detection.
    assert.equal(
      await store.rotateRefreshToken(sha256Hex("lc-3"), refresh("lc-5", "fam-lc", sha256Hex("lc-3"), FUTURE), LATER, undefined, attest()),
      null, "the replay revoked the family");
    await store.close();
  });

  test(`${label}: malformed persisted lineage is invalid_grant, not a retryable mismatch`, async () => {
    // The library only ever writes canonical resources, so a non-empty stored
    // value that is not canonical means the RECORD is unusable — migrated by
    // hand, corrupted, or written by something else. Rotation must return null
    // (invalid_grant: discard this grant) rather than compare it and report a
    // resource mismatch (invalid_target: retry another resource), which would
    // tell the client to keep retrying a record that can never work.
    const store = make();
    await store.saveRefreshToken(refreshRes("bad-1", "fam-bad", null, FUTURE, "not-a-url"));
    assert.equal(
      await store.rotateRefreshToken(sha256Hex("bad-1"), refreshRes("bad-2", "fam-bad", sha256Hex("bad-1"), FUTURE, "not-a-url"), NOW, undefined, expectA()),
      null, "malformed stored lineage yields no rotation");
    // A non-canonical spelling of a REAL resource is equally unusable.
    await store.saveRefreshToken(refreshRes("nc-1", "fam-nc", null, FUTURE, "https://API-A.test:443/mcp"));
    assert.equal(
      await store.rotateRefreshToken(sha256Hex("nc-1"), refreshRes("nc-2", "fam-nc", sha256Hex("nc-1"), FUTURE, "https://API-A.test:443/mcp"), NOW, undefined, expectA()),
      null, "non-canonical stored lineage yields no rotation");
    await store.close();
  });

  test(`${label}: rotation copies the STORED resource to the successor, ignoring the caller-supplied value`, async () => {
    const store = make();
    await store.saveRefreshToken(refreshRes("rc-1", "fam-rc", null, FUTURE, RES_A));
    // The successor input carries a DIFFERENT resource (poison); the store
    // authoritative-copies the stored resource, never the caller-supplied one.
    const rotated = await store.rotateRefreshToken(
      sha256Hex("rc-1"), refreshRes("rc-2", "fam-rc", sha256Hex("rc-1"), FUTURE, RES_B),
      NOW, undefined, expectA(),
    );
    assert.ok(isRefreshRecord(rotated));
    assert.equal(rotated.resource, RES_A, "consumed predecessor reports the stored resource");
    assert.equal((await store.findRefreshToken(sha256Hex("rc-2")))?.resource, RES_A, "successor carries the STORED resource, not the caller-supplied RES_B");
    await store.close();
  });

  test(`${label}: a resource mismatch returns the fieldless marker with NO mutation`, async () => {
    const store = make();
    await store.saveRefreshToken(refreshRes("mm-1", "fam-mm", null, FUTURE, RES_A));
    const result = await store.rotateRefreshToken(
      sha256Hex("mm-1"), refreshRes("mm-2", "fam-mm", sha256Hex("mm-1"), FUTURE, RES_A),
      NOW, undefined, expectB(),
    );
    assert.deepEqual(result, { status: "resource_mismatch" }, "fieldless marker, no record fields");
    // NO mutation: the predecessor is unconsumed and no successor was inserted.
    const retry = await store.rotateRefreshToken(
      sha256Hex("mm-1"), refreshRes("mm-ok", "fam-mm", sha256Hex("mm-1"), FUTURE, RES_A),
      LATER, undefined, expectA(),
    );
    assert.ok(isRefreshRecord(retry), "predecessor survived the mismatch unconsumed — retry rotates it");
    assert.equal(await store.findRefreshToken(sha256Hex("mm-2")), null, "no successor was inserted by the mismatched rotation");
    await store.close();
  });

  test(`${label}: replay of a consumed token revokes the family even when the request names a different resource`, async () => {
    const store = make();
    await store.saveRefreshToken(refreshRes("rp-1", "fam-rp", null, FUTURE, RES_A));
    // First (legitimate) rotation consumes rp-1 against its own resource.
    assert.ok(isRefreshRecord(await store.rotateRefreshToken(
      sha256Hex("rp-1"), refreshRes("rp-2", "fam-rp", sha256Hex("rp-1"), FUTURE, RES_A),
      NOW, undefined, expectA(),
    )));
    // Replay the CONSUMED rp-1, naming a DIFFERENT configured resource. Replay must
    // revoke the family and return null — NEVER downgrade into resource_mismatch.
    const replay = await store.rotateRefreshToken(
      sha256Hex("rp-1"), refreshRes("rp-3", "fam-rp", sha256Hex("rp-1"), FUTURE, RES_B),
      LATER, undefined, expectB(),
    );
    assert.equal(replay, null, "consumed replay -> null (family revoked), NOT a retryable resource_mismatch");
    assert.notDeepEqual(replay, { status: "resource_mismatch" }, "replay is never downgraded to a mismatch");
    // The family is revoked: the live successor rp-2 can no longer rotate.
    assert.equal(
      await store.rotateRefreshToken(
        sha256Hex("rp-2"), refreshRes("rp-4", "fam-rp", sha256Hex("rp-2"), FUTURE, RES_A),
        LATER, undefined, expectA(),
      ),
      null,
      "successor is dead after the family was revoked by the replay",
    );
    await store.close();
  });

  test(`${label}: findGrantedScopes isolates resources that share a scope string`, async () => {
    const store = make();
    await store.saveRefreshToken({ ...refreshRes("iso-a", "fam-iso-a", null, FUTURE, RES_A), scopes: ["mcp:shared", "mcp:a"] });
    await store.saveRefreshToken({ ...refreshRes("iso-b", "fam-iso-b", null, FUTURE, RES_B), scopes: ["mcp:shared", "mcp:b"] });
    const a = await store.findGrantedScopes("subject-1", "client-1", NOW, undefined, expectA());
    assert.deepEqual([...a].sort(), ["mcp:a", "mcp:shared"], "only RES_A's scopes — never RES_B's mcp:b");
    const b = await store.findGrantedScopes("subject-1", "client-1", NOW, undefined, expectB());
    assert.deepEqual([...b].sort(), ["mcp:b", "mcp:shared"], "only RES_B's scopes — never RES_A's mcp:a");
    await store.close();
  });

  test(`${label}: a legacy null lineage binds only with the singleton attestation`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("leg-1", "fam-leg", null, FUTURE)); // resource omitted -> null
    const bound = await store.rotateRefreshToken(
      sha256Hex("leg-1"), refreshRes("leg-2", "fam-leg", sha256Hex("leg-1"), FUTURE, RES_A),
      NOW, undefined, { resource: RES_A, allowLegacySingletonBinding: true },
    );
    assert.ok(isRefreshRecord(bound), "null lineage binds atomically to the sole attested resource");
    assert.equal((await store.findRefreshToken(sha256Hex("leg-2")))?.resource, RES_A, "successor carries the bound sole resource");

    // Same null lineage WITHOUT the attestation (or in multi mode): invalid_grant,
    // never assigned the request-selected resource.
    await store.saveRefreshToken(refresh("leg-3", "fam-leg2", null, FUTURE)); // resource omitted -> null
    const rejected = await store.rotateRefreshToken(
      sha256Hex("leg-3"), refreshRes("leg-4", "fam-leg2", sha256Hex("leg-3"), FUTURE, RES_A),
      NOW, undefined, expectA(),
    );
    assert.equal(rejected, null, "unattested null lineage is invalid_grant, never bound to the request resource");
    assert.ok(await store.findRefreshToken(sha256Hex("leg-3")), "predecessor not consumed by the rejected rotation");
    assert.equal(await store.findRefreshToken(sha256Hex("leg-4")), null, "no successor became live");
    await store.close();
  });

  test(`${label}: a legacy null active row contributes scopes only under the attestation`, async () => {
    const store = make();
    await store.saveRefreshToken(refresh("fs-null", "fam-fs-null", null, FUTURE)); // resource omitted -> null
    assert.deepEqual(
      await store.findGrantedScopes("subject-1", "client-1", NOW, undefined, { resource: RES_A, allowLegacySingletonBinding: true }),
      ["mcp:read"],
      "null active row contributes scopes under the singleton attestation",
    );
    assert.deepEqual(
      await store.findGrantedScopes("subject-1", "client-1", NOW, undefined, expectA()),
      [],
      "null active row contributes NO scopes without the attestation",
    );
    await store.close();
  });
}

/** Narrows a rotation result to a refresh record, excluding null and the fieldless
 *  resource-mismatch marker (which has only `status`). Used by rows that assert on
 *  record fields, so a surprise mismatch fails loudly instead of testing `undefined`. */
function isRefreshRecord(r: RefreshRotationResult): r is RefreshTokenRecord {
  return r !== null && !("status" in r);
}

function authCode(rawCode: string, expiresAt: string, grantGeneration?: number | null): SaveAuthCodeInput {
  return {
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "subject-1",
    redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
    scopes: ["mcp:read"], codeChallenge: "pkce-challenge",
    codeChallengeMethod: "S256", expiresAt, grantGeneration,
  };
}

function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string, grantGeneration?: number | null): SaveRefreshTokenInput {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1",
    scopes: ["mcp:read"], expiresAt, grantGeneration,
  };
}

/** A resource-bound refresh input (resource is an opaque canonical string; the
 *  store does equality only — no URL parsing). */
function refreshRes(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string, resource: string, scopes: string[] = ["mcp:read"]): SaveRefreshTokenInput {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", scopes, expiresAt, resource,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
