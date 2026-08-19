// StorePort conformance — explicit revocation, grant generations, row integrity, and granted scopes.
// One section of the suite in `store-conformance.ts` (contracts §12); adapters
// run every section through `runStoreConformance`, never a section alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import { STORED_DCR_GRANT_GENERATION } from "../ports/store.ts";
import type { SaveRefreshTokenInput } from "../ports/store.ts";
import {
  FUTURE, LATER, NOW, PAST, RESOURCE_A, RESOURCE_B, refresh, sha256Hex, type MakeStore,
} from "./store-conformance-fixtures.ts";

export function registerRevocationRows(label: string, make: MakeStore): void {
  test(`${label}: explicit family revocation is idempotent and disables a rotated successor`, async () => {
    const store = await make();
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

  test(`${label}: explicit family revocation mutates only the expected resource`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh("revoke-resource", "fam-revoke-resource", null, FUTURE, undefined, RESOURCE_A));
    await store.revokeRefreshTokenFamily("fam-revoke-resource", NOW, RESOURCE_B);
    const rotated = await store.rotateRefreshToken(
      sha256Hex("revoke-resource"),
      refresh("revoke-resource-next", "fam-revoke-resource", sha256Hex("revoke-resource"), FUTURE, undefined, RESOURCE_A),
      LATER,
      undefined,
      RESOURCE_A,
    );
    assert.ok(rotated, "wrong-resource revocation left the bound family active");
    await store.revokeRefreshTokenFamily("fam-revoke-resource", LATER, RESOURCE_A);
    assert.equal(await store.rotateRefreshToken(
      sha256Hex("revoke-resource-next"),
      refresh("revoke-resource-final", "fam-revoke-resource", sha256Hex("revoke-resource-next"), FUTURE, undefined, RESOURCE_A),
      FUTURE,
      undefined,
      RESOURCE_A,
    ), null, "matching-resource revocation disabled the family");
    await store.close();
  });

  test(`${label}: rotation backfill ignores caller-supplied identity (fix #3)`, async () => {
    const store = await make();
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
    const store = await make();
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
    const store = await make();
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
    const store = await make();
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
    const store = await make();
    await store.saveRefreshToken(refresh("exp", "fam-e", null, PAST));
    assert.equal(await store.rotateRefreshToken(sha256Hex("exp"), refresh("next", "fam-e", sha256Hex("exp"), FUTURE), NOW), null);
    await store.close();
    await store.close(); // idempotent
    await assert.rejects(store.saveRefreshToken(refresh("closed", "fam-c", null, FUTURE)));
  });

  test(`${label}: findGrantedScopes derives the union from active refresh records`, async () => {
    const store = await make();
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
    const store = await make();
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

  test(`${label}: findGrantedScopes binds scope accumulation to the exact resource`, async () => {
    const store = await make();
    await store.saveRefreshToken(refresh(
      "scope-resource-a", "fam-scope-resource-a", null, FUTURE,
      STORED_DCR_GRANT_GENERATION, RESOURCE_A,
    ));
    await store.saveRefreshToken({
      ...refresh(
        "scope-resource-b", "fam-scope-resource-b", null, FUTURE,
        STORED_DCR_GRANT_GENERATION, RESOURCE_B,
      ),
      scopes: ["mcp:write"],
    });
    const unbound = refresh(
      "scope-resource-unbound", "fam-scope-resource-unbound", null, FUTURE,
      STORED_DCR_GRANT_GENERATION,
    ) as { resource?: string } & Omit<SaveRefreshTokenInput, "resource">;
    delete unbound.resource;
    await store.saveRefreshToken({ ...unbound, scopes: ["mcp:admin"] } as SaveRefreshTokenInput);

    assert.deepEqual(
      await store.findGrantedScopes(
        "subject-1", "client-1", NOW, STORED_DCR_GRANT_GENERATION, RESOURCE_A,
      ),
      ["mcp:read"],
      "resource A excludes resource B and unbound legacy families",
    );
    assert.deepEqual(
      await store.findGrantedScopes(
        "subject-1", "client-1", NOW, STORED_DCR_GRANT_GENERATION, RESOURCE_B,
      ),
      ["mcp:write"],
      "resource B excludes resource A and unbound legacy families",
    );
    assert.deepEqual(
      await store.findGrantedScopes(
        "subject-1", "client-1", NOW, STORED_DCR_GRANT_GENERATION, "https://api-c.test/mcp",
      ),
      [],
      "an unrelated resource cannot inherit scopes",
    );
    await store.close();
  });
}
