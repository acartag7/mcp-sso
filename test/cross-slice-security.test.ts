// Cross-slice security regression suite.
//
// Every property here was fixed in an EARLIER slice, and two of them were later
// reverted — silently — when a subsequent slice rewrote the same file. The
// branch-local regression tests did not notice, because they lived on the branch
// where the fix was made, not the branch that ships.
//
// These re-assert every slice's security property against whatever code is
// actually in the tree, so a rewrite that drops one turns this red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceCatalog, canonicalResource, resolveResource } from "../src/resource.ts";
import { INVALID_RESOURCE, resourceParam } from "../src/adapters/http.ts";
import { MemoryStore } from "../src/store/memory.ts";

const OPT = { allowInsecureLocalhost: false } as const;
const A = "https://a.test/mcp";
const B = "https://b.test/mcp";
const multi = buildResourceCatalog({ resources: [
  { resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
  { resource: B, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
] } as never, OPT);
const throws = (fn: () => unknown) => assert.throws(fn);

test("MR1a: the catalog validates and publishes the SAME snapshot", () => {
  throws(() => buildResourceCatalog({ resources: [
    { get resource() { return A; }, scopeCatalog: ["x"], defaultScopes: ["x"] }] } as never, OPT));
  throws(() => buildResourceCatalog({ resources: [
    Object.create({ resource: A, scopeCatalog: ["x"], defaultScopes: ["x"] })] } as never, OPT));
  throws(() => buildResourceCatalog({
    resources: [{ resource: A, scopeCatalog: ["x"], defaultScopes: ["x"] }], resource: undefined } as never, OPT));
  throws(() => buildResourceCatalog({ resources: [
    { resource: A, scopeCatalog: ["x"], defaultScopes: ["x"], evil: 1 }] } as never, OPT));
  throws(() => buildResourceCatalog({ resources: [
    { resource: "https://A.test/mcp", scopeCatalog: ["x"], defaultScopes: ["x"] },
    { resource: "https://a.test:443/mcp", scopeCatalog: ["y"], defaultScopes: ["y"] }] } as never, OPT));
});

test("MR1a: resource identifiers are byte-capped before any scan", () => {
  // Reverted once by a later slice's rewrite of resource.ts.
  assert.equal(canonicalResource(`https://a.test/${"x".repeat(2000)}`, OPT), `https://a.test/${"x".repeat(2000)}`);
  throws(() => canonicalResource(`https://a.test/${"x".repeat(2100)}`, OPT));
  throws(() => canonicalResource(`https://a.test/${"é".repeat(1100)}`, OPT));
});

test("MR3: the boundary never collapses an invalid resource into omission", () => {
  // Reverted once by a later slice's rewrite of bridge.ts + http.ts.
  assert.equal(resourceParam(""), INVALID_RESOURCE);
  assert.equal(resourceParam([A, B]), INVALID_RESOURCE);
  assert.equal(resourceParam(42), INVALID_RESOURCE);
  assert.equal(resourceParam(null), INVALID_RESOURCE);
  assert.equal(resourceParam(undefined), undefined, "genuine omission is preserved");
  assert.equal(resourceParam(A), A);
  throws(() => resolveResource(multi, INVALID_RESOURCE));
});

test("MR3: request selection is fail-closed under a multi-resource catalog", () => {
  throws(() => resolveResource(multi, undefined));
  throws(() => resolveResource(multi, "https://evil.test/mcp"));
  assert.equal(resolveResource(multi, A).resource, A);
  assert.equal(resolveResource(multi, B).resource, B);
});

const iso = (d = 0) => new Date(Date.now() + d).toISOString();
const h = (c: string) => c.repeat(64);
const rec = (t: string, p: string | null) => ({
  tokenHash: h(t), familyId: "f1", previousTokenHash: p ? h(p) : null,
  clientId: "c1", subject: "u1", scopes: ["shared"], expiresAt: iso(3600e3),
});

test("MR2: replaying an OLDER consumed member of a bound legacy chain revokes the family", async () => {
  const store = new MemoryStore();
  const attest = { resource: A, allowLegacySingletonBinding: true };
  await store.saveRefreshToken(rec("a", null));
  await store.rotateRefreshToken(h("a"), rec("b", "a"), iso());               // old binary
  await store.rotateRefreshToken(h("b"), rec("c", "b"), iso(), undefined, attest); // upgrade binds
  assert.equal(await store.rotateRefreshToken(h("a"), rec("d", "a"), iso(), undefined, attest), null);
  assert.equal(await store.rotateRefreshToken(h("c"), rec("e", "c"), iso(), undefined, attest), null,
    "the replay revoked the whole family");
  await store.close();
});

test("MR2: a wrong-resource guess rejects without mutating (no cross-resource DoS)", async () => {
  const store = new MemoryStore();
  await store.saveRefreshToken({ ...rec("1", null), resource: A });
  const mismatch = await store.rotateRefreshToken(
    h("1"), { ...rec("2", "1"), resource: A }, iso(), undefined,
    { resource: B, allowLegacySingletonBinding: false });
  assert.deepEqual(mismatch, { status: "resource_mismatch" });
  const rotated = await store.rotateRefreshToken(
    h("1"), { ...rec("2", "1"), resource: A }, iso(), undefined,
    { resource: A, allowLegacySingletonBinding: false });
  assert.ok(rotated && !("status" in rotated), "the mismatch consumed nothing");
  await store.close();
});
