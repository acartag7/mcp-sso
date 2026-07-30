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
import type { AuthAuditEvent } from "../src/ports/audit.ts";

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

test("Codex P2: auth.request carries the pinned resource on success AND failure", async () => {
  // The authorizer's resource is resolved at CONSTRUCTION from trusted config, so
  // it is known even when the token is not. Omitting it left operators unable to
  // tell WHICH protected resource accepted or rejected a token — the one fact a
  // multi-resource audit trail exists to record.
  const { RequestAuthorizer } = await import("../src/verifier.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const events: AuthAuditEvent[] = [];

  const config = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
      { resource: B, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
    ],
  } as never);

  const authorizer = new RequestAuthorizer({
    config, resource: B, clock: { nowMs: () => Date.now() },
    audit: { async writeAuthEvent(e: AuthAuditEvent) { events.push(e); } },
  });
  await assert.rejects(() => authorizer.authorize({ authorization: "Bearer nope" }));
  assert.equal(events.length, 1);
  assert.equal(events[0]?.event, "auth.request");
  assert.equal(events[0]?.status, "failure");
  assert.equal(events[0]?.resource, B, "a rejection must still name the endpoint that rejected");
});

test("code exchange rejects a resource that disagrees with the code's lineage", async () => {
  // Third occurrence of "the parameter never reaches its guard" — after refresh
  // and the HTTP boundary. The stored record stays authoritative for signing, so
  // no wrong-audience token was ever minted; the defect was that a request naming
  // a DIFFERENT resource was silently accepted instead of invalid_target.
  const { assertRequestResourceMatchesRecord } = await import("../src/token-resource.ts");
  const { OAuthError } = await import("../src/errors.ts");
  const isTarget = (e: unknown) => e instanceof OAuthError && e.code === "invalid_target";

  // A code bound to A, exchanged while naming B.
  assert.throws(() => assertRequestResourceMatchesRecord(multi, A, B), isTarget);
  // ...and the mirror direction.
  assert.throws(() => assertRequestResourceMatchesRecord(multi, B, A), isTarget);
  // Matching request is accepted.
  assert.doesNotThrow(() => assertRequestResourceMatchesRecord(multi, A, A));
  // Omission cannot select for a multi-entry catalog.
  assert.throws(() => assertRequestResourceMatchesRecord(multi, A, undefined), isTarget);
  // An unknown request resource is rejected, never matched loosely.
  assert.throws(() => assertRequestResourceMatchesRecord(multi, A, "https://evil.test/mcp"), isTarget);
});

test("stored lineage errors distinguish unusable from retryable", async () => {
  // The distinction is client-facing: invalid_target tells a client to retry
  // another resource; invalid_grant tells it to discard an unusable grant.
  // Persisted lineage is always written canonical, so a malformed or
  // non-canonical stored value means the RECORD is broken, not the request.
  const { resolveRecordResource } = await import("../src/token-resource.ts");
  const { OAuthError } = await import("../src/errors.ts");
  const code = (fn: () => unknown): string => {
    try { fn(); return "no-throw"; } catch (e) { return e instanceof OAuthError ? e.code : "other"; }
  };

  assert.equal(code(() => resolveRecordResource(multi, null)), "invalid_grant", "absent lineage");
  assert.equal(code(() => resolveRecordResource(multi, "")), "invalid_grant", "empty lineage");
  assert.equal(code(() => resolveRecordResource(multi, "not-a-url")), "invalid_grant", "malformed lineage");
  assert.equal(code(() => resolveRecordResource(multi, "https://A.test/mcp")), "invalid_grant",
    "non-canonical spelling means the record was not written by this library");
  assert.equal(code(() => resolveRecordResource(multi, "https://a.test:443/mcp")), "invalid_grant",
    "default-port spelling is likewise non-canonical");
  // A well-formed canonical resource that is simply no longer configured stays
  // retryable — that is the case invalid_target exists for.
  assert.equal(code(() => resolveRecordResource(multi, "https://gone.test/mcp")), "invalid_target");
  assert.equal(code(() => resolveRecordResource(multi, A)), "no-throw");
});

test("scope arrays are snapshotted once, not validated then re-read", () => {
  // validate-then-re-read is this repo's recurring validate-vs-publish class.
  // Both scope validators now build one copy and validate THAT copy, so a
  // stateful array cannot answer differently to validation and to construction.
  let reads = 0;
  const counting = new Proxy(["ok"], {
    get(t, p, r) {
      if (typeof p === "string" && /^\d+$/.test(p)) reads++;
      return Reflect.get(t, p, r);
    },
  });
  const cat = buildResourceCatalog(
    { resources: [{ resource: A, scopeCatalog: counting, defaultScopes: ["ok"] }] } as never,
    OPT,
  );
  assert.deepEqual([...cat.entries[0]!.scopeCatalog], ["ok"]);
  assert.equal(reads, 1, `each element must be read exactly once, got ${reads} reads`);
});

test("post-resolution authorize failures name the resource; pre-resolution ones do not", async () => {
  // §13: once a canonical resource is established — from the catalog, or from
  // VERIFIED signed lineage — a failure event carries it, so an operator can
  // attribute the failure to a target. Before that boundary the field is omitted
  // rather than echoing unvalidated request text.
  const { OAuthAuthorizationUseCase } = await import("../src/authorize.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const events: AuthAuditEvent[] = [];

  const config = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
      { resource: B, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
    ],
  } as never);

  const auth = new OAuthAuthorizationUseCase({
    config, store: new MemoryStore(), clock: new SystemClock(),
    audit: { async writeAuthEvent(e: AuthAuditEvent) { events.push(e); } },
  });

  // Resource B resolves, THEN the PKCE method check fails (it runs after
  // selection, inside the same try) => the failure event must name B.
  await assert.rejects(() => auth.prepare({
    clientId: "c1", redirectUri: "https://c.test/cb", responseType: "code",
    codeChallenge: "x".repeat(43), codeChallengeMethod: "plain",
    subject: "u@test", resource: B,
  } as never));
  const afterResolve = events.at(-1);
  assert.equal(afterResolve?.status, "failure");
  assert.equal(afterResolve?.resource, B, "a post-resolution failure attributes to its target");

  // An UNKNOWN resource never resolves => the field must be absent, not guessed.
  events.length = 0;
  await assert.rejects(() => auth.prepare({
    clientId: "c1", redirectUri: "https://c.test/cb", responseType: "code",
    codeChallenge: "x".repeat(43), codeChallengeMethod: "S256",
    subject: "u@test", resource: "https://evil.test/mcp",
  } as never));
  assert.equal(events.at(-1)?.resource, undefined, "pre-resolution failures omit the field");
});

test("pairing round-trip does not collapse a repeated resource", async () => {
  // The pairing form carries authorize params through hidden fields. Reading
  // them with the general query helper made resource=A&resource=B authorize A
  // (first-wins) — the fourth place this parameter failed to reach its guard.
  const { gatherPairingOAuthParams } = await import("../src/adapters/pairing-flow.ts");
  const req = { query: { resource: [A, B], client_id: "c1" }, body: undefined, headers: {} };
  const params = gatherPairingOAuthParams(req as never);
  assert.notEqual(params.resource, A, "a repeated resource must NOT become first-wins");
  assert.equal(params.resource, INVALID_RESOURCE, "it carries the sentinel so authorize rejects it");
  assert.throws(() => resolveResource(multi, params.resource!));
  // A single valid value still round-trips untouched.
  const ok = gatherPairingOAuthParams({ query: { resource: A }, body: undefined, headers: {} } as never);
  assert.equal(ok.resource, A);
});
