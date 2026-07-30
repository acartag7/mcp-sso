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

test("unattested legacy scopes never reach a grant for a replacement resource", async () => {
  // The read/write split was wrong. `findGrantedScopes` was allowed to count
  // legacy null rows on any one-entry catalog because it "only reads" — but
  // approve() UNIONS the result into the authorization code. During an A-to-B
  // singleton URL change, an unattested legacy `admin` grant from A landed in a
  // B code while the consent page showed only the newly requested scope.
  const { OAuthAuthorizationUseCase } = await import("../src/authorize.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync, createHash } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { noopAudit } = await import("../src/ports/audit.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const sha = (v: string) => createHash("sha256").update(v).digest("hex");
  const REPLACEMENT = "https://new-resource.test/mcp";

  const clients = {
    m: new Map<string, unknown>(),
    async save(c: { clientId: string }) { this.m.set(c.clientId, c); },
    async find(id: string) { return this.m.get(id) ?? null; },
  };
  await clients.save({ clientId: "stored-client", redirectUris: ["https://c.test/cb"], applicationType: "web" } as never);

  const config = createBridgeConfig({
    issuer: "https://iss.test", resource: REPLACEMENT,
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], scopeCatalog: ["read", "admin"], defaultScopes: ["read"],
    allowedOrigins: ["https://iss.test"], dcr: { mode: "stored", store: clients },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    // deliberately NO legacySingletonResource
  } as never);

  const store = new MemoryStore();
  await store.saveRefreshToken({
    tokenHash: sha("legacy-token"), familyId: "legacyfamily000000001", previousTokenHash: null,
    clientId: "stored-client", subject: "user-1", scopes: ["admin"],
    expiresAt: "2099-01-01T00:00:00.000Z", grantGeneration: 1,
  });

  const auth = new OAuthAuthorizationUseCase({ config, store, clock: new SystemClock(), audit: noopAudit });
  const prepared = await auth.prepare({
    clientId: "stored-client", redirectUri: "https://c.test/cb", responseType: "code",
    codeChallenge: "x".repeat(43), codeChallengeMethod: "S256",
    subject: "user-1", scope: "read", resource: REPLACEMENT,
  } as never);
  const approved = await auth.approve({
    consentToken: prepared.consentToken, approved: true, origin: "https://iss.test",
  } as never);

  const code = new URL(approved.redirectTo!).searchParams.get("code")!;
  const record = await store.consumeAuthCode(sha(code), new Date().toISOString(), 1);
  assert.ok(record, "the code was saved");
  assert.ok(!record!.scopes.includes("admin"),
    `an unattested legacy scope must not enter a grant for a replacement resource, got ${JSON.stringify(record!.scopes)}`);
  assert.deepEqual(record!.scopes, ["read"], "only what the consent page actually showed");
});

test("a resource whose CANONICAL form exceeds storage is rejected at boot", () => {
  // The cap bounded the raw input only. WHATWG percent-encodes every non-ASCII
  // byte, so a 2 KB raw resource can serialize to ~6 KB: the deployment booted
  // and then failed every store write against the VARCHAR(2048) columns.
  const inflating = `https://a.test/${"é".repeat(1000)}`;   // ~2015 raw bytes
  assert.ok(Buffer.byteLength(inflating, "utf8") <= 2048, "raw input passes the byte cap");
  assert.throws(() => canonicalResource(inflating, OPT), /canonicalizes to/);
  // ASCII of the same raw size still fits, and a shorter non-ASCII path is fine.
  assert.doesNotThrow(() => canonicalResource(`https://a.test/${"x".repeat(2000)}`, OPT));
  assert.doesNotThrow(() => canonicalResource(`https://a.test/${"é".repeat(300)}`, OPT));
});

test("machine provisioning validates deps against the bridge's own catalog", async () => {
  // The context built a THROWAWAY catalog from whatever deps carried, so
  // provisioning accepted an unconfigured resource, one resource paired with
  // another's scopes, or invented scopes. Nothing was minted — token-time checks
  // still rejected the credential — but it failed LATE: provisioning reported
  // success and every use then failed, with no signal where the mistake was made.
  const { provisionMachineClient } = await import("../src/machine-client.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { noopAudit } = await import("../src/ports/audit.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

  class Store {
    rows = new Map<string, { clientId: string; resource?: string }>();
    machineClientResourceBinding = 1 as const;
    storedDcrGrantGeneration = 1 as const;
    async find(id: string) { return this.rows.get(id) ?? null; }
    async save(c: { clientId: string }) { this.rows.set(c.clientId, c); }
    async createMachineClient(rec: { clientId: string }) { this.rows.set(rec.clientId, rec); return true; }
    async compareAndSwapMachineClient(_v: number, next: { clientId: string }) { this.rows.set(next.clientId, next); return true; }
  }
  const store = new Store();
  const config = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stored", store }, clientCredentials: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
      { resource: B, scopeCatalog: ["shared", "b:only"], defaultScopes: ["shared"] },
    ],
  } as never);
  const deps = (resource: string, catalog: string[]) =>
    ({ store, catalog, resource, config, clock: new SystemClock(), audit: noopAudit }) as never;

  await assert.rejects(() => provisionMachineClient(deps(A, ["b:only"]), { allowedScopes: ["b:only"] }),
    /not in the scope catalog/, "A must not be provisioned with B's scope");
  await assert.rejects(() => provisionMachineClient(deps("https://evil.test/mcp", ["shared"]), { allowedScopes: ["shared"] }),
    /not a configured resource/, "an unconfigured resource must be rejected");
  await assert.rejects(() => provisionMachineClient(deps(A, ["invented"]), { allowedScopes: ["invented"] }),
    /not in the scope catalog/, "an invented scope must be rejected");
  // The legitimate pairing still provisions.
  assert.ok(await provisionMachineClient(deps(A, ["shared"]), { allowedScopes: ["shared"] }));
});

test("stored-lineage canonicality agrees with the real parser in both directions", async () => {
  // The helper is a dependency-free restatement of the canonical form, so it can
  // drift from the parser that actually produces those values. It accepted
  // malformed percent escapes the parser rejects — values this library could
  // never have written, which then read as retryable mismatches instead of
  // unusable records. This pins the two-way agreement, not one example.
  const { isCanonicalStoredResource } = await import("../src/ports/store.ts");
  const DEV = { allowInsecureLocalhost: true } as const;

  for (const raw of [
    "https://a.test/mcp", "https://a.test", "https://a.test/mcp/", "http://localhost/mcp",
    "https://a.test:8443/mcp", "https://a.test/%6dcp", "https://A.test/MCP", "https://a.test:443/mcp",
    // Scheme-specific default ports: only https:443 and http:80 are stripped, so
    // these two are legitimate non-default ports the parser preserves.
    "https://a.test:80/mcp", "http://localhost:443/mcp",
    "http://localhost:80/mcp", "https://a.test/a/../mcp",
  ]) {
    const emitted = canonicalResource(raw, DEV);
    assert.ok(isCanonicalStoredResource(emitted),
      `the parser emits ${emitted}, so stored-lineage validation must accept it`);
  }
  for (const notCanonical of [
    "https://h/%zz", "https://h/%", "https://h/%2",        // malformed escapes
    "https://h:abc/a", "https://h:99999/a", "https://h::1/a", "https://[bad/a",  // bad authority
    "not-a-url", "https://A.test/mcp", "https://a.test:443/mcp", "http://a.test:80/mcp",
    "https://a.test/", "https://u@a.test/mcp", "https://a.test/mcp?x=1", "",
  ]) {
    assert.ok(!isCanonicalStoredResource(notCanonical),
      `${JSON.stringify(notCanonical)} is not a value this library writes`);
  }
});

test("machine deps must carry the resource's WHOLE catalog, not a subset", async () => {
  // The check was one-way: it caught invented scopes but not a shrunken catalog,
  // so a scope the bridge really does configure was rejected — and the error
  // blamed allowedScopes rather than the deps that were actually wrong.
  const { provisionMachineClient } = await import("../src/machine-client.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { noopAudit } = await import("../src/ports/audit.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

  class Store {
    rows = new Map<string, { clientId: string }>();
    machineClientResourceBinding = 1 as const;
    storedDcrGrantGeneration = 1 as const;
    async find(id: string) { return this.rows.get(id) ?? null; }
    async save(c: { clientId: string }) { this.rows.set(c.clientId, c); }
    async createMachineClient(rec: { clientId: string }) { this.rows.set(rec.clientId, rec); return true; }
    async compareAndSwapMachineClient(_v: number, next: { clientId: string }) { this.rows.set(next.clientId, next); return true; }
  }
  const store = new Store();
  const config = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stored", store }, clientCredentials: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [{ resource: A, scopeCatalog: ["read", "write"], defaultScopes: ["read"] }],
  } as never);
  const deps = (catalog: string[]) =>
    ({ store, catalog, resource: A, config, clock: new SystemClock(), audit: noopAudit }) as never;

  await assert.rejects(() => provisionMachineClient(deps(["read"]), { allowedScopes: ["read"] }),
    /omits "write"/, "a subset catalog is rejected at the deps, where the mistake is");
  // The complete catalog provisions, including the scope the subset would have hidden.
  assert.ok(await provisionMachineClient(deps(["read", "write"]), { allowedScopes: ["write"] }));
});

test("upgrading a REAL v0.3.2 database can still complete a consent approval", async () => {
  // The fixture is generated by the RELEASED v0.3.2 migration code, not by a
  // hand-written guess at its schema. An earlier version of this test invented a
  // schema with no resource column anywhere; that shape never shipped —
  // oauth_auth_codes has carried `resource` since the first store commit — so it
  // pinned a defect that did not exist. Upgrade fixtures come from released
  // artifacts, never from memory.
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { DatabaseSync } = await import("node:sqlite");
  const { openSqliteStore } = await import("../src/store/sqlite.ts");

  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-v032-"));
  const modPath = join(dir, "released-schema.ts");
  writeFileSync(modPath, execFileSync("git", ["show", "cc9ab1c:src/store/sqlite-schema.ts"], { encoding: "utf8" }));
  const released = await import(modPath) as { migrateSqliteStore: (db: unknown) => void };

  const file = join(dir, "auth.db");
  const legacy = new DatabaseSync(file);
  released.migrateSqliteStore(legacy as unknown);        // the ACTUAL shipped v0.3.2 schema
  legacy.close();

  const store = openSqliteStore(file);        // 0.4 runs its own migration on top
  await store.saveAuthCode({
    codeHash: "a".repeat(64), clientId: "c1", subject: "u1",
    redirectUri: "https://c.test/cb", resource: A, scopes: ["read"],
    codeChallenge: "x".repeat(43), codeChallengeMethod: "S256",
    expiresAt: "2099-01-01T00:00:00.000Z", grantGeneration: 1,
  });
  assert.equal((await store.consumeAuthCode("a".repeat(64), "2026-07-30T12:00:00.000Z", 1))?.resource, A);

  // The refresh tables ARE the ones v0.3.2 lacked a resource column for, so
  // rotation against the migrated shape is the part that actually needed adding.
  await store.saveRefreshToken({
    tokenHash: "b".repeat(64), familyId: "fam-upgrade-0001", previousTokenHash: null,
    clientId: "c1", subject: "u1", scopes: ["read"],
    expiresAt: "2099-01-01T00:00:00.000Z", grantGeneration: 1, resource: A,
  });
  const rotated = await store.rotateRefreshToken(
    "b".repeat(64),
    { tokenHash: "c".repeat(64), familyId: "fam-upgrade-0001", previousTokenHash: "b".repeat(64),
      clientId: "c1", subject: "u1", scopes: ["read"], expiresAt: "2099-01-01T00:00:00.000Z" },
    "2026-07-30T12:00:00.000Z", 1, { resource: A, allowLegacySingletonBinding: false },
  );
  assert.ok(rotated && !("status" in rotated), "an upgraded database can rotate refresh tokens");
  await store.close();
});

test("the legacy machine attestation is refused under a multi-resource catalog", async () => {
  // The context builds a throwaway ONE-entry catalog, which marked the
  // attestation valid even for a multi-resource bridge — letting a rotate or
  // disable bind a pre-0.4 unbound credential to whichever resource the caller
  // selected. Multi-resource mode forbids legacy binding entirely.
  const { machineClientResourceContext } = await import("../src/machine-client-resource.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { noopAudit } = await import("../src/ports/audit.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

  class Store {
    rows = new Map<string, unknown>();
    machineClientResourceBinding = 1 as const;
    storedDcrGrantGeneration = 1 as const;
    async find() { return null; }
    async save() {}
    async createMachineClient() { return true; }
    async compareAndSwapMachineClient() { return true; }
  }
  const store = new Store();
  const multiCfg = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stored", store }, clientCredentials: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
      { resource: B, scopeCatalog: ["shared"], defaultScopes: ["shared"] },
    ],
  } as never);

  assert.throws(() => machineClientResourceContext({
    store, catalog: ["shared"], resource: A, legacySingletonResource: A,
    config: multiCfg, clock: new SystemClock(), audit: noopAudit,
  } as never), /not accepted under a multi-resource configuration/);
  // Without the attestation the same multi-resource context is fine.
  assert.ok(machineClientResourceContext({
    store, catalog: ["shared"], resource: A,
    config: multiCfg, clock: new SystemClock(), audit: noopAudit,
  } as never));
});

test("a one-entry `resources` config still forbids the legacy attestation", async () => {
  // Keyed on the configuration KIND, not the entry count. `{ resources: [one] }`
  // is a valid multi-resource configuration that happens to list one entry
  // today; counting entries called it a singleton and re-admitted the
  // attestation, letting an ambiguous pre-0.4 credential be reattributed.
  const { machineClientResourceContext } = await import("../src/machine-client-resource.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { SystemClock } = await import("../src/ports/clock.ts");
  const { noopAudit } = await import("../src/ports/audit.ts");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

  class Store {
    machineClientResourceBinding = 1 as const;
    storedDcrGrantGeneration = 1 as const;
    async find() { return null; }
    async save() {}
    async createMachineClient() { return true; }
    async compareAndSwapMachineClient() { return true; }
  }
  const store = new Store();
  const oneEntryMulti = createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stored", store }, clientCredentials: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resources: [{ resource: A, scopeCatalog: ["shared"], defaultScopes: ["shared"] }],
  } as never);

  assert.throws(() => machineClientResourceContext({
    store, catalog: ["shared"], resource: A, legacySingletonResource: A,
    config: oneEntryMulti, clock: new SystemClock(), audit: noopAudit,
  } as never), /multi-resource configuration/,
    "one entry in the `resources` form is still the multi-resource form");
});

test("PRM route characters are allowlisted, not blocklisted", async () => {
  // A blocklist of router metacharacters was wrong twice: it missed `!`, which
  // the pinned Express/path-to-regexp reserves, so mounting threw MID-REGISTRATION
  // — after the authorization-server route was already added — instead of failing
  // as the promised pre-side-effect AuthConfigError. Each framework reserves its
  // own set, so only characters safe as a literal route everywhere are accepted.
  const { planProtectedResourceRoutes } = await import("../src/adapters/protected-resource-routes.ts");
  const { createBridgeConfig } = await import("../src/config.ts");
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const cfg = (path: string) => createBridgeConfig({
    issuer: "https://iss.test", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
    redirectAllowlist: ["https://c.test/cb"], allowedOrigins: ["https://iss.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    resource: `https://h${path}`, scopeCatalog: ["x"], defaultScopes: ["x"],
  } as never);

  // pchar minus what the routers reserve — verified against all three, not
  // assumed. Narrowing further would reject resources the config accepts,
  // leaving a bridge unable to serve its own contracted metadata route.
  for (const ok of ["/mcp", "/a-b.c_d~e/mcp", "/%6dcp", "/mcp;v=1", "/mcp,a", "/mcp@v", "/mcp$x", "/mcp&y"]) {
    assert.ok(planProtectedResourceRoutes(cfg(ok)), `${ok} is safe as a literal route`);
  }
  // Anything a router might reserve is refused BEFORE any route is registered.
  for (const bad of ["/mcp/!x", "/mcp/:id", "/mcp/*rest", "/mcp/(x)", "/mcp/x+y"]) {
    assert.throws(() => planProtectedResourceRoutes(cfg(bad)), /not safe to register as a literal route/,
      `${bad} must fail preflight`);
  }
});
