// Machine-client provisioning primitives (contracts §17.2). Covers: provision
// (secret-returned-once, hashes-only storage, allowedScopes⊆catalog, TTL),
// rotation (max-2-active grace invariant, unknown/non-machine rejection), the
// timing-safe verify primitive (+ expiry), audit emission (no secret/hash
// leak), the open-DCR machine-shape rejection, the redirect-policy
// defense-in-depth guard, and the clientCredentials boot rule. The
// /oauth/token grant that consumes these records is S3b.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ClientRegistration, ClientStore, MachineClientRegistration } from "../src/ports/client-store.ts";
import { AuthConfigError, createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import { sha256Hex } from "../src/crypto.ts";
import { registerClient } from "../src/register.ts";
import { assertRedirectAllowedForClient } from "../src/redirect.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { MemoryStore } from "../src/store/memory.ts";
import {
  provisionMachineClient, rotateMachineClientSecret, verifyMachineClientSecret,
  rotateSecrets, DEFAULT_ROTATION_GRACE_SECONDS,
  type MachineClientDeps,
} from "../src/machine-client.ts";

const NOW_MS = Date.parse("2026-07-06T12:00:00.000Z");
const CATALOG = ["mcp:read", "mcp:write", "mcp:admin"];

class FakeClock implements ClockPort {
  private ms: number;
  constructor(ms: number) { this.ms = ms; }
  nowMs(): number { return this.ms; }
  advance(ms: number): void { this.ms += ms; }
}

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

class InMemoryClientStore implements ClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

interface Harness { deps: MachineClientDeps; store: InMemoryClientStore; clock: FakeClock; audit: MemoryAudit; }

/** Narrow a stored record to MachineClientRegistration (these tests only ever
 *  load provisioned machine clients). Asserts the discriminant first. */
async function machineRecord(store: InMemoryClientStore, clientId: string): Promise<MachineClientRegistration> {
  const r = await store.find(clientId);
  assert.equal(r?.applicationType, "machine");
  return r as MachineClientRegistration;
}

function harness(catalog: readonly string[] = CATALOG): Harness {
  const store = new InMemoryClientStore();
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  return { deps: { store, catalog, clock, audit }, store, clock, audit };
}

function testJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k1" } as JWK;
}

function storedConfig(store: ClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40), signingPrivateJwk: testJwk(), signingKeyId: "k1",
    redirectAllowlist: ["https://client.test/callback"], scopeCatalog: [...CATALOG], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stored", store },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

// ---------- provision ----------

test("provision: returns mcc_ clientId + mcs_ secret once; stores hashes only", async () => {
  const h = harness();
  const res = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read", "mcp:write"] });
  assert.match(res.clientId, /^mcc_[A-Za-z0-9_-]{16,}$/);
  assert.match(res.clientSecret, /^mcs_[A-Za-z0-9_-]{43}$/); // base64url(32) = 43 chars → 256 bits
  const record = await machineRecord(h.store, res.clientId);
  assert.equal(record?.applicationType, "machine");
  assert.deepEqual(record?.redirectUris, []);
  assert.deepEqual(record?.allowedScopes, ["mcp:read", "mcp:write"]);
  assert.equal(record?.secrets.length, 1);
  assert.equal(record!.secrets[0]!.hash, sha256Hex(res.clientSecret));
  assert.equal(record!.secrets[0]!.expiresAtEpoch, undefined); // no TTL ⇒ live until rotated
  assert.equal(record!.secrets[0]!.createdAtEpoch, Math.floor(NOW_MS / 1000));
  // The raw secret is NOT in the stored record — only its hash.
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes(res.clientSecret), false, "raw secret must not be persisted");
});

test("provision: secretTtlSeconds sets the first secret's expiresAtEpoch", async () => {
  const h = harness();
  const res = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"], secretTtlSeconds: 3600 });
  const record = await machineRecord(h.store, res.clientId);
  assert.equal(record!.secrets[0]!.expiresAtEpoch, Math.floor(NOW_MS / 1000) + 3600);
});

test("provision: allowedScopes must be a non-empty subset of the catalog (single tokens)", async () => {
  const h = harness();
  for (const bad of [
    [], ["mcp:nope"], ["unknown"], ["mcp:read mcp:write"], [123],
  ]) {
    await assert.rejects(() => provisionMachineClient(h.deps, { allowedScopes: bad as string[] }), (e: unknown) => {
      assert.ok(e instanceof OAuthError && e.code === "invalid_scope", `expected invalid_scope for ${JSON.stringify(bad)}`);
      return true;
    });
  }
  // Duplicates are de-duped (a subset), not rejected — matches normalizeScopes.
  const res = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read", "mcp:read"] });
  const record = await machineRecord(h.store, res.clientId);
  assert.deepEqual(record?.allowedScopes, ["mcp:read"]);
});

test("provision: rejects a bad secretTtlSeconds and a non-string name", async () => {
  const h = harness();
  for (const ttl of [0, -1, 1.5, "x"]) {
    await assert.rejects(() => provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"], secretTtlSeconds: ttl as number }), (e: unknown) => {
      assert.ok(e instanceof OAuthError && e.code === "invalid_request");
      return true;
    });
  }
  await assert.rejects(() => provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"], name: 42 as unknown as string }), (e: unknown) => {
    assert.ok(e instanceof OAuthError && e.code === "invalid_request");
    return true;
  });
});

// ---------- rotation ----------

test("rotation: from a single secret yields exactly [old-grace, new-live]", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const oldHash = (await machineRecord(h.store, prov.clientId)).secrets[0]!.hash;
  h.clock.advance(1000);
  const rot = await rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: 3600 });
  assert.match(rot.clientSecret, /^mcs_[A-Za-z0-9_-]{43}$/);
  const record = await machineRecord(h.store, prov.clientId);
  assert.equal(record?.secrets.length, 2, "exactly two active secrets after rotation");
  const [grace, live] = record!.secrets;
  assert.equal(grace!.hash, oldHash, "old secret retained as grace");
  assert.equal(grace!.expiresAtEpoch, Math.floor((NOW_MS + 1000) / 1000) + 3600);
  assert.equal(live!.hash, sha256Hex(rot.clientSecret));
  assert.equal(live!.expiresAtEpoch, undefined, "new secret is live (no expiry)");
  assert.notEqual(rot.clientSecret, prov.clientSecret);
});

test("rotation: default grace is 24h; new secret verified, old still accepted during overlap", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const rot = await rotateMachineClientSecret(h.deps, prov.clientId); // no opts ⇒ default grace
  const record = await machineRecord(h.store, prov.clientId);
  assert.equal(record!.secrets[0]!.expiresAtEpoch, Math.floor(NOW_MS / 1000) + DEFAULT_ROTATION_GRACE_SECONDS);
  // Both old and new are accepted during the overlap window.
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, prov.clientSecret), true);
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, rot.clientSecret), true);
});

test("rotation: holds the two-active cap across rapid successive rotations", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  h.clock.advance(1000);
  await rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: 86_400 });
  h.clock.advance(2000); // still inside the first grace window
  await rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: 86_400 });
  let record = await machineRecord(h.store, prov.clientId);
  assert.equal(record?.secrets.length, 2, "never more than two active secrets");
  assert.equal(record!.secrets.filter((s) => s.expiresAtEpoch === undefined).length, 1, "exactly one live secret");
  // Advance past the grace of the now-demoted secret, then rotate again → expired entry evicted.
  h.clock.advance(86_400 * 1000 + 5000);
  await rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: 86_400 });
  record = await machineRecord(h.store, prov.clientId);
  assert.equal(record?.secrets.length, 2, "expired secret evicted, still capped at two");
  assert.equal(record!.secrets.filter((s) => s.expiresAtEpoch === undefined).length, 1);
});

test("rotation: rejects unknown / non-machine / malformed-record clientId with invalid_client 401", async () => {
  const h = harness();
  await assert.rejects(() => rotateMachineClientSecret(h.deps, "mcc_nope"), (e: unknown) => {
    assert.ok(e instanceof OAuthError && e.code === "invalid_client" && e.status === 401, "unknown ⇒ invalid_client 401");
    return true;
  });
  // A user client in the same store is not rotatable.
  const user: ClientRegistration = { clientId: "mcpdc_user1", redirectUris: ["https://client.test/callback"], applicationType: "web", issuedAtEpoch: 1 };
  await h.store.save(user);
  await assert.rejects(() => rotateMachineClientSecret(h.deps, "mcpdc_user1"), (e: unknown) => {
    assert.ok(e instanceof OAuthError && e.code === "invalid_client" && e.status === 401, "non-machine ⇒ invalid_client 401");
    return true;
  });
  // A machine record whose secrets is not an array (a buggy/malicious custom
  // ClientStore) yields a CONTROLLED invalid_client, not a raw TypeError.
  await h.store.save({ clientId: "mcc_bad", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: undefined as unknown as never[] });
  await assert.rejects(() => rotateMachineClientSecret(h.deps, "mcc_bad"), (e: unknown) => {
    assert.ok(e instanceof OAuthError && e.code === "invalid_client", "malformed secrets ⇒ controlled invalid_client (no raw TypeError)");
    return true;
  });
});

test("rotation: rejects a bad graceSeconds", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  for (const g of [0, -5, 1.5]) {
    await assert.rejects(() => rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: g }), (e: unknown) => {
      assert.ok(e instanceof OAuthError && e.code === "invalid_request");
      return true;
    });
  }
});

// ---------- rotateSecrets (pure model) ----------

test("rotateSecrets: [old→grace, new] from one; supersedes prior grace; evicts expired", () => {
  const now = 1000;
  const h1 = rotateSecrets([{ hash: "A", createdAtEpoch: 0 }], now, 600, "B");
  assert.deepEqual(h1.map((s) => s.hash), ["A", "B"]);
  assert.equal(h1[0]!.expiresAtEpoch, now + 600);
  assert.equal(h1[1]!.expiresAtEpoch, undefined);
  // Second rotation before the first grace elapses: the prior grace secret (A) is dropped.
  const h2 = rotateSecrets(h1, now + 100, 600, "C");
  assert.deepEqual(h2.map((s) => s.hash), ["B", "C"], "A superseded to hold the two-active cap");
  // After B's grace expires, it is evicted on the next rotation.
  const h3 = rotateSecrets(h2, now + 600 + 200, 600, "D");
  assert.deepEqual(h3.map((s) => s.hash), ["C", "D"], "expired B evicted");
  // An empty record yields a single live secret.
  assert.deepEqual(rotateSecrets([], now, 600, "Z").map((s) => s.hash), ["Z"]);
});

test("rotateSecrets: an already-expired secret is DROPPED, not resurrected (no grace revival)", () => {
  // Newest (and only) secret already expired (e.g. a TTL-provisioned secret that
  // was never rotated). Rotation must drop it, NOT demote it back to now+grace.
  const expired = [{ hash: "A", createdAtEpoch: 0, expiresAtEpoch: 500 }];
  const res = rotateSecrets(expired, 1000, 600, "B");
  assert.deepEqual(res.map((s) => s.hash), ["B"], "expired A dropped, not resurrected");
  assert.equal(res[0]!.expiresAtEpoch, undefined, "B is live");
});

test("rotateSecrets: a TTL-provisioned still-valid secret is demoted to now+grace (overrides prior expiry)", () => {
  // Provisioned with ttl=600 (exp=600); rotate at now=100 before it expires.
  // Per §17.2 the old secret expires at now+grace, overriding its birth TTL.
  const res = rotateSecrets([{ hash: "A", createdAtEpoch: 0, expiresAtEpoch: 600 }], 100, 600, "B");
  assert.deepEqual(res.map((s) => s.hash), ["A", "B"]);
  assert.equal(res[0]!.expiresAtEpoch, 100 + 600);
});

// ---------- verify (timing-safe primitive) ----------

test("verifyMachineClientSecret: correct true, wrong/expired/non-machine false, no throw", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"], secretTtlSeconds: 600 });
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, prov.clientSecret), true);
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, "mcs_" + "A".repeat(43)), false);
  assert.equal(await verifyMachineClientSecret(h.deps, "mcc_unknown", prov.clientSecret), false);
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, ""), false);
  // TTL expiry: advance past the provisioned secret's lifetime.
  h.clock.advance(601 * 1000);
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, prov.clientSecret), false, "expired secret rejected");
  // A user client is never a machine verification target.
  await h.store.save({ clientId: "mcpdc_u", redirectUris: [], applicationType: "web", issuedAtEpoch: 1 });
  assert.equal(await verifyMachineClientSecret(h.deps, "mcpdc_u", "anything"), false);
});

test("verifyMachineClientSecret: rotation grace keeps the old secret valid until expiry", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const rot = await rotateMachineClientSecret(h.deps, prov.clientId, { graceSeconds: 600 });
  h.clock.advance(599 * 1000); // still within grace
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, prov.clientSecret), true);
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, rot.clientSecret), true);
  h.clock.advance(2 * 1000); // past grace
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, prov.clientSecret), false, "old secret expired out of grace");
  assert.equal(await verifyMachineClientSecret(h.deps, prov.clientId, rot.clientSecret), true);
});

test("verifyMachineClientSecret: malformed / poisoned records fail closed (false, never throw)", async () => {
  const h = harness();
  const presented = "mcs_" + "A".repeat(43);
  // secrets not an array; secrets undefined; an entry missing hash; >2 active.
  const malformed: ClientRegistration[] = [
    { clientId: "m1", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: undefined as unknown as never[] },
    { clientId: "m2", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: [{ hash: "x", createdAtEpoch: 1 }] as never as never[] },
    { clientId: "m3", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: [
      { hash: "a".repeat(64), createdAtEpoch: 1 }, { hash: "b".repeat(64), createdAtEpoch: 1 }, { hash: "c".repeat(64), createdAtEpoch: 1 },
    ] },
  ];
  for (const m of malformed) {
    await h.store.save(m);
    // Must resolve to false, never reject (no raw TypeError on undefined/non-string).
    assert.equal(await verifyMachineClientSecret(h.deps, m.clientId, presented), false, `${m.clientId} must fail closed`);
  }
});

// ---------- audit (no secret / no hash leak) ----------

test("audit: provision + rotate emit metadata-only events (no secret, no hash, no mcs_)", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read", "mcp:write"], name: "ci-runner" });
  const rot = await rotateMachineClientSecret(h.deps, prov.clientId);
  const dump = JSON.stringify(h.audit.events);
  const provisionEvt = h.audit.events.find((e) => e.event === "oauth.client.provision" && e.status === "success");
  const rotateEvt = h.audit.events.find((e) => e.event === "oauth.client.rotate_secret" && e.status === "success");
  assert.deepEqual(provisionEvt?.scopes, ["mcp:read", "mcp:write"]);
  assert.equal(provisionEvt?.clientId, prov.clientId);
  assert.equal(rotateEvt?.clientId, prov.clientId);
  // No secret value, no secret hash, no secret prefix anywhere in the audit trail.
  for (const needle of [prov.clientSecret, rot.clientSecret, sha256Hex(prov.clientSecret), sha256Hex(rot.clientSecret), "mcs_", "hash"]) {
    assert.equal(dump.toLowerCase().includes(needle.toLowerCase()), false, `audit leaked '${needle}'`);
  }
  // No event carries a secret-bearing key.
  for (const e of h.audit.events) {
    for (const key of ["clientSecret", "secret", "secrets", "hash", "client_secret"]) {
      assert.equal(key in e, false, `event ${e.event} carried key '${key}'`);
    }
  }
});

test("audit: failed provision/rotate emit failure events with the OAuth reason", async () => {
  const h = harness();
  await assert.rejects(() => provisionMachineClient(h.deps, { allowedScopes: ["nope"] }));
  const provFail = h.audit.events.at(-1)!;
  assert.equal(provFail.event, "oauth.client.provision");
  assert.equal(provFail.status, "failure");
  assert.equal(provFail.reason, "invalid_scope");
});

// ---------- open DCR rejects machine-shape ----------

test("registerClient: rejects machine-shape signals with invalid_client_metadata", async () => {
  const h = harness();
  const cfg = storedConfig(h.store);
  const deps = { config: cfg, clock: h.clock, audit: h.audit };
  // token_endpoint_auth_method other than "none"
  await assert.rejects(
    () => registerClient(deps, { redirectUris: ["https://client.test/callback"], tokenEndpointAuthMethod: "client_secret_basic" }),
    (e: unknown) => { assert.equal((e as OAuthError).code, "invalid_client_metadata"); return true; },
  );
  // grant_types containing client_credentials
  await assert.rejects(
    () => registerClient(deps, { redirectUris: ["https://client.test/callback"], grantTypes: ["client_credentials"] }),
    (e: unknown) => { assert.equal((e as OAuthError).code, "invalid_client_metadata"); return true; },
  );
  // application_type:"machine" is a machine-shape signal too (RFC 7591 §3.2.1).
  await assert.rejects(
    () => registerClient(deps, { redirectUris: ["https://client.test/callback"], applicationType: "machine" }),
    (e: unknown) => { assert.equal((e as OAuthError).code, "invalid_client_metadata"); return true; },
  );
  // A normal user registration still succeeds.
  const ok = await registerClient(deps, { redirectUris: ["https://client.test/callback"], tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"] });
  assert.equal(ok.token_endpoint_auth_method, "none");
});

test("Bridge.handleRegister: machine-shape rejection surfaces as the RFC 7591 error body", async () => {
  const h = harness();
  const bridge = new Bridge({ config: storedConfig(h.store), store: new MemoryStore(), clock: h.clock, audit: h.audit });
  const res = await bridge.handleRegister({ query: {}, headers: {}, body: { redirect_uris: ["https://client.test/callback"], grant_types: ["client_credentials"] } });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_client_metadata", error_description: (res.body as { error_description: string }).error_description });
});

// ---------- redirect-policy defense-in-depth ----------

test("assertRedirectAllowedForClient: a machine client is rejected (invalid_client)", () => {
  const machine: ClientRegistration = { clientId: "mcc_x", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: [{ hash: "a".repeat(64), createdAtEpoch: 1 }] };
  assert.throws(() => assertRedirectAllowedForClient("http://localhost:1234/cb", machine), (e: unknown) => {
    assert.equal((e as OAuthError).code, "invalid_client");
    assert.equal((e as OAuthError).status, 401);
    return true;
  });
});

// ---------- clientCredentials boot rule ----------

test("config: clientCredentials.enabled requires dcr.mode 'stored'", () => {
  const cfg = (dcr: BridgeConfig["dcr"], clientCredentials?: { enabled: boolean }): unknown =>
    createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "x".repeat(40), signingPrivateJwk: testJwk(), signingKeyId: "k1",
      redirectAllowlist: ["https://client.test/callback"], scopeCatalog: [...CATALOG], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr, clientCredentials,
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  // enabled with stateless ⇒ boot failure.
  assert.throws(() => cfg({ mode: "stateless" }, { enabled: true }), (e: unknown) => {
    assert.ok(e instanceof AuthConfigError);
    return true;
  });
  // enabled with stored mode is accepted; disabled with stateless is accepted; malformed rejected.
  assert.ok(cfg({ mode: "stored", store: new InMemoryClientStore() }, { enabled: true }));
  assert.ok(cfg({ mode: "stateless" }, { enabled: false }));
  assert.throws(() => cfg({ mode: "stateless" }, { enabled: "yes" as unknown as boolean }));
});

// ---------- regression: user DCR/authorize still round-trips through the union store ----------

test("regression: a user client registered via the union ClientStore still authorizes", async () => {
  const h = harness();
  const cfg = storedConfig(h.store);
  const deps = { config: cfg, clock: h.clock, audit: h.audit };
  const reg = await registerClient(deps, { redirectUris: ["https://client.test/callback"], applicationType: "web" });
  const stored = await h.store.find(reg.client_id);
  assert.equal(stored?.applicationType, "web");
  // The per-client redirect policy still accepts the registered web URI.
  assert.equal(assertRedirectAllowedForClient("https://client.test/callback", stored!), "https://client.test/callback");
});
