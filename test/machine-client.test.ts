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
import type {
  ActiveMachineClientRegistration,
  ClientRegistration,
  ClientStore,
  LegacyMachineClientRegistration,
  MachineClientMutationAudit,
  MachineClientStore,
  VersionedMachineClientRegistration,
} from "../src/ports/client-store.ts";
import { AuthConfigError, createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import { sha256Hex } from "../src/crypto.ts";
import { registerClient } from "../src/register.ts";
import { assertRedirectAllowedForClient } from "../src/redirect.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { MemoryStore } from "../src/store/memory.ts";
import {
  disableMachineClient, provisionMachineClient, rotateMachineClientSecret,
  verifyMachineClientSecret, rotateSecrets, DEFAULT_ROTATION_GRACE_SECONDS,
  MAX_ROTATION_GRACE_SECONDS,
  type MachineClientDeps,
} from "../src/machine-client.ts";
import { parseMachineClientRegistration } from "../src/machine-client-record.ts";

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

class ThrowingAudit implements AuditPort {
  async writeAuthEvent(): Promise<void> { throw new Error("supplemental audit unavailable"); }
}

class InMemoryClientStore implements MachineClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  readonly mutationAudits: MachineClientMutationAudit[] = [];
  saveCalls = 0;
  createCalls = 0;
  casCalls = 0;
  failDurableAudit = false;
  async save(c: ClientRegistration): Promise<void> { this.saveCalls += 1; this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
  setAt(clientId: string, record: unknown): void { this.clients.set(clientId, record as ClientRegistration); }
  async createMachineClient(
    client: ActiveMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    this.createCalls += 1;
    if (this.clients.has(client.clientId)) return false;
    if (this.failDurableAudit) throw new Error("durable audit unavailable");
    this.clients.set(client.clientId, client);
    this.mutationAudits.push(audit);
    return true;
  }
  async compareAndSwapMachineClient(
    expectedVersion: number,
    client: VersionedMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    this.casCalls += 1;
    const current = this.clients.get(client.clientId);
    if (!current || current.applicationType !== "machine") return false;
    const currentVersion = "version" in current ? current.version : 0;
    if (currentVersion !== expectedVersion) return false;
    if (this.failDurableAudit) throw new Error("durable audit unavailable");
    this.clients.set(client.clientId, client);
    this.mutationAudits.push(audit);
    return true;
  }
}

interface Harness { deps: MachineClientDeps; store: InMemoryClientStore; clock: FakeClock; audit: MemoryAudit; }

/** Narrow a stored record to VersionedMachineClientRegistration (these tests only ever
 *  load provisioned machine clients). Asserts the discriminant first. */
async function machineRecord(store: InMemoryClientStore, clientId: string): Promise<VersionedMachineClientRegistration> {
  const r = await store.find(clientId);
  assert.equal(r?.applicationType, "machine");
  assert.ok(r && "version" in r);
  return r as VersionedMachineClientRegistration;
}

function harness(catalog: readonly string[] = CATALOG): Harness {
  const store = new InMemoryClientStore();
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  return { deps: { store, catalog, clock, audit }, store, clock, audit };
}

function storedMachineRecord(clientId: string, secret: string): LegacyMachineClientRegistration {
  const epoch = Math.floor(NOW_MS / 1000);
  return {
    clientId, redirectUris: [], applicationType: "machine", issuedAtEpoch: epoch,
    name: "build agent", allowedScopes: ["mcp:read"],
    secrets: [{ hash: sha256Hex(secret), createdAtEpoch: epoch }],
  };
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

test("provision: a v0.3.0 ClientStore fails closed without atomic mutation methods", async () => {
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  let saveCalls = 0;
  const store: ClientStore = {
    async save(): Promise<void> { saveCalls += 1; },
    async find(): Promise<ClientRegistration | null> { return null; },
  };
  const deps: MachineClientDeps = { store, catalog: CATALOG, clock, audit };
  await assert.rejects(
    provisionMachineClient(deps, { allowedScopes: ["mcp:read"] }),
    (error: unknown) => error instanceof OAuthError
      && error.code === "server_error"
      && error.message === "MachineClientStore atomic mutations are required",
  );
  assert.equal(saveCalls, 0);
  assert.equal(audit.events.at(-1)?.status, "failure");
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

test("provision: rejects a TTL whose derived expiry is unsafe before save or success audit", async () => {
  const h = harness();
  await assert.rejects(
    () => provisionMachineClient(h.deps, {
      allowedScopes: ["mcp:read"],
      secretTtlSeconds: Number.MAX_SAFE_INTEGER,
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_request",
  );
  assert.equal(h.store.createCalls, 0);
  assert.equal(h.audit.events.some((event) =>
    event.event === "oauth.client.provision" && event.status === "success"), false);
  assert.equal(h.audit.events.at(-1)?.reason, "invalid_request");
});

test("provision: durable-audit failure rolls back the row and returns no credential", async () => {
  const h = harness();
  h.store.failDurableAudit = true;
  await assert.rejects(
    provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] }),
    /durable audit unavailable/,
  );
  assert.equal(h.store.clients.size, 0, "failed durable transaction committed no credential");
  assert.equal(h.store.mutationAudits.length, 0, "failed durable transaction committed no audit");
});

test("provision: supplemental audit failure cannot suppress the durably committed secret", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(
    { ...h.deps, audit: new ThrowingAudit() },
    { allowedScopes: ["mcp:read"] },
  );
  assert.equal(h.store.mutationAudits.length, 1);
  assert.equal(h.store.mutationAudits[0]?.event, "oauth.client.provision");
  assert.equal(
    await verifyMachineClientSecret(h.deps, provisioned.clientId, provisioned.clientSecret),
    true,
  );
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

test("rotation: same-version competitors return exactly one still-valid secret", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const outcomes = await Promise.allSettled([
    rotateMachineClientSecret(h.deps, provisioned.clientId),
    rotateMachineClientSecret(h.deps, provisioned.clientId),
  ]);
  const winners = outcomes.filter(
    (outcome): outcome is PromiseFulfilledResult<Awaited<ReturnType<typeof rotateMachineClientSecret>>> =>
      outcome.status === "fulfilled",
  );
  const losers = outcomes.filter(
    (outcome): outcome is PromiseRejectedResult => outcome.status === "rejected",
  );
  assert.equal(winners.length, 1);
  assert.equal(losers.length, 1);
  assert.ok(losers[0]?.reason instanceof OAuthError && losers[0].reason.status === 409);
  assert.equal(
    await verifyMachineClientSecret(h.deps, provisioned.clientId, winners[0]!.value.clientSecret),
    true,
    "the only returned rotation secret remains current",
  );
  assert.equal(
    h.store.mutationAudits.filter((audit) => audit.event === "oauth.client.rotate_secret").length,
    1,
  );
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
  h.store.setAt("mcc_bad", { clientId: "mcc_bad", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1, allowedScopes: ["mcp:read"], secrets: undefined });
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

test("rotation: accepts the 24-hour maximum and rejects one second above it before CAS", async () => {
  const accepted = harness();
  const first = await provisionMachineClient(accepted.deps, { allowedScopes: ["mcp:read"] });
  await rotateMachineClientSecret(accepted.deps, first.clientId, {
    graceSeconds: MAX_ROTATION_GRACE_SECONDS,
  });
  assert.equal(accepted.store.casCalls, 1);

  const rejected = harness();
  const second = await provisionMachineClient(rejected.deps, { allowedScopes: ["mcp:read"] });
  await assert.rejects(
    rotateMachineClientSecret(rejected.deps, second.clientId, {
      graceSeconds: MAX_ROTATION_GRACE_SECONDS + 1,
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_request",
  );
  assert.equal(rejected.store.casCalls, 0);
});

test("rotation: rejects a grace whose derived expiry is unsafe before save or success audit", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const mutationsBefore = h.store.casCalls;
  await assert.rejects(
    () => rotateMachineClientSecret(h.deps, provisioned.clientId, {
      graceSeconds: Number.MAX_SAFE_INTEGER,
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_request",
  );
  assert.equal(h.store.casCalls, mutationsBefore);
  assert.equal(h.audit.events.some((event) =>
    event.event === "oauth.client.rotate_secret" && event.status === "success"), false);
  assert.equal(h.audit.events.at(-1)?.reason, "invalid_request");
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

test("stored machine grammar: malformed or mis-keyed rows fail verification and rotation before save", async () => {
  const presented = "mcs_" + "A".repeat(43);
  const base = storedMachineRecord("mcc_lookup", presented);
  const malformed: Array<[string, unknown]> = [
    ["record type", 42],
    ["embedded clientId", { ...base, clientId: "mcc_other" }],
    ["applicationType", { ...base, applicationType: "web" }],
    ["redirectUris", { ...base, redirectUris: ["https://wrong.test/cb"] }],
    ["redirectUris type", { ...base, redirectUris: "none" as unknown as string[] }],
    ["issuedAtEpoch", { ...base, issuedAtEpoch: -1 }],
    ["issuedAtEpoch range", { ...base, issuedAtEpoch: Number.MAX_SAFE_INTEGER + 1 }],
    ["name", { ...base, name: "" }],
    ["name type", { ...base, name: 42 as unknown as string }],
    ["allowedScopes", { ...base, allowedScopes: "mcp:read" as unknown as string[] }],
    ["status without version", { ...base, status: "active" }],
    ["version without status", { ...base, version: 1 }],
    ["unknown status", { ...base, status: "paused", version: 1 }],
    ["active carries disabledAtEpoch", { ...base, status: "active", version: 1, disabledAtEpoch: 1 }],
    ["disabled keeps secrets", { ...base, status: "disabled", version: 1, disabledAtEpoch: 1 }],
    ["disabled lacks epoch", { ...base, status: "disabled", version: 1, secrets: [] }],
    ["secret hash", { ...base, secrets: [{ hash: "x", createdAtEpoch: base.issuedAtEpoch }] }],
    ["secret hash case", { ...base, secrets: [{ hash: "A".repeat(64), createdAtEpoch: base.issuedAtEpoch }] }],
    ["secret createdAtEpoch", { ...base, secrets: [{ hash: sha256Hex(presented), createdAtEpoch: -1 }] }],
    ["secret createdAtEpoch type", { ...base, secrets: [{
      hash: sha256Hex(presented), createdAtEpoch: "1" as unknown as number,
    }] }],
    ["secret expiresAtEpoch", { ...base, secrets: [{
      hash: sha256Hex(presented), createdAtEpoch: 1, expiresAtEpoch: base.issuedAtEpoch + 1000.5,
    }] }],
    ["secrets empty", { ...base, secrets: [] }],
    ["secret count", { ...base, secrets: [
      { hash: sha256Hex(presented), createdAtEpoch: 1, expiresAtEpoch: base.issuedAtEpoch + 1000 },
      { hash: "b".repeat(64), createdAtEpoch: 1, expiresAtEpoch: base.issuedAtEpoch + 1000 },
      { hash: "c".repeat(64), createdAtEpoch: 1, expiresAtEpoch: base.issuedAtEpoch + 1000 },
    ] }],
    ["multiple unbounded secrets", { ...base, secrets: [
      { hash: sha256Hex(presented), createdAtEpoch: 1 },
      { hash: "b".repeat(64), createdAtEpoch: 1 },
    ] }],
  ];
  for (const [label, record] of malformed) {
    const h = harness();
    h.store.setAt("mcc_lookup", record);
    assert.equal(await verifyMachineClientSecret(h.deps, "mcc_lookup", presented), false, `${label}: verification`);
    await assert.rejects(
      rotateMachineClientSecret(h.deps, "mcc_lookup"),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_client" && error.status === 401,
      `${label}: rotation`,
    );
    assert.equal(h.store.casCalls, 0, `${label}: no CAS`);
    assert.equal(h.audit.events.some((event) => event.event === "oauth.client.rotate_secret" && event.status === "success"), false);
    assert.deepEqual(h.audit.events.at(-1), {
      occurredAt: new Date(NOW_MS).toISOString(), event: "oauth.client.rotate_secret",
      status: "failure", clientId: "mcc_lookup", reason: "invalid_client",
    });
  }
});

test("stored machine grammar: expired history remains readable and rotation compacts it", async () => {
  const h = harness();
  const clientId = "mcc_history";
  const liveSecret = "mcs_" + "H".repeat(43);
  const nowEpoch = Math.floor(NOW_MS / 1000);
  h.store.setAt(clientId, {
    ...storedMachineRecord(clientId, liveSecret),
    secrets: [
      { hash: "a".repeat(64), createdAtEpoch: 1, expiresAtEpoch: nowEpoch - 2 },
      { hash: "b".repeat(64), createdAtEpoch: 2, expiresAtEpoch: nowEpoch - 1 },
      { hash: sha256Hex(liveSecret), createdAtEpoch: nowEpoch },
    ],
  });

  assert.equal(await verifyMachineClientSecret(h.deps, clientId, liveSecret), true);
  const rotated = await rotateMachineClientSecret(h.deps, clientId, { graceSeconds: 600 });
  const saved = await machineRecord(h.store, clientId);
  assert.equal(saved.secrets.length, 2);
  assert.deepEqual(saved.secrets.map((secret) => secret.hash), [
    sha256Hex(liveSecret),
    sha256Hex(rotated.clientSecret),
  ]);
});

test("stored machine grammar: an all-expired row can rotate to one new live secret", async () => {
  const h = harness();
  const clientId = "mcc_expired_history";
  const nowEpoch = Math.floor(NOW_MS / 1000);
  h.store.setAt(clientId, {
    ...storedMachineRecord(clientId, "mcs_" + "E".repeat(43)),
    secrets: [
      { hash: "a".repeat(64), createdAtEpoch: 1, expiresAtEpoch: nowEpoch - 2 },
      { hash: "b".repeat(64), createdAtEpoch: 2, expiresAtEpoch: nowEpoch - 1 },
      { hash: "c".repeat(64), createdAtEpoch: 3, expiresAtEpoch: nowEpoch },
    ],
  });

  const rotated = await rotateMachineClientSecret(h.deps, clientId);
  const saved = await machineRecord(h.store, clientId);
  assert.deepEqual(saved.secrets, [{
    hash: sha256Hex(rotated.clientSecret),
    createdAtEpoch: nowEpoch,
  }]);
});

test("stored machine parser returns fresh known-field arrays and secret slots", () => {
  const clientId = "mcc_snapshot";
  const nowEpoch = Math.floor(NOW_MS / 1000);
  assert.equal(parseMachineClientRegistration(undefined, clientId, nowEpoch), null);
  const expected = storedMachineRecord(clientId, "mcs_" + "S".repeat(43));
  const input = {
    ...expected, operatorNote: "drop",
    secrets: [{ ...expected.secrets[0]!, operatorNote: "drop" }],
  };
  const parsed = parseMachineClientRegistration(input, clientId, nowEpoch)!;
  assert.notEqual(parsed, input);
  assert.notEqual(parsed.redirectUris, input.redirectUris);
  assert.notEqual(parsed.allowedScopes, input.allowedScopes);
  assert.notEqual(parsed.secrets, input.secrets);
  assert.notEqual(parsed.secrets[0], input.secrets[0]);
  assert.deepEqual(parsed, { ...expected, status: "active", version: 0 });
});

test("legacy v0.3.0 row authenticates and migrates from version 0 on first rotation", async () => {
  const h = harness();
  const clientId = "mcc_legacy_v030";
  const oldSecret = "mcs_" + "L".repeat(43);
  h.store.setAt(clientId, storedMachineRecord(clientId, oldSecret));
  assert.equal(await verifyMachineClientSecret(h.deps, clientId, oldSecret), true);

  const rotated = await rotateMachineClientSecret(h.deps, clientId);
  assert.equal(rotated.version, 1);
  const saved = await machineRecord(h.store, clientId);
  assert.equal(saved.status, "active");
  assert.equal(saved.version, 1);
  assert.equal(await verifyMachineClientSecret(h.deps, clientId, rotated.clientSecret), true);
  assert.equal(h.store.mutationAudits.at(-1)?.event, "oauth.client.rotate_secret");
});

test("legacy v0.3.0 row can migrate directly to a version-1 disabled tombstone", async () => {
  const h = harness();
  const clientId = "mcc_legacy_disable";
  const secret = "mcs_" + "D".repeat(43);
  h.store.setAt(clientId, storedMachineRecord(clientId, secret));
  const disabled = await disableMachineClient(h.deps, clientId);
  assert.equal(disabled.version, 1);
  const stored = await machineRecord(h.store, clientId);
  assert.equal(stored.status, "disabled");
  assert.deepEqual(stored.secrets, []);
  assert.equal(await verifyMachineClientSecret(h.deps, clientId, secret), false);
});

test("rotation and disable reject version overflow before CAS", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const current = await machineRecord(h.store, provisioned.clientId);
  h.store.setAt(provisioned.clientId, { ...current, version: Number.MAX_SAFE_INTEGER });
  const before = h.store.casCalls;
  for (const mutate of [
    () => rotateMachineClientSecret(h.deps, provisioned.clientId),
    () => disableMachineClient(h.deps, provisioned.clientId),
  ]) {
    await assert.rejects(
      mutate,
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_client",
    );
  }
  assert.equal(h.store.casCalls, before);
});

test("rotation saves the parser's named projection, not unknown stored fields", async () => {
  const h = harness();
  const clientId = "mcc_projected";
  const record = { ...storedMachineRecord(clientId, "mcs_" + "A".repeat(43)), operatorNote: "do not republish" };
  h.store.setAt(clientId, record);
  await rotateMachineClientSecret(h.deps, clientId);
  const saved = h.store.clients.get(clientId) as VersionedMachineClientRegistration;
  assert.equal("operatorNote" in (saved as unknown as Record<string, unknown>), false);
  assert.notEqual(saved.redirectUris, record.redirectUris);
  assert.notEqual(saved.allowedScopes, record.allowedScopes);
  assert.deepEqual(saved.allowedScopes, record.allowedScopes);
});

test("verifyMachineClientSecret: a 64-char NON-ASCII hash (byte-length mismatch) fails closed, no throw", async () => {
  // Codex P2: a corrupted stored hash that is 64 JS chars but multibyte (>64 bytes)
  // must NOT make timingSafeEqual throw ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH.
  const h = harness();
  h.store.setAt("mcc_m4", {
    clientId: "mcc_m4", redirectUris: [], applicationType: "machine", issuedAtEpoch: 1,
    allowedScopes: ["mcp:read"], secrets: [{ hash: "é".repeat(64), createdAtEpoch: 1 }],
  });
  assert.equal(await verifyMachineClientSecret(h.deps, "mcc_m4", "mcs_" + "A".repeat(43)), false);
});

// ---------- audit (no secret / no hash leak) ----------

test("audit: provision + rotate + disable emit metadata-only events (no secret, no hash, no mcs_)", async () => {
  const h = harness();
  const prov = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read", "mcp:write"], name: "ci-runner" });
  const rot = await rotateMachineClientSecret(h.deps, prov.clientId);
  await disableMachineClient(h.deps, prov.clientId);
  const dump = JSON.stringify(h.audit.events);
  const provisionEvt = h.audit.events.find((e) => e.event === "oauth.client.provision" && e.status === "success");
  const rotateEvt = h.audit.events.find((e) => e.event === "oauth.client.rotate_secret" && e.status === "success");
  const disableEvt = h.audit.events.find((e) => e.event === "oauth.client.disable" && e.status === "success");
  assert.deepEqual(provisionEvt?.scopes, ["mcp:read", "mcp:write"]);
  assert.equal(provisionEvt?.clientId, prov.clientId);
  assert.equal(rotateEvt?.clientId, prov.clientId);
  assert.equal(disableEvt?.clientId, prov.clientId);
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

// ---------- disable ----------

test("disable: atomically writes a hash-free tombstone and rejects future authentication", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  const rotated = await rotateMachineClientSecret(h.deps, provisioned.clientId);
  const disabled = await disableMachineClient(h.deps, provisioned.clientId);
  assert.equal(disabled.version, 3);
  const stored = await machineRecord(h.store, provisioned.clientId);
  assert.equal(stored.status, "disabled");
  assert.deepEqual(stored.secrets, []);
  assert.equal("disabledAtEpoch" in stored, true);
  assert.equal(await verifyMachineClientSecret(h.deps, provisioned.clientId, provisioned.clientSecret), false);
  assert.equal(await verifyMachineClientSecret(h.deps, provisioned.clientId, rotated.clientSecret), false);
  assert.equal(h.store.mutationAudits.at(-1)?.event, "oauth.client.disable");
  await assert.rejects(
    rotateMachineClientSecret(h.deps, provisioned.clientId),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_client",
  );
  await assert.rejects(
    disableMachineClient(h.deps, provisioned.clientId),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_client",
  );
});

test("disable: durable-audit failure leaves the active credential unchanged", async () => {
  const h = harness();
  const provisioned = await provisionMachineClient(h.deps, { allowedScopes: ["mcp:read"] });
  h.store.failDurableAudit = true;
  await assert.rejects(disableMachineClient(h.deps, provisioned.clientId), /durable audit unavailable/);
  assert.equal(await verifyMachineClientSecret(h.deps, provisioned.clientId, provisioned.clientSecret), true);
  assert.equal(
    h.store.mutationAudits.filter((audit) => audit.event === "oauth.client.disable").length,
    0,
  );
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
