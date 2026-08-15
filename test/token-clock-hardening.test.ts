import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { generateRefreshToken, parseRefreshFamilyId, pkceChallenge, sha256Hex } from "../src/crypto.ts";
import { provisionMachineClient } from "../src/machine-client.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type {
  ActiveMachineClientRegistration, ClientRegistration, MachineClientMutationAudit,
  MachineClientStore, VersionedMachineClientRegistration,
} from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { OAuthTokenUseCase } from "../src/token.ts";

const NOW_MS = Date.parse("2026-08-15T12:00:00.000Z");
const NOW_ISO = new Date(NOW_MS).toISOString();
const MAX_CANONICAL_MS = Date.parse("9999-12-31T23:59:59.999Z");
const RESOURCE = "https://api.test/mcp";
const REDIRECT = "https://client.test/callback";
const CLIENT_ID = "client-1";
const SUBJECT = "operator";
const ACCESS_TTL = 30;
const REFRESH_TTL = 60;

class ScriptedClock implements ClockPort {
  reads = 0;
  private readonly values: number[];
  constructor(values: number[]) { this.values = values; }
  nowMs(): number {
    const value = this.values[Math.min(this.reads, this.values.length - 1)];
    this.reads += 1;
    if (value === undefined) throw new Error("clock script is empty");
    return value;
  }
}

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

class InMemoryClientStore implements MachineClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  findCalls = 0;
  async save(client: ClientRegistration): Promise<void> { this.clients.set(client.clientId, client); }
  async find(clientId: string): Promise<ClientRegistration | null> {
    this.findCalls += 1;
    return this.clients.get(clientId) ?? null;
  }
  async createMachineClient(
    client: ActiveMachineClientRegistration, _audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    if (this.clients.has(client.clientId)) return false;
    this.clients.set(client.clientId, client);
    return true;
  }
  async compareAndSwapMachineClient(
    expectedVersion: number, client: VersionedMachineClientRegistration,
    _audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    const current = this.clients.get(client.clientId);
    if (!current || current.applicationType !== "machine") return false;
    const version = "version" in current ? current.version : 0;
    if (version !== expectedVersion) return false;
    this.clients.set(client.clientId, client);
    return true;
  }
}

function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "clock" } as JWK;
}

function config(clientStore?: InMemoryClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: RESOURCE,
    consentSigningSecret: "clock-hardening-secret-with-enough-entropy",
    signingPrivateJwk: signingJwk(), signingKeyId: "clock",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: clientStore ? { mode: "stored", store: clientStore } : { mode: "stateless" },
    ...(clientStore ? { clientCredentials: { enabled: true } } : {}),
    accessTokenTtlSeconds: ACCESS_TTL, refreshTokenTtlSeconds: REFRESH_TTL,
    consentTokenTtlSeconds: 30, authorizationCodeTtlSeconds: 30,
  });
}

function assertJwtClock(token: string): void {
  const claims = decodeJwt(token);
  assert.equal(claims.iat, Math.floor(NOW_MS / 1000));
  assert.equal(claims.exp, Math.floor(NOW_MS / 1000) + ACCESS_TTL);
}

async function seedCode(store: MemoryStore, raw: string, verifier: string): Promise<void> {
  await store.saveAuthCode({
    codeHash: sha256Hex(raw), clientId: CLIENT_ID, redirectUri: REDIRECT,
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    subject: SUBJECT, resource: RESOURCE,
    scopes: ["mcp:read"], expiresAt: "2099-01-01T00:00:00.000Z",
  });
}

test("authorization-code exchange reuses one clock snapshot for store, JWT, refresh, and audit", async () => {
  const store = new MemoryStore();
  const audit = new MemoryAudit();
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const rawCode = "ac_clock_snapshot";
  const verifier = "clock-snapshot-verifier-123456789012345678901234567890";
  await seedCode(store, rawCode, verifier);
  let consumedAt: string | undefined;
  let savedExpiry: string | undefined;
  const consume = store.consumeAuthCode.bind(store);
  store.consumeAuthCode = async (hash, now, generation, resource) => {
    consumedAt = now;
    return consume(hash, now, generation, resource);
  };
  const save = store.saveRefreshToken.bind(store);
  store.saveRefreshToken = async (input) => { savedExpiry = input.expiresAt; await save(input); };
  try {
    const result = await new OAuthTokenUseCase({ config: config(), store, clock, audit })
      .exchangeAuthorizationCode({
        grantType: "authorization_code", code: rawCode, redirectUri: REDIRECT,
        clientId: CLIENT_ID, codeVerifier: verifier,
      });
    assert.equal(clock.reads, 1);
    assert.equal(consumedAt, NOW_ISO);
    assert.equal(savedExpiry, new Date(NOW_MS + REFRESH_TTL * 1000).toISOString());
    assertJwtClock(result.access_token);
    assert.equal(audit.events.at(-1)?.occurredAt, NOW_ISO);
    assert.equal(audit.events.at(-1)?.status, "success");
  } finally {
    await store.close();
  }
});

test("refresh reuses one clock snapshot for rotation, successor, JWT, and audit", async () => {
  const store = new MemoryStore();
  const audit = new MemoryAudit();
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const raw = generateRefreshToken();
  const familyId = parseRefreshFamilyId(raw);
  assert.ok(familyId);
  await store.saveRefreshToken({
    tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
    clientId: CLIENT_ID, subject: SUBJECT, resource: RESOURCE,
    scopes: ["mcp:read"], expiresAt: "2099-01-01T00:00:00.000Z",
  });
  let rotationTime: string | undefined;
  let successorExpiry: string | undefined;
  const rotate = store.rotateRefreshToken.bind(store);
  store.rotateRefreshToken = async (hash, next, now, generation, resource) => {
    rotationTime = now;
    successorExpiry = next.expiresAt;
    return rotate(hash, next, now, generation, resource);
  };
  try {
    const result = await new OAuthTokenUseCase({ config: config(), store, clock, audit })
      .refresh({ grantType: "refresh_token", refreshToken: raw, clientId: CLIENT_ID });
    assert.equal(clock.reads, 1);
    assert.equal(rotationTime, NOW_ISO);
    assert.equal(successorExpiry, new Date(NOW_MS + REFRESH_TTL * 1000).toISOString());
    assertJwtClock(result.access_token);
    assert.equal(audit.events.at(-1)?.occurredAt, NOW_ISO);
    assert.equal(audit.events.at(-1)?.status, "success");
  } finally {
    await store.close();
  }
});

test("refresh failure reuses the operation snapshot for compensation and failure audit", async () => {
  const store = new MemoryStore();
  const audit = new MemoryAudit();
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const raw = generateRefreshToken();
  const familyId = parseRefreshFamilyId(raw);
  assert.ok(familyId);
  await store.saveRefreshToken({
    tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
    clientId: CLIENT_ID, subject: SUBJECT, resource: RESOURCE,
    scopes: ["mcp:read"], expiresAt: "2099-01-01T00:00:00.000Z",
  });
  const badConfig = createBridgeConfig({
    ...config(),
    signingPrivateJwk: {
      kty: "EC", crv: "P-256", x: "x", y: "y", d: "d", alg: "ES256", kid: "bad",
    } as JWK,
    signingKeyId: "bad",
  });
  let revokedAt: string | undefined;
  const revoke = store.revokeRefreshTokenFamily.bind(store);
  store.revokeRefreshTokenFamily = async (id, at) => {
    revokedAt = at;
    await revoke(id, at);
  };
  try {
    await assert.rejects(
      new OAuthTokenUseCase({ config: badConfig, store, clock, audit })
        .refresh({ grantType: "refresh_token", refreshToken: raw, clientId: CLIENT_ID }),
    );
    assert.equal(clock.reads, 1);
    assert.equal(revokedAt, NOW_ISO);
    assert.equal(audit.events.at(-1)?.occurredAt, NOW_ISO);
    assert.equal(audit.events.at(-1)?.status, "failure");
    assert.equal(audit.events.some((event) => event.status === "success"), false);
  } finally {
    await store.close();
  }
});

test("client credentials reuses one clock snapshot for authentication, JWT, and audit", async () => {
  const clientStore = new InMemoryClientStore();
  const cfg = config(clientStore);
  const setupAudit = new MemoryAudit();
  const credential = await provisionMachineClient({
    store: clientStore, catalog: ["mcp:read"], resource: RESOURCE,
    clock: { nowMs: () => NOW_MS }, audit: setupAudit,
  }, { allowedScopes: ["mcp:read"], secretTtlSeconds: 600 });
  const audit = new MemoryAudit();
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const store = new MemoryStore();
  try {
    const result = await new OAuthTokenUseCase({ config: cfg, store, clock, audit })
      .exchangeClientCredentials({
        grantType: "client_credentials", clientId: credential.clientId,
        clientSecret: credential.clientSecret,
      });
    assert.equal(clock.reads, 1);
    assert.equal(clientStore.findCalls, 1);
    assertJwtClock(result.access_token);
    assert.equal(audit.events.at(-1)?.occurredAt, NOW_ISO);
    assert.equal(audit.events.at(-1)?.status, "success");
  } finally {
    await store.close();
  }
});

test("invalid issuance snapshots reject before code consumption, refresh rotation, or client lookup", async () => {
  for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, 0.5]) {
    const store = new MemoryStore();
    const audit = new MemoryAudit();
    const clock = new ScriptedClock([invalid]);
    let consumeCalls = 0;
    store.consumeAuthCode = async () => { consumeCalls += 1; return null; };
    await assert.rejects(
      new OAuthTokenUseCase({ config: config(), store, clock, audit })
        .exchangeAuthorizationCode({ grantType: "authorization_code", code: "unused" }),
      RangeError,
    );
    assert.equal(clock.reads, 1);
    assert.equal(consumeCalls, 0);
    assert.deepEqual(audit.events, []);
    await store.close();
  }

  const overflowStore = new MemoryStore();
  const overflowAudit = new MemoryAudit();
  const overflowClock = new ScriptedClock([MAX_CANONICAL_MS - REFRESH_TTL * 1000 + 1]);
  let rotationCalls = 0;
  overflowStore.rotateRefreshToken = async () => { rotationCalls += 1; return null; };
  await assert.rejects(
    new OAuthTokenUseCase({ config: config(), store: overflowStore,
      clock: overflowClock, audit: overflowAudit })
      .refresh({ grantType: "refresh_token", refreshToken: "unused", clientId: CLIENT_ID }),
    RangeError,
  );
  assert.equal(overflowClock.reads, 1);
  assert.equal(rotationCalls, 0);
  assert.deepEqual(overflowAudit.events, []);
  await overflowStore.close();

  const clientStore = new InMemoryClientStore();
  const machineAudit = new MemoryAudit();
  const machineStore = new MemoryStore();
  const machineClock = new ScriptedClock([Number.NaN]);
  await assert.rejects(
    new OAuthTokenUseCase({ config: config(clientStore), store: machineStore,
      clock: machineClock, audit: machineAudit })
      .exchangeClientCredentials({ grantType: "client_credentials", clientId: "mcc_unused", clientSecret: "unused" }),
    RangeError,
  );
  assert.equal(machineClock.reads, 1);
  assert.equal(clientStore.findCalls, 0);
  assert.deepEqual(machineAudit.events, []);
  await machineStore.close();
});

test("Bridge sanitizes an invalid issuance snapshot before token-store or audit work", async () => {
  const store = new MemoryStore();
  const audit = new MemoryAudit();
  const clock = new ScriptedClock([Number.NaN]);
  let consumeCalls = 0;
  store.consumeAuthCode = async () => { consumeCalls += 1; return null; };
  const response = await new Bridge({
    config: config(), store, clock, audit,
  }).handleToken({
    query: {}, headers: {},
    body: { grant_type: "authorization_code", code: "unused", client_id: CLIENT_ID },
  });
  assert.equal(response.status, 500);
  assert.equal((response.body as { error?: string }).error, "internal_error");
  assert.equal(clock.reads, 1);
  assert.equal(consumeCalls, 0);
  assert.deepEqual(audit.events, []);
  await store.close();
});
