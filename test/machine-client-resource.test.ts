import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { noopAudit } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type {
  ActiveMachineClientRegistration,
  ClientRegistration,
  ClientStore,
  MachineClientMutationAudit,
  VersionedMachineClientRegistration,
} from "../src/ports/client-store.ts";
import { AuthConfigError, type BridgeConfig } from "../src/config.ts";
import { sha256Hex, verifyAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import {
  disableMachineClient,
  provisionMachineClient,
  rotateMachineClientSecret,
  type MachineClientDeps,
} from "../src/machine-client.ts";
import { parseMachineClientRegistration } from "../src/machine-client-record.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { OAuthTokenUseCase } from "../src/token.ts";

const NOW_MS = Date.parse("2026-07-29T12:00:00.000Z");
const A = "https://a.test/mcp";
const B = "https://b.test/mcp";
const SCOPES = ["mcp:read", "mcp:write"];

class FixedClock implements ClockPort {
  nowMs(): number { return NOW_MS; }
}

class MachineStore implements ClientStore {
  readonly machineClientResourceBinding?: 1;
  readonly rows = new Map<string, ClientRegistration>();
  readonly audits: MachineClientMutationAudit[] = [];
  findCalls = 0;
  createCalls = 0;
  casCalls = 0;

  constructor(capable = true) {
    if (capable) this.machineClientResourceBinding = 1;
  }

  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, client); }
  async find(clientId: string): Promise<ClientRegistration | null> {
    this.findCalls += 1;
    return this.rows.get(clientId) ?? null;
  }
  async createMachineClient(
    client: ActiveMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    this.createCalls += 1;
    if (this.rows.has(client.clientId)) return false;
    this.rows.set(client.clientId, client);
    this.audits.push(audit);
    return true;
  }
  async compareAndSwapMachineClient(
    expectedVersion: number,
    client: VersionedMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean> {
    this.casCalls += 1;
    const current = this.rows.get(client.clientId);
    if (!current || current.applicationType !== "machine") return false;
    const version = "version" in current ? current.version : 0;
    if (version !== expectedVersion) return false;
    this.rows.set(client.clientId, client);
    this.audits.push(audit);
    return true;
  }
}

function key(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k1" } as JWK;
}

function common(store: ClientStore): Omit<BridgeConfig, "resource" | "scopeCatalog" | "defaultScopes"> {
  return {
    issuer: "https://auth.test",
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: key(),
    signingKeyId: "k1",
    redirectAllowlist: ["https://client.test/callback"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stored", store },
    clientCredentials: { enabled: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  };
}

function multiConfig(store: ClientStore): BridgeConfig {
  return {
    ...common(store),
    resources: [
      { resource: A, scopeCatalog: [...SCOPES], defaultScopes: ["mcp:read"] },
      { resource: B, scopeCatalog: [...SCOPES], defaultScopes: ["mcp:read"] },
    ],
  } as unknown as BridgeConfig;
}

function singletonConfig(store: ClientStore, attested = false): BridgeConfig {
  return {
    ...common(store),
    resource: A,
    scopeCatalog: [...SCOPES],
    defaultScopes: ["mcp:read"],
    ...(attested ? { legacySingletonResource: A } : {}),
  } as unknown as BridgeConfig;
}

function deps(store: ClientStore, resource = A, legacySingletonResource?: string, config?: BridgeConfig): MachineClientDeps {
  return {
    store,
    resource,
    catalog: [...SCOPES],
    config: config ?? multiConfig(store),
    ...(legacySingletonResource === undefined ? {} : { legacySingletonResource }),
    clock: new FixedClock(),
    audit: noopAudit,
  };
}

function token(config: BridgeConfig): OAuthTokenUseCase {
  return new OAuthTokenUseCase({
    config,
    store: new MemoryStore(),
    clock: new FixedClock(),
    audit: noopAudit,
  });
}

function hasOAuthCode(code: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof OAuthError && error.code === code;
}

function legacyRow(clientId: string, secret: string): ClientRegistration {
  const epoch = Math.floor(NOW_MS / 1000);
  return {
    clientId,
    redirectUris: [],
    applicationType: "machine",
    issuedAtEpoch: epoch,
    allowedScopes: ["mcp:read"],
    secrets: [{ hash: sha256Hex(secret), createdAtEpoch: epoch }],
  };
}

test("an A machine credential cannot mint for B even when both scope catalogs are identical", async () => {
  const store = new MachineStore();
  const provisioned = await provisionMachineClient(deps(store, A), { allowedScopes: ["mcp:read"] });
  const config = multiConfig(store);
  const useCase = token(config);

  const issued = await useCase.exchangeClientCredentials({
    grantType: "client_credentials",
    clientId: provisioned.clientId,
    clientSecret: provisioned.clientSecret,
    resource: A,
  });
  assert.equal((await verifyAccessToken(issued.access_token, config, new FixedClock(), A)).resource, A);

  await assert.rejects(useCase.exchangeClientCredentials({
    grantType: "client_credentials",
    clientId: provisioned.clientId,
    clientSecret: provisioned.clientSecret,
    resource: B,
  }), hasOAuthCode("invalid_target"));

  await assert.rejects(useCase.exchangeClientCredentials({
    grantType: "client_credentials",
    clientId: provisioned.clientId,
    clientSecret: "wrong",
    resource: B,
  }), hasOAuthCode("invalid_client"), "wrong credentials must not expose the resource binding");
  await assert.rejects(useCase.exchangeClientCredentials({
    grantType: "client_credentials",
    clientId: "mcc_unknown",
    clientSecret: provisioned.clientSecret,
    resource: B,
  }), hasOAuthCode("invalid_client"), "unknown credentials must not expose the resource binding");

  const current = store.rows.get(provisioned.clientId)! as VersionedMachineClientRegistration;
  store.rows.set(provisioned.clientId, { ...current, resource: "https://A.test:443/mcp" });
  await assert.rejects(useCase.exchangeClientCredentials({
    grantType: "client_credentials",
    clientId: provisioned.clientId,
    clientSecret: provisioned.clientSecret,
    resource: B,
  }), hasOAuthCode("invalid_client"), "a malformed stored resource makes the row unreadable");
});

test("rotation and disable reject different-resource deps without rebinding", async () => {
  const store = new MachineStore();
  const provisioned = await provisionMachineClient(deps(store, A), { allowedScopes: ["mcp:read"] });
  const original = store.rows.get(provisioned.clientId)! as VersionedMachineClientRegistration;
  assert.equal(original.resource, A);
  assert.equal(store.audits[0]?.resource, A);

  await assert.rejects(
    rotateMachineClientSecret(deps(store, B), provisioned.clientId),
    hasOAuthCode("invalid_target"),
  );
  await assert.rejects(
    disableMachineClient(deps(store, B), provisioned.clientId),
    hasOAuthCode("invalid_target"),
  );
  assert.equal(store.casCalls, 0);
  assert.equal((store.rows.get(provisioned.clientId) as VersionedMachineClientRegistration).resource, A);

  await rotateMachineClientSecret(deps(store, A), provisioned.clientId);
  const rotated = store.rows.get(provisioned.clientId)! as VersionedMachineClientRegistration;
  assert.equal(rotated.resource, A);
  assert.equal(store.audits.at(-1)?.resource, A);
});

test("stored resource parsing rejects present malformed values instead of treating them as legacy", () => {
  const secret = "mcs_" + "S".repeat(43);
  const clientId = "mcc_parser";
  const base = legacyRow(clientId, secret) as unknown as Record<string, unknown>;
  const now = Math.floor(NOW_MS / 1000);

  assert.equal(parseMachineClientRegistration(base, clientId, now)?.resource, undefined);
  assert.equal(parseMachineClientRegistration({ ...base, resource: A }, clientId, now)?.resource, A);
  for (const resource of [null, "", 42, "https://A.test:443/mcp", "not-a-url"]) {
    assert.equal(
      parseMachineClientRegistration({ ...base, resource }, clientId, now),
      null,
      `resource ${String(resource)} must make the row unreadable`,
    );
  }
});

test("legacy unbound rows require singleton attestation and bind on first mutation", async () => {
  const store = new MachineStore();
  const clientId = "mcc_legacy_resource";
  const secret = "mcs_" + "L".repeat(43);
  store.rows.set(clientId, legacyRow(clientId, secret));

  const unattested = token(singletonConfig(store));
  await assert.rejects(unattested.exchangeClientCredentials({
    grantType: "client_credentials", clientId, clientSecret: secret, resource: A,
  }), hasOAuthCode("invalid_client"));
  await assert.rejects(unattested.exchangeClientCredentials({
    grantType: "client_credentials", clientId, clientSecret: secret, resource: "not-a-url",
  }), hasOAuthCode("invalid_client"), "unattested legacy lineage wins over request-resource errors");
  await assert.rejects(token(multiConfig(store)).exchangeClientCredentials({
    grantType: "client_credentials", clientId, clientSecret: secret, resource: A,
  }), hasOAuthCode("invalid_client"));

  const attestedConfig = singletonConfig(store, true);
  const attested = token(attestedConfig);
  const issued = await attested.exchangeClientCredentials({
    grantType: "client_credentials", clientId, clientSecret: secret, resource: A,
  });
  assert.equal((await verifyAccessToken(issued.access_token, attestedConfig, new FixedClock(), A)).resource, A);

  await rotateMachineClientSecret(deps(store, A, A), clientId);
  const migrated = store.rows.get(clientId)! as VersionedMachineClientRegistration;
  assert.equal(migrated.version, 1);
  assert.equal(migrated.resource, A);
  assert.equal(store.audits.at(-1)?.resource, A);
});

test("lifecycle uses the exact store snapshot whose capability it checked", async () => {
  const checked = new MachineStore();
  const provisioned = await provisionMachineClient(deps(checked), { allowedScopes: ["mcp:read"] });
  const unchecked = new MachineStore(false);
  let storeReads = 0;
  const dynamicDeps = {
    get store(): ClientStore {
      storeReads += 1;
      return storeReads === 1 ? checked : unchecked;
    },
    resource: A,
    catalog: [...SCOPES],
    config: multiConfig(checked),
    clock: new FixedClock(),
    audit: noopAudit,
  } as MachineClientDeps;

  await rotateMachineClientSecret(dynamicDeps, provisioned.clientId);
  assert.equal(storeReads, 1);
  assert.equal(checked.casCalls, 1);
  assert.equal(unchecked.findCalls, 0);
});

test("missing machine resource capability fails before token construction or lifecycle store access", async () => {
  const store = new MachineStore(false);
  assert.throws(() => token(singletonConfig(store)), AuthConfigError);
  assert.equal(store.findCalls, 0);

  await assert.rejects(
    provisionMachineClient(deps(store), { allowedScopes: ["mcp:read"] }),
    AuthConfigError,
  );
  await assert.rejects(rotateMachineClientSecret(deps(store), "mcc_none"), AuthConfigError);
  await assert.rejects(disableMachineClient(deps(store), "mcc_none"), AuthConfigError);
  assert.equal(store.findCalls, 0);
  assert.equal(store.createCalls, 0);
  assert.equal(store.casCalls, 0);
});

test("provisioning validates the canonical resource/catalog pair before generation or create", async () => {
  const store = new MachineStore();
  await assert.rejects(
    provisionMachineClient(deps(store, "https://A.test:443/mcp"), { allowedScopes: ["mcp:read"] }),
    AuthConfigError,
  );
  await assert.rejects(
    provisionMachineClient({ ...deps(store), catalog: ["mcp:read", "mcp:read"] }, { allowedScopes: ["mcp:read"] }),
    AuthConfigError,
  );
  assert.equal(store.createCalls, 0);
});
