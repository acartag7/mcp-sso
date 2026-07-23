import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { issuerOrigin } from "../src/adapters/http.ts";
import { JsonlFileAudit } from "../src/audit/jsonl-file.ts";
import { WebhookAudit } from "../src/audit/webhook.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import {
  buildBasicClientChallenge, buildUnauthorizedChallenge, protectedResourceMetadataUrl,
} from "../src/challenge.ts";
import {
  assertBridgeConfig, AuthConfigError, createBridgeConfig, type BridgeConfig,
} from "../src/config.ts";
import {
  pkceChallenge, publicJwk, sha256Hex, signAccessToken, signConsentToken,
  verifyAccessToken, verifyConsentToken,
} from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import {
  authorizationServerMetadata, jwks, protectedResourceMetadata,
  protectedResourceMetadataUrls,
} from "../src/metadata.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore, MachineClientRegistration } from "../src/ports/client-store.ts";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput,
  StorePort,
} from "../src/ports/store.ts";
import { StoreInputError } from "../src/ports/store.ts";
import { registerClient } from "../src/register.ts";
import { verifyMachineClientSecret } from "../src/machine-client.ts";
import { parseFoundClientRegistration } from "../src/stored-records.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { OAuthTokenUseCase } from "../src/token.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const NOW_MS = Date.parse("2026-07-23T12:00:00.000Z");
const NOW_ISO = new Date(NOW_MS).toISOString();
const FUTURE = "2099-01-01T00:00:00.000Z";
const PAST = "2000-01-01T00:00:00.000Z";
const REDIRECT = "https://client.test/callback";
const VERIFIER = "boundary-verifier-0123456789abcdef012345678901234567";
const clock = Object.freeze({ nowMs: () => NOW_MS });
const audit = Object.freeze({ async writeAuthEvent(): Promise<void> {} });

function config(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "boundary-key" } as JWK;
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "boundary-consent-secret-with-enough-entropy",
    signingPrivateJwk: jwk,
    signingKeyId: "boundary-key",
    redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

function stubStore(overrides: Partial<StorePort> = {}): StorePort {
  return {
    async saveAuthCode() {},
    async consumeAuthCode() { return null; },
    async saveRefreshToken() {},
    async rotateRefreshToken() { return null; },
    async revokeRefreshTokenFamily() {},
    async findRefreshToken() { return null; },
    async consumeConsentJti() { return true; },
    async findGrantedScopes() { return []; },
    async sweepExpired() {},
    async close() {},
    ...overrides,
  };
}

function validAuthCode(rawCode: string, cfg: BridgeConfig): AuthCodeRecord {
  return {
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "user-1",
    redirectUri: REDIRECT, resource: cfg.resource, scopes: ["mcp:read"],
    codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
    expiresAt: FUTURE,
  };
}

test("token exchange rejects inherited and accessor-backed store records", async () => {
  const cfg = config();
  for (const kind of ["inherited", "accessor"] as const) {
    const rawCode = `boundary-${kind}`;
    const valid = validAuthCode(rawCode, cfg);
    let getterCalls = 0;
    const record = kind === "inherited"
      ? Object.assign(Object.create({ resource: valid.resource }), { ...valid, resource: undefined })
      : { ...valid };
    if (kind === "inherited") delete record.resource;
    else {
      Object.defineProperty(record, "resource", {
        enumerable: true,
        get() { getterCalls += 1; return valid.resource; },
      });
    }
    let refreshWrites = 0;
    const store = stubStore({
      async consumeAuthCode() { return record as AuthCodeRecord; },
      async saveRefreshToken() { refreshWrites += 1; },
    });
    const tokens = new OAuthTokenUseCase({ config: cfg, store, clock, audit });
    await assert.rejects(
      tokens.exchangeAuthorizationCode({
        grantType: "authorization_code", code: rawCode, clientId: "client-1",
        redirectUri: REDIRECT, codeVerifier: VERIFIER,
      }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
    );
    assert.equal(getterCalls, 0, "store-return accessor was never invoked");
    assert.equal(refreshWrites, 0, "malformed store record caused no token write");
  }
});

test("token exchange binds returned authorization codes to lookup, resource, and expiry", async () => {
  const cfg = config();
  const cases = [
    {
      label: "lookup hash",
      make(rawCode: string) { return { ...validAuthCode(rawCode, cfg), codeHash: sha256Hex("different-code") }; },
    },
    {
      label: "configured resource",
      make(rawCode: string) { return { ...validAuthCode(rawCode, cfg), resource: "https://other.test/mcp" }; },
    },
    {
      label: "strict expiry",
      make(rawCode: string) { return { ...validAuthCode(rawCode, cfg), expiresAt: NOW_ISO }; },
    },
  ];
  for (const { label, make } of cases) {
    const rawCode = `bound-auth-code-${label.replace(/\s/g, "-")}`;
    let refreshWrites = 0;
    const store = stubStore({
      async consumeAuthCode() { return make(rawCode); },
      async saveRefreshToken() { refreshWrites += 1; },
    });
    const tokens = new OAuthTokenUseCase({ config: cfg, store, clock, audit });
    await assert.rejects(
      tokens.exchangeAuthorizationCode({
        grantType: "authorization_code", code: rawCode, clientId: "client-1",
        redirectUri: REDIRECT, codeVerifier: VERIFIER,
      }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
      label,
    );
    assert.equal(refreshWrites, 0, `${label}: no refresh token was written`);
  }
});

test("refresh rejects returned records not bound to the token family or validity window", async () => {
  const cfg = config();
  const familyId = "family-0123456789abcdef";
  const raw = `rt.${familyId}.refresh-material`;
  const valid: RefreshTokenRecord = {
    tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
    clientId: "client-1", subject: "user-1", scopes: ["mcp:read"], expiresAt: FUTURE,
  };
  let getterCalls = 0;
  const inherited = Object.assign(Object.create({ subject: valid.subject }), valid) as RefreshTokenRecord;
  delete (inherited as { subject?: string }).subject;
  const accessor = { ...valid } as RefreshTokenRecord;
  Object.defineProperty(accessor, "scopes", {
    enumerable: true,
    get() { getterCalls += 1; return ["mcp:read"]; },
  });
  const cases: Array<[string, RefreshTokenRecord]> = [
    ["lookup hash", { ...valid, tokenHash: sha256Hex("different-refresh") }],
    ["family", { ...valid, familyId: "family-fedcba9876543210" }],
    ["expiry", { ...valid, expiresAt: NOW_ISO }],
    ["inherited field", inherited],
    ["accessor field", accessor],
  ];
  for (const [label, record] of cases) {
    let familyRevocations = 0;
    const store = stubStore({
      async rotateRefreshToken() { return record; },
      async revokeRefreshTokenFamily() { familyRevocations += 1; },
    });
    const tokens = new OAuthTokenUseCase({ config: cfg, store, clock, audit });
    await assert.rejects(
      tokens.refresh({ grantType: "refresh_token", refreshToken: raw, clientId: "client-1" }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
      label,
    );
    assert.equal(familyRevocations, 0, `${label}: an unbound record cannot select a family`);
  }
  assert.equal(getterCalls, 0, "refresh-record accessors were never invoked");
});

test("refresh uses one timestamp for rotation and returned-record validation", async () => {
  const cfg = config();
  const familyId = "family-0123456789abcdef";
  const raw = `rt.${familyId}.refresh-material`;
  const first = NOW_MS;
  let clockReads = 0;
  const advancingClock = {
    nowMs() { clockReads += 1; return clockReads === 1 ? first : first + 2_000; },
  };
  let storeNow: string | undefined;
  const store = stubStore({
    async rotateRefreshToken(_hash, _next, nowIso) {
      storeNow = nowIso;
      return {
        tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
        clientId: "client-1", subject: "user-1", scopes: ["mcp:read"],
        expiresAt: new Date(first + 1_000).toISOString(),
      };
    },
  });
  const tokens = new OAuthTokenUseCase({ config: cfg, store, clock: advancingClock, audit });
  const response = await tokens.refresh({
    grantType: "refresh_token", refreshToken: raw, clientId: "client-1",
  });
  assert.equal(response.token_type, "Bearer");
  assert.equal(storeNow, new Date(first).toISOString());
});

test("revocation only uses a lookup-bound own-data refresh record", async () => {
  const cfg = config();
  const familyId = "family-0123456789abcdef";
  const raw = `rt.${familyId}.revocation-material`;
  const valid: RefreshTokenRecord = {
    tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
    clientId: "client-1", subject: "user-1", scopes: ["mcp:read"], expiresAt: PAST,
  };
  let getterCalls = 0;
  const accessor = { ...valid } as RefreshTokenRecord;
  Object.defineProperty(accessor, "familyId", {
    enumerable: true,
    get() { getterCalls += 1; return familyId; },
  });
  for (const record of [{ ...valid, tokenHash: sha256Hex("other") }, accessor]) {
    let familyRevocations = 0;
    const tokens = new OAuthTokenUseCase({
      config: cfg,
      store: stubStore({
        async findRefreshToken() { return record; },
        async revokeRefreshTokenFamily() { familyRevocations += 1; },
      }),
      clock,
      audit,
    });
    await assert.doesNotReject(tokens.revoke(raw));
    assert.equal(familyRevocations, 0, "an unbound record did not select a family");
  }
  assert.equal(getterCalls, 0, "revocation did not invoke a returned-record accessor");

  let revokedFamily: string | undefined;
  const tokens = new OAuthTokenUseCase({
    config: cfg,
    store: stubStore({
      async findRefreshToken() { return valid; },
      async revokeRefreshTokenFamily(value) { revokedFamily = value; },
    }),
    clock,
    audit,
  });
  await tokens.revoke(raw);
  assert.equal(revokedFamily, familyId, "a bound record remains revocable after token expiry");
});

test("revocation accepts a structurally valid class-based store record", async () => {
  const cfg = config();
  const familyId = "family-0123456789abcdef";
  const raw = `rt.${familyId}.class-record`;
  class RefreshDto {
    get tokenHash() { return sha256Hex(raw); }
    get familyId() { return familyId; }
    get previousTokenHash() { return null; }
    get clientId() { return "client-1"; }
    get subject() { return "user-1"; }
    get scopes() { return ["mcp:read"]; }
    get expiresAt() { return FUTURE; }
  }
  let revoked: string | undefined;
  const tokens = new OAuthTokenUseCase({
    config: cfg,
    store: stubStore({
      async findRefreshToken() { return new RefreshDto() as RefreshTokenRecord; },
      async revokeRefreshTokenFamily(value) { revoked = value; },
    }),
    clock, audit,
  });
  await tokens.revoke(raw);
  assert.equal(revoked, familyId);
});

test("returned client registrations require own-data identity, type, and secret entries", async () => {
  const clientId = "mcc_boundary_client";
  const secret = "boundary-client-secret";
  const epoch = Math.floor(NOW_MS / 1000);
  const validMachine: MachineClientRegistration = {
    clientId, redirectUris: [], applicationType: "machine", issuedAtEpoch: epoch,
    allowedScopes: ["mcp:read"],
    secrets: [{ hash: sha256Hex(secret), createdAtEpoch: epoch }],
  };
  const validUser: ClientRegistration = {
    clientId: "mcpdc_boundary_client", redirectUris: [REDIRECT],
    applicationType: "web", issuedAtEpoch: epoch,
  };
  assert.ok(parseFoundClientRegistration(validUser, validUser.clientId), "well-formed user record accepted");
  assert.equal(parseFoundClientRegistration(validUser, "mcpdc_other"), null, "lookup identity is exact");
  assert.equal(
    parseFoundClientRegistration({ ...validUser, applicationType: "desktop" }, validUser.clientId),
    null,
    "unknown application type is rejected",
  );

  let getterCalls = 0;
  const inheritedIdentity = Object.assign(Object.create({ clientId }), validMachine) as MachineClientRegistration;
  delete (inheritedIdentity as { clientId?: string }).clientId;
  const typeAccessor = { ...validMachine } as MachineClientRegistration;
  Object.defineProperty(typeAccessor, "applicationType", {
    enumerable: true,
    get() { getterCalls += 1; return "machine"; },
  });
  const inheritedSecret = {
    ...validMachine,
    secrets: [Object.assign(Object.create({ hash: sha256Hex(secret) }), { createdAtEpoch: epoch })],
  } as MachineClientRegistration;
  const secretAccessor = {
    ...validMachine,
    secrets: [{ createdAtEpoch: epoch }],
  } as unknown as MachineClientRegistration;
  Object.defineProperty(secretAccessor.secrets[0]!, "hash", {
    enumerable: true,
    get() { getterCalls += 1; return sha256Hex(secret); },
  });

  const storeFor = (record: ClientRegistration): ClientStore => ({
    async save() {},
    async find() { return record; },
  });
  for (const record of [inheritedIdentity, typeAccessor, inheritedSecret, secretAccessor]) {
    assert.equal(
      await verifyMachineClientSecret(
        { store: storeFor(record), catalog: ["mcp:read"], clock, audit },
        clientId,
        secret,
      ),
      false,
      "malformed returned client record is rejected",
    );
  }
  assert.equal(getterCalls, 0, "client-record accessors were never invoked");
  assert.equal(
    await verifyMachineClientSecret(
      { store: storeFor(validMachine), catalog: ["mcp:read"], clock, audit },
      clientId,
      secret,
    ),
    true,
    "well-formed own-data machine record remains accepted",
  );
});

test("memory store rejects accessor-backed auth and refresh write inputs", async () => {
  const store = new MemoryStore();
  let getterCalls = 0;
  const authInput = validAuthCode("auth-write", config()) as SaveAuthCodeInput;
  Object.defineProperty(authInput, "subject", {
    enumerable: true,
    get() { getterCalls += 1; return "user-1"; },
  });
  await assert.rejects(store.saveAuthCode(authInput), StoreInputError);

  const refreshInput: SaveRefreshTokenInput = {
    tokenHash: sha256Hex("refresh-write"), familyId: "family-0123456789",
    previousTokenHash: null, clientId: "client-1", subject: "user-1",
    scopes: ["mcp:read"], expiresAt: FUTURE,
  };
  Object.defineProperty(refreshInput, "scopes", {
    enumerable: true,
    get() { getterCalls += 1; return ["mcp:read"]; },
  });
  await assert.rejects(store.saveRefreshToken(refreshInput), StoreInputError);
  assert.equal(getterCalls, 0, "store input accessors were never invoked");
  await store.close();
});

test("approval denies a truthy non-boolean consent-store result", async () => {
  const cfg = config();
  let authCodeWrites = 0;
  const store = stubStore({
    async consumeConsentJti() { return 1 as unknown as boolean; },
    async saveAuthCode() { authCodeWrites += 1; },
  });
  const authorization = new OAuthAuthorizationUseCase({ config: cfg, store, clock, audit });
  const prepared = await authorization.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
    subject: "user-1",
  });
  await assert.rejects(
    authorization.approve({
      consentToken: prepared.consentToken, approved: true, origin: "https://auth.test",
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  assert.equal(authCodeWrites, 0, "non-boolean consent result caused no authorization-code write");
});

test("empty persisted scopes remain empty instead of expanding to defaults", async () => {
  const cfg = config();
  const store = new MemoryStore();
  const rawCode = "empty-scope-code";
  await store.saveAuthCode({ ...validAuthCode(rawCode, cfg), scopes: [] });
  const tokens = new OAuthTokenUseCase({ config: cfg, store, clock, audit });
  const response = await tokens.exchangeAuthorizationCode({
    grantType: "authorization_code", code: rawCode, clientId: "client-1",
    redirectUri: REDIRECT, codeVerifier: VERIFIER,
  });
  assert.equal(response.scope, "");
  assert.deepEqual((await verifyAccessToken(response.access_token, cfg, clock)).scopes, []);
  const stored = await store.findRefreshToken(sha256Hex(response.refresh_token));
  assert.deepEqual(stored?.scopes, []);
  await store.close();
});

test("plain structural clones of validated config are rejected at every config boundary", async () => {
  const cfg = config();
  const clone = { ...cfg } as BridgeConfig;
  const syncBoundaries: Array<readonly [string, () => unknown]> = [
    ["assertBridgeConfig", () => assertBridgeConfig(clone)],
    ["Bridge", () => new Bridge({ config: clone, store: stubStore(), clock, audit })],
    ["OAuthAuthorizationUseCase", () => new OAuthAuthorizationUseCase({ config: clone, store: stubStore(), clock, audit })],
    ["OAuthTokenUseCase", () => new OAuthTokenUseCase({ config: clone, store: stubStore(), clock, audit })],
    ["RequestAuthorizer", () => new RequestAuthorizer({ config: clone, clock, audit })],
    ["protectedResourceMetadataUrl", () => protectedResourceMetadataUrl(clone)],
    ["buildUnauthorizedChallenge", () => buildUnauthorizedChallenge(clone)],
    ["buildBasicClientChallenge", () => buildBasicClientChallenge(clone)],
    ["authorizationServerMetadata", () => authorizationServerMetadata(clone)],
    ["protectedResourceMetadata", () => protectedResourceMetadata(clone)],
    ["protectedResourceMetadataUrls", () => protectedResourceMetadataUrls(clone)],
    ["jwks", () => jwks(clone)],
    ["publicJwk", () => publicJwk(clone)],
    ["issuerOrigin", () => issuerOrigin(clone)],
  ];
  for (const [label, invoke] of syncBoundaries) {
    assert.throws(invoke, AuthConfigError, label);
  }

  await assert.rejects(
    registerClient(
      { config: clone, clock, audit },
      { redirectUris: [REDIRECT], applicationType: "web" },
    ),
    AuthConfigError,
  );
  await assert.rejects(
    signConsentToken({
      clientId: "client-1", redirectUri: REDIRECT, resource: cfg.resource,
      scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER),
      codeChallengeMethod: "S256", subject: "user-1",
    }, clone, clock),
    AuthConfigError,
  );
  await assert.rejects(verifyConsentToken("not-a-token", clone, clock), AuthConfigError);
  await assert.rejects(
    signAccessToken({ subject: "user-1", clientId: "client-1", scopes: ["mcp:read"] }, clone, clock),
    AuthConfigError,
  );
  await assert.rejects(verifyAccessToken("not-a-token", clone, clock), AuthConfigError);
});

test("audit sinks never reject when event or status accessors throw", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-boundary-audit-"));
  const originalError = console.error;
  console.error = () => {};
  try {
    for (const field of ["event", "status"] as const) {
      let reads = 0;
      const hostile = {
        occurredAt: NOW_ISO, event: "auth.request", status: "failure",
      } as AuthAuditEvent;
      Object.defineProperty(hostile, field, {
        enumerable: true,
        get() { reads += 1; throw new Error(`${field} getter`); },
      });
      const file = new JsonlFileAudit(join(dir, `${field}.jsonl`));
      await assert.doesNotReject(() => file.writeAuthEvent(hostile));
      assert.equal(reads, 1, "JSON serialization was the only accessor read");

      let fetchCalls = 0;
      const webhook = new WebhookAudit("https://audit.test/ingest", {
        fetchImpl: (async () => {
          fetchCalls += 1;
          return { ok: true, status: 200 } as Response;
        }) as typeof fetch,
      });
      await assert.doesNotReject(() => webhook.writeAuthEvent(hostile));
      assert.equal(reads, 2, "each sink attempted serialization once");
      assert.equal(fetchCalls, 0, "serialization failure prevented transport side effects");
    }
  } finally {
    console.error = originalError;
    await rm(dir, { recursive: true, force: true });
  }
});
