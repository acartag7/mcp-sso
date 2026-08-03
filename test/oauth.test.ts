import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { importJWK, SignJWT, type JWTPayload, type JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import {
  type BridgeConfig, AuthConfigError, createBridgeConfig, originOf, KNOWN_CONFIG_KEYS,
} from "../src/config.ts";
import { OAuthError, oauthErrorBody } from "../src/errors.ts";
import { pkceChallenge, sha256Hex, signAccessToken, verifyAccessToken } from "../src/crypto.ts";
import { requireScope } from "../src/scopes.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import {
  authorizationServerMetadata, jwks, protectedResourceMetadata, protectedResourceMetadataUrls,
} from "../src/metadata.ts";
import {
  type ApproveResult, type PreparedConsent, OAuthAuthorizationUseCase,
} from "../src/authorize.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { OAuthTokenUseCase, type TokenResponse } from "../src/token.ts";
import { registerClient } from "../src/register.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";

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
  writeAuthEvent(): Promise<void> { throw new Error("audit unavailable"); }
}

class InMemoryClientStore implements ClientStore {
  private readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

interface Ctx {
  config: BridgeConfig;
  clock: FakeClock;
  store: MemoryStore;
  audit: MemoryAudit;
  auth: OAuthAuthorizationUseCase;
  token: OAuthTokenUseCase;
  clientStore?: InMemoryClientStore;
}

function testPrivateJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "test-key-1" } as JWK;
}

function makeConfig(opts: { resource?: string; redirectAllowlist?: string[]; scopeCatalog?: string[]; defaultScopes?: string[]; dcr?: BridgeConfig["dcr"]; dev?: boolean } = {}): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: opts.resource ?? "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: testPrivateJwk(),
    signingKeyId: "test-key-1",
    redirectAllowlist: opts.redirectAllowlist ?? [REDIRECT],
    scopeCatalog: opts.scopeCatalog ?? ["mcp:read", "mcp:write"],
    defaultScopes: opts.defaultScopes ?? ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: opts.dcr ?? { mode: "stateless" },
    dev: opts.dev ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

async function forgeAccessToken(ctx: Ctx, claims: JWTPayload): Promise<string> {
  const now = Math.floor(ctx.clock.nowMs() / 1000);
  const key = await importJWK(ctx.config.signingPrivateJwk, "ES256");
  return await new SignJWT({ client_id: "client-1", scope: "mcp:read", ...claims })
    .setProtectedHeader({ alg: "ES256", kid: ctx.config.signingKeyId, typ: "JWT" })
    .setIssuer(ctx.config.issuer)
    .setAudience(ctx.config.resource)
    .setIssuedAt(now)
    .setExpirationTime(now + ctx.config.accessTokenTtlSeconds)
    .sign(key);
}

function setup(opts: {
  redirectAllowlist?: string[];
  scopeCatalog?: string[];
  defaultScopes?: string[];
  dcr?: BridgeConfig["dcr"];
} = {}): Ctx {
  const clientStore = opts.dcr?.mode === "stored" ? new InMemoryClientStore() : undefined;
  const config = makeConfig({
    redirectAllowlist: opts.redirectAllowlist,
    scopeCatalog: opts.scopeCatalog,
    defaultScopes: opts.defaultScopes,
    dcr: opts.dcr ?? (clientStore ? { mode: "stored", store: clientStore } : undefined),
  });
  return setupWithConfig(config);
}

function setupWithConfig(config: BridgeConfig, store = new MemoryStore(), audit = new MemoryAudit()): Ctx {
  const clientStore = config.dcr.mode === "stored" && config.dcr.store instanceof InMemoryClientStore
    ? config.dcr.store : undefined;
  const clock = new FakeClock(NOW_MS);
  return {
    config, clock, store, audit, clientStore,
    auth: new OAuthAuthorizationUseCase({ config, store, clock, audit }),
    token: new OAuthTokenUseCase({ config, store, clock, audit }),
  };
}

async function approveCode(ctx: Ctx, verifier: string, scope: string, subject = SUBJECT, clientId = "client-1"): Promise<{ code: string }> {
  const prepared = await ctx.auth.prepare({
    clientId, redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    scope, state: "state-1", subject,
  });
  const approved = await ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approved.code, "approve mints a code");
  const location = new URL(approved.redirectTo);
  assert.equal(location.searchParams.get("iss"), ctx.config.issuer); // RFC 9207
  assert.equal(location.searchParams.get("state"), "state-1");
  return { code: approved.code };
}

async function exchangeCode(ctx: Ctx, verifier: string, scope = "mcp:read mcp:write", clientId = "client-1"): Promise<TokenResponse> {
  const { code } = await approveCode(ctx, verifier, scope, SUBJECT, clientId);
  return await ctx.token.exchangeAuthorizationCode({
    grantType: "authorization_code", code, redirectUri: REDIRECT, clientId, codeVerifier: verifier,
  });
}

function isInvalidAuthorizationCode(error: unknown): boolean {
  return error instanceof OAuthError
    && error.code === "invalid_grant"
    && error.message === "Authorization code is invalid";
}

// --- the flow ---

test("PKCE S256 authorize/approve/token mints an ES256 access token + hashed refresh", async () => {
  const ctx = setup();
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const { code } = await approveCode(ctx, verifier, "mcp:read mcp:write");
  const token = await ctx.token.exchangeAuthorizationCode({
    grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier,
  });
  assert.equal(token.token_type, "Bearer");
  assert.equal(token.expires_in, 600);
  assert.equal(token.scope, "mcp:read mcp:write");
  assert.match(token.access_token, /^[^.]+\.[^.]+\.[^.]+$/);
  assert.match(token.refresh_token, /^rt\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const verified = await verifyAccessToken(token.access_token, ctx.config, ctx.clock);
  assert.equal(verified.subject, SUBJECT);
  assert.equal(verified.clientId, "client-1");
  assert.deepEqual(verified.scopes.sort(), ["mcp:read", "mcp:write"]);
  assert.equal(verified.credentialKind, "interactive");
  // audit never contains raw secrets
  const auditJson = JSON.stringify(ctx.audit.events);
  for (const secret of [code, token.refresh_token, token.access_token]) assert.equal(auditJson.includes(secret), false, `audit leaked: ${secret}`);
  await ctx.store.close();
});

test("authorize: pre-validation redirect error is direct (no redirect tag)", async () => {
  const ctx = setup();
  await assert.rejects(
    ctx.auth.prepare({
      clientId: "client-1", redirectUri: "https://evil.test/callback", responseType: "code",
      codeChallenge: pkceChallenge("verifier-123456789012345678901234567890123"), codeChallengeMethod: "S256", subject: SUBJECT,
    }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_redirect_uri" && !e.redirect,
  );
  await ctx.store.close();
});

test("authorize: post-validation scope error is redirect-tagged (RFC 6749 §4.1.2.1)", async () => {
  const ctx = setup();
  await assert.rejects(
    ctx.auth.prepare({
      clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
      codeChallenge: pkceChallenge("verifier-123456789012345678901234567890123"), codeChallengeMethod: "S256",
      scope: "mcp:admin", state: "s1", subject: SUBJECT,
    }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_scope" && e.redirect?.redirectUri === REDIRECT && e.redirect?.state === "s1",
  );
  await ctx.store.close();
});

test("authorize fails closed (access_denied 401) with no subject", async () => {
  const ctx = setup();
  await assert.rejects(
    ctx.auth.prepare({
      clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
      codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", subject: undefined,
    }),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401 && !e.redirect,
  );
  await ctx.store.close();
});

test("invalid verifier consumes the code and prevents later reuse", async () => {
  const ctx = setup();
  const verifier = "valid-verifier-123456789012345678901234567890123";
  const { code } = await approveCode(ctx, verifier, "mcp:read");
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({
      grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1",
      codeVerifier: "wrong-verifier-123456789012345678901234567890123",
    }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await ctx.store.close();
});

test("expired auth code returns invalid_grant", async () => {
  const ctx = setup();
  const verifier = "valid-verifier-abcdef123456789012345678901234567890123";
  const { code } = await approveCode(ctx, verifier, "mcp:read");
  ctx.clock.advance(301_000); // code TTL is 300s
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await ctx.store.close();
});

test("authorization code stays bound to its resource across token use-cases sharing a store", async () => {
  const resourceA = "https://resource-a.test/mcp";
  const resourceB = "https://resource-b.test/mcp";
  const store = new MemoryStore();
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  const configA = makeConfig({ resource: resourceA });
  const configB = makeConfig({ resource: resourceB });
  const tokenA = new OAuthTokenUseCase({ config: configA, store, clock, audit });
  const tokenB = new OAuthTokenUseCase({ config: configB, store, clock, audit });
  const verifier = "resource-binding-verifier-123456789012345678901234567";
  const code = "resource-binding-code";
  await store.saveAuthCode({
    codeHash: sha256Hex(code), clientId: "client-1", subject: SUBJECT,
    redirectUri: REDIRECT, resource: resourceA, scopes: ["mcp:read"],
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    expiresAt: "2026-07-03T13:00:00.000Z", grantGeneration: null,
  });
  const input = { grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier };
  await assert.rejects(tokenB.exchangeAuthorizationCode(input), isInvalidAuthorizationCode);
  assert.equal(audit.events.some((event) => event.event === "oauth.token.authorization_code" && event.status === "success"), false);
  const issued = await tokenA.exchangeAuthorizationCode(input);
  assert.equal((await verifyAccessToken(issued.access_token, configA, clock)).subject, SUBJECT);
  await assert.rejects(tokenA.exchangeAuthorizationCode(input), isInvalidAuthorizationCode);
  await store.close();
});

test("token use-case rejects a wrong-resource record returned by a custom store before signing or refresh persistence", async () => {
  const resourceA = "https://resource-a.test/mcp";
  const resourceB = "https://resource-b.test/mcp";
  class IgnoringResourceStore extends MemoryStore {
    override consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number): ReturnType<MemoryStore["consumeAuthCode"]> {
      return super.consumeAuthCode(codeHash, nowIso, expectedGrantGeneration);
    }
  }
  const store = new IgnoringResourceStore();
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  const configB = makeConfig({ resource: resourceB });
  const tokenB = new OAuthTokenUseCase({ config: configB, store, clock, audit });
  const verifier = "custom-store-resource-verifier-12345678901234567890123";
  const code = "custom-store-resource-code";
  await store.saveAuthCode({
    codeHash: sha256Hex(code), clientId: "client-1", subject: SUBJECT,
    redirectUri: REDIRECT, resource: resourceA, scopes: ["mcp:read"],
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    expiresAt: "2026-07-03T13:00:00.000Z", grantGeneration: null,
  });
  let refreshWrites = 0;
  const saveRefreshToken = store.saveRefreshToken.bind(store);
  store.saveRefreshToken = async (input) => { refreshWrites += 1; await saveRefreshToken(input); };
  let response: TokenResponse | undefined;
  let error: unknown;
  try {
    response = await tokenB.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier });
  } catch (caught) { error = caught; }
  assert.deepEqual({
    invalidGrant: isInvalidAuthorizationCode(error),
    tokenReturned: response !== undefined,
    refreshWrites,
    successAudits: audit.events.filter((event) => event.event === "oauth.token.authorization_code" && event.status === "success").length,
  }, { invalidGrant: true, tokenReturned: false, refreshWrites: 0, successAudits: 0 });
  await store.close();
});

test("refresh token rotates and replay revokes the family", async () => {
  const ctx = setup();
  const initial = await exchangeCode(ctx, "refresh-verifier-123456789012345678901234567890123");
  const rotated = await ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" });
  assert.notEqual(rotated.refresh_token, initial.refresh_token);
  assert.equal((await verifyAccessToken(initial.access_token, ctx.config, ctx.clock)).credentialKind, "interactive");
  assert.equal((await verifyAccessToken(rotated.access_token, ctx.config, ctx.clock)).credentialKind, "interactive");
  // replay the original -> invalid_grant
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  // the rotated successor is also dead now (family revoked)
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: rotated.refresh_token, clientId: "client-1" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await ctx.store.close();
});

test("replay still revokes the family when the consumed row's scope left the catalog", async () => {
  const ctx = setup();
  const initial = await exchangeCode(
    ctx, "catalog-drift-verifier-123456789012345678901234567", "mcp:read",
  );
  const rotated = await ctx.token.refresh({
    grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1",
  });
  const driftedToken = new OAuthTokenUseCase({
    config: makeConfig({ scopeCatalog: ["mcp:write"], defaultScopes: [] }),
    store: ctx.store, clock: ctx.clock, audit: ctx.audit,
  });
  await assert.rejects(
    driftedToken.refresh({
      grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1",
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  await assert.rejects(
    ctx.token.refresh({
      grantType: "refresh_token", refreshToken: rotated.refresh_token, clientId: "client-1",
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
    "replaying the predecessor revoked the successor despite catalog drift",
  );
  await ctx.store.close();
});

test("refresh with a mismatched client_id is rejected and revokes the family (RFC 6749 §6)", async () => {
  const ctx = setup();
  const initial = await exchangeCode(ctx, "refresh-verifier-123456789012345678901234567890123");
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-2" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  // the legitimate client can no longer use it either (family revoked)
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" }),
    (e: unknown) => e instanceof OAuthError,
  );
  await ctx.store.close();
});

test("refresh resource substitution is invalid_grant without mutation, then the bound resource rotates and replays normally", async () => {
  const signingPrivateJwk = testPrivateJwk();
  const resourceA = "https://api-a.test/mcp";
  const resourceB = "https://api-b.test/mcp";
  const configA = createBridgeConfig({ ...baseInput(), resource: resourceA, signingPrivateJwk });
  const configB = createBridgeConfig({ ...baseInput(), resource: resourceB, signingPrivateJwk });
  const store = new MemoryStore();
  const auditA = new MemoryAudit();
  const auditB = new MemoryAudit();
  const ctxA = setupWithConfig(configA, store, auditA);
  const ctxB = setupWithConfig(configB, store, auditB);
  const initial = await exchangeCode(ctxA, "resource-binding-verifier-123456789012345678901234567890");

  await assert.rejects(
    ctxB.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" }),
    (error: unknown) => error instanceof OAuthError
      && error.code === "invalid_grant" && error.message === "Refresh token is invalid",
  );
  assert.equal(
    auditB.events.some((event) => event.event === "oauth.token.refresh" && event.status === "success"),
    false,
    "resource B emits no refresh success audit",
  );
  assert.equal((await store.findRefreshToken(sha256Hex(initial.refresh_token)))?.resource, resourceA);

  const rotated = await ctxA.token.refresh({
    grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1",
  });
  assert.notEqual(rotated.refresh_token, initial.refresh_token, "resource A still rotates once");
  await assert.rejects(
    ctxA.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  await assert.rejects(
    ctxA.token.refresh({ grantType: "refresh_token", refreshToken: rotated.refresh_token, clientId: "client-1" }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
    "the correct-resource replay retains normal family revocation",
  );
  await store.close();
});

test("refresh rejects a hostile store's mismatched resource before signing or success audit", async () => {
  const resourceA = "https://api-a.test/mcp";
  const resourceB = "https://api-b.test/mcp";
  const config = createBridgeConfig({
    ...baseInput(), resource: resourceA,
    // This shape passes configuration validation but causes signing to fail. An
    // invalid_grant therefore proves the resource recheck happens before signing.
    signingPrivateJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d", alg: "ES256", kid: "bad" } as JWK,
    signingKeyId: "bad",
  });
  const store = new MemoryStore();
  const audit = new MemoryAudit();
  const familyId = "hostileresource012345";
  const raw = `rt.${familyId}.secret-1234567890`;
  await store.saveRefreshToken({
    tokenHash: sha256Hex(raw), familyId, previousTokenHash: null,
    clientId: "client-1", subject: SUBJECT, resource: resourceB, scopes: ["mcp:read"],
    expiresAt: "2099-01-01T00:00:00.000Z",
  });
  const rotateIgnoringResource = store.rotateRefreshToken.bind(store);
  store.rotateRefreshToken = async (tokenHash, next, nowIso, expectedGeneration, _expectedResource) =>
    rotateIgnoringResource(tokenHash, next, nowIso, expectedGeneration);
  const token = new OAuthTokenUseCase({ config, store, clock: new FakeClock(NOW_MS), audit });

  await assert.rejects(
    token.refresh({ grantType: "refresh_token", refreshToken: raw, clientId: "client-1" }),
    (error: unknown) => error instanceof OAuthError
      && error.code === "invalid_grant" && error.message === "Refresh token is invalid",
  );
  assert.equal(
    audit.events.some((event) => event.event === "oauth.token.refresh" && event.status === "success"),
    false,
    "hostile result cannot emit success audit",
  );
  assert.deepEqual(
    await store.findGrantedScopes(SUBJECT, "client-1", new Date(NOW_MS).toISOString()),
    [],
    "post-rotation compensation leaves no active unreturned hostile successor",
  );
  await store.close();
});

test("refresh signing failure compensates the committed rotation through Bridge.handleToken", async () => {
  const ctx = setup();
  const initial = await exchangeCode(ctx, "sign-failure-verifier-123456789012345678901234567890");
  const badConfig = createBridgeConfig({
    ...ctx.config,
    signingPrivateJwk: {
      kty: "EC", crv: "P-256", x: "x", y: "y", d: "d", alg: "ES256", kid: "bad",
    } as JWK,
    signingKeyId: "bad",
  });
  const revocations: Array<{ familyId: string; at: string }> = [];
  const revokeFamily = ctx.store.revokeRefreshTokenFamily.bind(ctx.store);
  ctx.store.revokeRefreshTokenFamily = async (familyId, at) => {
    revocations.push({ familyId, at });
    await revokeFamily(familyId, at);
  };
  const bridge = new Bridge({
    config: badConfig, store: ctx.store, clock: ctx.clock, audit: ctx.audit,
  });
  const response = await bridge.handleToken({
    query: {}, headers: {},
    body: {
      grant_type: "refresh_token",
      refresh_token: initial.refresh_token,
      client_id: "client-1",
    },
  });
  const familyId = initial.refresh_token.split(".")[1]!;
  const nowIso = new Date(NOW_MS).toISOString();
  assert.equal(response.status, 500);
  assert.equal((response.body as { error: string }).error, "internal_error");
  assert.deepEqual(revocations, [{ familyId, at: nowIso }]);
  assert.deepEqual(
    await ctx.store.findGrantedScopes(SUBJECT, "client-1", nowIso),
    [],
    "the signing failure left no active unreturned successor",
  );
  await ctx.store.close();
});

test("refresh compensation store failure returns no token and preserves the store boundary", async () => {
  const ctx = setup();
  const initial = await exchangeCode(ctx, "store-failure-verifier-123456789012345678901234567890");
  const badConfig = createBridgeConfig({
    ...ctx.config,
    signingPrivateJwk: {
      kty: "EC", crv: "P-256", x: "x", y: "y", d: "d", alg: "ES256", kid: "bad",
    } as JWK,
    signingKeyId: "bad",
  });
  const revocations: Array<{ familyId: string; at: string }> = [];
  ctx.store.revokeRefreshTokenFamily = async (familyId, at) => {
    revocations.push({ familyId, at });
    throw new Error("store unavailable");
  };
  const bridge = new Bridge({
    config: badConfig, store: ctx.store, clock: ctx.clock, audit: ctx.audit,
  });
  const response = await bridge.handleToken({
    query: {}, headers: {},
    body: {
      grant_type: "refresh_token",
      refresh_token: initial.refresh_token,
      client_id: "client-1",
    },
  });
  const familyId = initial.refresh_token.split(".")[1]!;
  const nowIso = new Date(NOW_MS).toISOString();
  assert.equal(response.status, 500);
  assert.deepEqual(response.body, {
    error: "internal_error", error_description: "OAuth request failed",
  });
  assert.equal("access_token" in (response.body as object), false);
  assert.equal("refresh_token" in (response.body as object), false);
  assert.deepEqual(revocations, [{ familyId, at: nowIso }], "one compensation attempt at the rotation timestamp");
  assert.equal(
    ctx.audit.events.some((event) => event.event === "oauth.token.refresh" && event.status === "success"),
    false,
    "a failed response and failed compensation never emit token success",
  );
  assert.deepEqual(
    (await ctx.store.findGrantedScopes(SUBJECT, "client-1", nowIso)).sort(),
    ["mcp:read", "mcp:write"],
    "the rejecting store demonstrates why durable compensation remains store-dependent",
  );
  await ctx.store.close();
});

test("malformed stored scopes after rotation revoke the committed successor", async () => {
  const ctx = setup();
  const familyId = "malformedscopes012345";
  const rawRefresh = `rt.${familyId}.secret-1234567890`;
  await ctx.store.saveRefreshToken({
    tokenHash: sha256Hex(rawRefresh), familyId, previousTokenHash: null,
    clientId: "client-1", subject: SUBJECT, resource: ctx.config.resource, scopes: ["not-in-catalog"],
    expiresAt: "2099-01-01T00:00:00.000Z",
  });
  const revocations: Array<{ familyId: string; at: string }> = [];
  const revokeFamily = ctx.store.revokeRefreshTokenFamily.bind(ctx.store);
  ctx.store.revokeRefreshTokenFamily = async (revokedFamilyId, at) => {
    revocations.push({ familyId: revokedFamilyId, at });
    await revokeFamily(revokedFamilyId, at);
  };
  const nowIso = new Date(NOW_MS).toISOString();
  await assert.rejects(
    ctx.token.refresh({
      grantType: "refresh_token", refreshToken: rawRefresh, clientId: "client-1",
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  assert.deepEqual(revocations, [{ familyId, at: nowIso }]);
  assert.deepEqual(
    await ctx.store.findGrantedScopes(SUBJECT, "client-1", nowIso),
    [],
    "the malformed row left no active unreturned successor",
  );
  await ctx.store.close();
});

test("PKCE rejects a too-short verifier (RFC 7636: 43-128 chars)", async () => {
  const ctx = setup();
  const { code } = await approveCode(ctx, "valid-verifier-123456789012345678901234567890123", "mcp:read");
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: "x" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await ctx.store.close();
});

test("approve rejects a cross-origin POST (invalid_origin, direct)", async () => {
  const ctx = setup();
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", subject: SUBJECT,
  });
  await assert.rejects(
    ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://evil.test" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_origin" && e.status === 403 && !e.redirect,
  );
  await ctx.store.close();
});

test("approve rejects a replayed consent token (single-use jti, direct)", async () => {
  const ctx = setup();
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", state: "s", subject: SUBJECT,
  });
  await ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  await assert.rejects(
    ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant" && !e.redirect,
  );
  await ctx.store.close();
});

async function assertCrossResourceConsentRejected(approved: boolean): Promise<void> {
  const resourceA = "https://resource-a.test/mcp";
  const resourceB = "https://resource-b.test/mcp";
  const store = new MemoryStore();
  const clock = new FakeClock(NOW_MS);
  const auditA = new MemoryAudit();
  const auditB = new MemoryAudit();
  const authA = new OAuthAuthorizationUseCase({ config: makeConfig({ resource: resourceA }), store, clock, audit: auditA });
  const authB = new OAuthAuthorizationUseCase({ config: makeConfig({ resource: resourceB }), store, clock, audit: auditB });
  let codeWrites = 0;
  let jtiConsumes = 0;
  const saveAuthCode = store.saveAuthCode.bind(store);
  const consumeConsentJti = store.consumeConsentJti.bind(store);
  store.saveAuthCode = async (record) => { codeWrites += 1; await saveAuthCode(record); };
  store.consumeConsentJti = async (jti, expiresAtIso) => {
    jtiConsumes += 1;
    return await consumeConsentJti(jti, expiresAtIso);
  };
  const prepared = await authA.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge("cross-resource-consent-verifier-12345678901234567890"),
    codeChallengeMethod: "S256", state: "resource-a-state", subject: SUBJECT,
  });

  await assert.rejects(
    authB.approve({ consentToken: prepared.consentToken, approved, origin: "https://auth.test" }),
    (error: unknown) => error instanceof OAuthError
      && error.code === "invalid_consent"
      && error.message === "Consent token is invalid or expired"
      && !error.redirect,
  );
  assert.deepEqual({
    codeWrites,
    jtiConsumes,
    successAudits: auditB.events.filter((event) => event.event === "oauth.authorize.approve" && event.status === "success").length,
    redirectHosts: auditB.events.filter((event) => event.event === "oauth.authorize.approve").map((event) => event.redirectHost),
  }, { codeWrites: 0, jtiConsumes: 0, successAudits: 0, redirectHosts: [undefined] });

  const approvedAtA = await authA.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approvedAtA.code);
  assert.equal(new URL(approvedAtA.redirectTo).origin, new URL(REDIRECT).origin);
  assert.deepEqual({ codeWrites, jtiConsumes }, { codeWrites: 1, jtiConsumes: 1 });
  await assert.rejects(
    authA.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant" && !error.redirect,
  );
  await store.close();
}

test("approve rejects a consent token from another resource without consuming it", async () => {
  await assertCrossResourceConsentRejected(true);
});

test("deny rejects a consent token from another resource without using its redirect", async () => {
  await assertCrossResourceConsentRejected(false);
});

test("Deny redirects access_denied without consuming the consent jti (fix #5)", async () => {
  const ctx = setup();
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", state: "deny-state", subject: SUBJECT,
  });
  const denied: ApproveResult = await ctx.auth.approve({ consentToken: prepared.consentToken, approved: false, origin: "https://auth.test" });
  assert.equal(denied.code, undefined);
  const url = new URL(denied.redirectTo);
  assert.equal(`${url.protocol}//${url.host}${url.pathname}`, REDIRECT);
  assert.equal(url.searchParams.get("error"), "access_denied");
  assert.equal(url.searchParams.get("state"), "deny-state");
  // the consent jti was NOT consumed: the same token can still be approved
  const approved = await ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approved.code, "Deny did not consume the consent token");
  await ctx.store.close();
});

test("token issuance: a mint failure audits failure-only, never success-then-failure (always-check #4)", async () => {
  const ctx = setup();
  // A shape-valid-but-invalid signing key: createBridgeConfig accepts it (presence
  // check only), but jose importJWK rejects it at first signAccessToken → mint throws.
  const badConfig = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d", alg: "ES256", kid: "bad" } as JWK,
    signingKeyId: "bad", redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const badToken = new OAuthTokenUseCase({ config: badConfig, store: ctx.store, clock: ctx.clock, audit: ctx.audit });
  let refreshSaves = 0;
  const saveRefreshToken = ctx.store.saveRefreshToken.bind(ctx.store);
  ctx.store.saveRefreshToken = async (input) => {
    refreshSaves += 1;
    await saveRefreshToken(input);
  };
  const verifier = "valid-verifier-123456789012345678901234567890123";
  const { code } = await approveCode(ctx, verifier, "mcp:read"); // real-key auth mints a valid code
  await assert.rejects(
    badToken.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier }),
  );
  const events = ctx.audit.events.filter((e) => e.event === "oauth.token.authorization_code");
  assert.equal(events.length, 1, "exactly ONE audit event (the failure) — no success-then-failure");
  assert.equal(events[0]?.status, "failure");
  assert.equal(refreshSaves, 0, "signing failure occurs before refresh state is saved");
  await ctx.store.close();
});

test("authorization-code response preparation rejects malformed stored scopes before refresh state is saved", async () => {
  const ctx = setup();
  const verifier = "stored-scope-verifier-123456789012345678901234567";
  await ctx.store.saveAuthCode({
    codeHash: sha256Hex("malformed-scope-code"), clientId: "client-1", subject: SUBJECT,
    redirectUri: REDIRECT, resource: ctx.config.resource, scopes: ["not-in-catalog"],
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    expiresAt: "2099-01-01T00:00:00.000Z",
  });
  let saves = 0;
  const saveRefreshToken = ctx.store.saveRefreshToken.bind(ctx.store);
  ctx.store.saveRefreshToken = async (input) => {
    saves += 1;
    await saveRefreshToken(input);
  };
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: "malformed-scope-code",
      redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier,
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  assert.equal(saves, 0);
  await ctx.store.close();
});

test("a throwing custom audit port cannot replace token or revocation outcomes", async () => {
  const ctx = setup();
  const token = new OAuthTokenUseCase({
    config: ctx.config, store: ctx.store, clock: ctx.clock, audit: new ThrowingAudit(),
  });
  const verifier = "throwing-audit-verifier-1234567890123456789012345";
  const { code } = await approveCode(ctx, verifier, "mcp:read");
  const first = await token.exchangeAuthorizationCode({
    grantType: "authorization_code", code, redirectUri: REDIRECT,
    clientId: "client-1", codeVerifier: verifier,
  });
  const refreshed = await token.refresh({
    grantType: "refresh_token", refreshToken: first.refresh_token, clientId: "client-1",
  });
  assert.equal(refreshed.token_type, "Bearer");
  await assert.rejects(
    token.refresh({ grantType: "refresh_token", refreshToken: "invalid", clientId: "client-1" }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
  );
  await token.revoke(refreshed.refresh_token);
  await ctx.store.close();
});

test("prepare rejects a subject in the reserved mcc_ machine namespace (RFC 9700 distinguishability, both directions)", async () => {
  const ctx = setup();
  await assert.rejects(
    ctx.auth.prepare({
      clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
      codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", subject: "mcc_impostor",
    }),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401 && !e.redirect,
  );
  await ctx.store.close();
});

test("verifier classifies the complete machine triad and rejects every partial/conflicting marker", async () => {
  const ctx = setup();
  const isInvalidToken = (e: unknown): boolean => e instanceof OAuthError && e.code === "invalid_token" && e.status === 401;

  const invalid: Array<{ label: string; claims: JWTPayload }> = [
    { label: "reserved subject with foreign client", claims: { sub: "mcc_impostor", client_id: "mcpdc_human1" } },
    { label: "reserved subject and client without gty", claims: { sub: "mcc_alice", client_id: "mcc_alice" } },
    { label: "machine gty on an interactive identity", claims: { sub: "alice", client_id: "client-1", gty: "client_credentials" } },
    { label: "conflicting reserved identities", claims: { sub: "mcc_one", client_id: "mcc_two", gty: "client_credentials" } },
    { label: "unknown gty", claims: { sub: "alice", client_id: "client-1", gty: "future_grant" } },
    { label: "non-string gty", claims: { sub: "alice", client_id: "client-1", gty: 7 } },
    { label: "null gty", claims: { sub: "alice", client_id: "client-1", gty: null } },
  ];
  for (const c of invalid) {
    await assert.rejects(
      verifyAccessToken(await forgeAccessToken(ctx, c.claims), ctx.config, ctx.clock),
      isInvalidToken,
      c.label,
    );
  }

  const machine = await signAccessToken({ subject: "mcc_svc1", clientId: "mcc_svc1", scopes: ["mcp:read"], machine: true }, ctx.config, ctx.clock);
  assert.deepEqual(await verifyAccessToken(machine, ctx.config, ctx.clock), {
    subject: "mcc_svc1", clientId: "mcc_svc1", scopes: ["mcp:read"], credentialKind: "machine",
  });
  await ctx.store.close();
});

test("a stateless mcc_ opaque client completes the authorization-code flow as interactive", async () => {
  const ctx = setup();
  const token = await exchangeCode(
    ctx, "opaque-client-verifier-1234567890123456789012345", "mcp:read", "mcc_opaque_client",
  );
  assert.deepEqual(await verifyAccessToken(token.access_token, ctx.config, ctx.clock), {
    subject: SUBJECT, clientId: "mcc_opaque_client",
    scopes: ["mcp:read"], credentialKind: "interactive",
  });
  await ctx.store.close();
});

test("token issuance rejects a LEGACY stored grant whose subject is in the reserved mcc_ namespace (both paths)", async () => {
  const ctx = setup();
  const verifier = "valid-verifier-123456789012345678901234567890123";
  // A stored auth code minted by a pre-guard version with an mcc_ subject:
  await ctx.store.saveAuthCode({
    codeHash: sha256Hex("legacy-code"), clientId: "client-1", subject: "mcc_legacy",
    redirectUri: REDIRECT, resource: ctx.config.resource, scopes: ["mcp:read"],
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256", expiresAt: "2099-01-01T00:00:00.000Z",
  });
  await assert.rejects(
    ctx.token.exchangeAuthorizationCode({ grantType: "authorization_code", code: "legacy-code", redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  const nowIso = new Date(NOW_MS).toISOString();
  // No side effects: the rejection saved NO refresh token for the legacy subject.
  assert.deepEqual(await ctx.store.findGrantedScopes("mcc_legacy", "client-1", nowIso), []);
  // A legacy refresh record with an mcc_ subject must not mint on rotation either
  // (family id must satisfy parseRefreshFamilyId: >=16 chars of [A-Za-z0-9_-]):
  const legacyFamily = "famlegacy0123456789";
  const rawRefresh = `rt.${legacyFamily}.secret-1234567890`;
  await ctx.store.saveRefreshToken({
    tokenHash: sha256Hex(rawRefresh), familyId: legacyFamily, previousTokenHash: null,
    clientId: "client-1", subject: "mcc_legacy", resource: ctx.config.resource, scopes: ["mcp:read"], expiresAt: "2099-01-01T00:00:00.000Z",
  });
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: rawRefresh, clientId: "client-1" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  // The legacy family was revoked outright (rotation side effects undone at the ledger level)...
  assert.deepEqual(await ctx.store.findGrantedScopes("mcc_legacy", "client-1", nowIso), []);
  // ...and the audit trail shows NO success for the reserved subject — only failures.
  assert.ok(ctx.audit.events.every((e) => !(e.subject === "mcc_legacy" && e.status === "success")), "no success event for a reserved-namespace subject");
  await ctx.store.close();
});

test("empty persisted scopes remain empty instead of expanding to defaults", async () => {
  const ctx = setup();
  const rawCode = "empty-scope-code";
  const verifier = "empty-scope-verifier-0123456789abcdef012345678901";
  await ctx.store.saveAuthCode({
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: SUBJECT,
    redirectUri: REDIRECT, resource: ctx.config.resource, scopes: [],
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    expiresAt: "2099-01-01T00:00:00.000Z",
  });
  const response = await ctx.token.exchangeAuthorizationCode({
    grantType: "authorization_code", code: rawCode, clientId: "client-1",
    redirectUri: REDIRECT, codeVerifier: verifier,
  });
  assert.equal(response.scope, "");
  const stored = await ctx.store.findRefreshToken(sha256Hex(response.refresh_token));
  assert.deepEqual(stored?.scopes, []);
  await ctx.store.close();
});

test("scopeless authorize round-trips empty scopes through consent and access tokens", async () => {
  const ctx = setup({ defaultScopes: [] });
  const verifier = "scopeless-verifier-0123456789abcdef012345678901234";
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    subject: SUBJECT,
  });
  assert.deepEqual(prepared.scopes, []);
  const approved = await ctx.auth.approve({
    consentToken: prepared.consentToken, approved: true, origin: "https://auth.test",
  });
  assert.ok(approved.code);
  const response = await ctx.token.exchangeAuthorizationCode({
    grantType: "authorization_code", code: approved.code, clientId: "client-1",
    redirectUri: REDIRECT, codeVerifier: verifier,
  });
  assert.equal(response.scope, "");
  assert.deepEqual((await verifyAccessToken(response.access_token, ctx.config, ctx.clock)).scopes, []);
  const stored = await ctx.store.findRefreshToken(sha256Hex(response.refresh_token));
  assert.deepEqual(stored?.scopes, []);
  await ctx.store.close();
});

test("approve without an explicit approved:true is a Deny at the CORE layer (§9.3 fail-closed)", async () => {
  const ctx = setup();
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge("verifier-12345678901234567890"), codeChallengeMethod: "S256", state: "absent-state", subject: SUBJECT,
  });
  // approved absent (undefined) must deny — not fall through to code issuance.
  const denied: ApproveResult = await ctx.auth.approve({ consentToken: prepared.consentToken, origin: "https://auth.test" });
  assert.equal(denied.code, undefined);
  assert.equal(new URL(denied.redirectTo).searchParams.get("error"), "access_denied");
  // and the jti was not consumed: an explicit approve still succeeds.
  const approved = await ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approved.code, "absent-field deny did not consume the consent token");
  await ctx.store.close();
});

test("scope accumulation: re-authorize unions with active grants (stored mode, RC c)", async () => {
  const ctx = setup({ dcr: { mode: "stored", store: new InMemoryClientStore() } });
  const reg = await registerClient({ config: ctx.config, clock: ctx.clock, audit: ctx.audit }, { redirectUris: [REDIRECT], applicationType: "web" });
  const clientId = reg.client_id;
  // first authorization: mcp:read
  const v1 = "verifier-one-123456789012345678901234567890123456";
  const t1 = await exchangeCode(ctx, v1, "mcp:read", clientId);
  assert.deepEqual(t1.scope.split(" "), ["mcp:read"]);
  // re-authorize for mcp:write: prior grant (mcp:read) surfaces for the delta
  const v2 = "verifier-two-123456789012345678901234567890123456";
  const prepared: PreparedConsent = await ctx.auth.prepare({
    clientId, redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge(v2), codeChallengeMethod: "S256", scope: "mcp:write", subject: SUBJECT,
  });
  assert.deepEqual(prepared.priorScopes, ["mcp:read"]); // delta display
  const approved = await ctx.auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "https://auth.test" });
  const t2 = await ctx.token.exchangeAuthorizationCode({ grantType: "authorization_code", code: approved.code, redirectUri: REDIRECT, clientId, codeVerifier: v2 });
  assert.deepEqual(t2.scope.split(" ").sort(), ["mcp:read", "mcp:write"]); // union
  await ctx.store.close();
});

test("config fail-closed: https-only, secret length, key shape, catalog, defaults-subset", () => {
  const base = baseInput();
  assert.throws(() => createBridgeConfig({ ...base, issuer: "http://auth.test" }), AuthConfigError); // not https
  assert.throws(() => createBridgeConfig({ ...base, consentSigningSecret: "short" }), AuthConfigError); // <32
  assert.throws(() => createBridgeConfig({ ...base, signingPrivateJwk: { kty: "EC", crv: "P-256" } }), AuthConfigError); // no d/x/y
  assert.throws(() => createBridgeConfig({ ...base, scopeCatalog: [] }), AuthConfigError); // empty catalog
  assert.throws(() => createBridgeConfig({ ...base, defaultScopes: ["mcp:admin"] }), AuthConfigError); // default not in catalog
  assert.throws(() => createBridgeConfig({ ...base, accessTokenTtlSeconds: 0 }), AuthConfigError); // bad ttl
  // dev loopback flag permits http on loopback only
  const dev = createBridgeConfig({ ...base, issuer: "http://localhost", resource: "http://localhost/mcp", dev: { allowInsecureLocalhost: true } });
  assert.equal(originOf(dev.resource), "http://localhost");
  assert.throws(() => createBridgeConfig({ ...base, issuer: "http://api.test", dev: { allowInsecureLocalhost: true } }), AuthConfigError); // non-loopback
});

test("config fail-closed: unknown top-level keys rejected with the key named", () => {
  const base = baseInput();

  // Unknown string key (e.g. a backend credential a caller parked on the input).
  // The error must NAME the key so a JS/cast-TS caller can fix it without guessing.
  let caught: unknown;
  assert.throws(
    () => createBridgeConfig({ ...base, backendApiKey: "TOP_SECRET_BACKEND_CSENTIAL" } as BridgeConfig),
    (e: unknown) => { caught = e; return e instanceof AuthConfigError && /unknown BridgeConfig key "backendApiKey"/.test((e as Error).message); },
  );
  // The message names the key but must NOT echo the secret VALUE — errors get logged.
  assert.equal(
    /TOP_SECRET_BACKEND_CSENTIAL/.test((caught as Error).message), false,
    "the secret value must not be echoed in the AuthConfigError message",
  );

  // A typo'd real key is also caught (the message must name it).
  assert.throws(
    () => createBridgeConfig({ ...base, issuers: base.issuer } as BridgeConfig),
    (e: unknown) => e instanceof AuthConfigError && /unknown BridgeConfig key "issuers"/.test((e as Error).message),
  );

  // A symbol-keyed value would survive the `{ ...input }` spread onto the frozen
  // public object, so it must be rejected too.
  const secret = Symbol("backendApiKey");
  assert.throws(
    () => createBridgeConfig({ ...base, [secret]: "TOP_SECRET" } as BridgeConfig),
    (e: unknown) => e instanceof AuthConfigError && /Symbol\(backendApiKey\)/.test((e as Error).message),
  );
});

test("config fail-closed: a parked secret never reaches the frozen bridge.config", () => {
  // Constructing WITH an extra key throws (previous test); a successfully-built
  // config therefore cannot carry one. Pin the surface against the source of
  // truth: every own key is a real BridgeConfig field, no symbol survived the
  // spread, and the specific secret name is absent. (baseInput omits the optional
  // `dev`, so it is correctly absent here — a key is present iff the caller set it.)
  const config = createBridgeConfig(baseInput());
  assert.equal(Object.isFrozen(config), true);
  assert.equal("backendApiKey" in config, false);
  const unknown = Object.keys(config).filter((k) => !KNOWN_CONFIG_KEYS.has(k));
  assert.deepEqual(unknown, [], "frozen bridge.config carries a key outside BridgeConfig");
  assert.deepEqual(Reflect.ownKeys(config).filter((k) => typeof k === "symbol"), []);
});

test("config TOCTOU: a getter-backed issuer cannot smuggle http past https validation", () => {
  // Pre-fix, createBridgeConfig validated `input.issuer` then built the output via
  // `{...input}` — two reads, so a getter returning https on the validate-read and
  // http on the spread-read smuggled http onto the frozen config. The fix reads
  // each field ONCE; validation and the frozen output share that single read.
  const base = baseInput();
  let reads = 0;
  const input = { ...base } as BridgeConfig;
  Object.defineProperty(input, "issuer", {
    enumerable: true, configurable: true,
    get() { reads += 1; return reads === 1 ? "https://auth.test" : "http://evil.test"; },
  });
  const config = createBridgeConfig(input);
  assert.equal(config.issuer, "https://auth.test", "the validated (first-read) value is what ships");
  assert.equal(reads, 1, "issuer read exactly once");
});

test("config TOCTOU: a Proxy ownKeys trap cannot inject an unknown key via the spread", () => {
  // Pre-fix, the reject-unknown loop's Reflect.ownKeys call hid the extra key, then
  // the `{...input}` spread's second ownKeys call revealed it and copied it onto
  // the frozen config. The fix builds the output from named locals, so ownKeys is
  // called once (the loop) and no extra key can ever reach the output.
  const base = baseInput();
  let ownKeysCalled = 0;
  const input = new Proxy({ ...base }, {
    ownKeys(target) {
      // First call (the reject loop) hides backendApiKey; a later call would reveal it.
      return ownKeysCalled++ === 0 ? Reflect.ownKeys(target) : [...Reflect.ownKeys(target), "backendApiKey"];
    },
    getOwnPropertyDescriptor(target, prop) {
      if (prop === "backendApiKey") return { configurable: true, enumerable: true, writable: true, value: "TOP_SECRET" };
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
    get(target, prop) {
      if (prop === "backendApiKey") return "TOP_SECRET";
      return Reflect.get(target, prop);
    },
  }) as BridgeConfig;
  const config = createBridgeConfig(input);
  assert.equal("backendApiKey" in config, false, "Proxy ownKeys trap cannot inject an unknown key");
  assert.equal((config as unknown as Record<string, unknown>).backendApiKey, undefined);
});

test("oauthErrorBody is RFC 6749 §5.2 shape (top-level error string)", () => {
  // The official MCP SDK reads body.error as a STRING to drive recovery
  // (invalid_grant -> drop token, re-authorize). It must NOT be {error:{code,...}}.
  const body = oauthErrorBody(new OAuthError("invalid_grant", "Authorization code is invalid"));
  assert.deepEqual(body, { error: "invalid_grant", error_description: "Authorization code is invalid" });
  assert.equal(typeof body.error, "string");
});

test("dev.allowInsecureLocalhost emits a loud warning (and only then)", () => {
  const captured: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => { captured.push(args.map(String).join(" ")); };
  try {
    createBridgeConfig({ ...baseInput(), issuer: "http://localhost", resource: "http://localhost/mcp", dev: { allowInsecureLocalhost: true } });
    createBridgeConfig(baseInput()); // https, no flag -> no warning
  } finally {
    console.warn = orig;
  }
  assert.equal(captured.length, 1, "exactly one warning, only for the dev flag");
  assert.match(captured[0]!, /allowInsecureLocalhost/);
});

function baseInput() {
  return {
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: testPrivateJwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" as const },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  };
}

test("requireScope step-up (403 insufficient_scope)", () => {
  assert.doesNotThrow(() => requireScope({
    subject: "s", clientId: "c", scopes: ["mcp:read"], credentialKind: "interactive",
  }, "mcp:read"));
  assert.throws(
    () => requireScope({
      subject: "s", clientId: "c", scopes: ["mcp:read"], credentialKind: "interactive",
    }, "mcp:write"),
    (e: unknown) => e instanceof OAuthError && e.code === "insufficient_scope" && e.status === 403,
  );
});

// --- challenge + metadata builders ---

test("401 challenge carries resource_metadata + scope + error (fix #1)", () => {
  const config = makeConfig();
  const challenge = buildUnauthorizedChallenge(config, { scope: config.scopeCatalog, error: "invalid_token", errorDescription: "Bearer token is invalid" });
  assert.match(challenge, /^Bearer resource_metadata="https:\/\/api\.test\/\.well-known\/oauth-protected-resource"/);
  assert.match(challenge, /scope="mcp:read mcp:write"/);
  assert.match(challenge, /error="invalid_token"/);
  assert.match(challenge, /error_description="Bearer token is invalid"/);
});

test("AS metadata advertises iss flag + public-client auth method + S256", () => {
  const m = authorizationServerMetadata(makeConfig());
  assert.equal(m.authorization_response_iss_parameter_supported, true);
  assert.deepEqual(m.token_endpoint_auth_methods_supported, ["none"]);
  assert.deepEqual(m.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(m.grant_types_supported, ["authorization_code", "refresh_token"]);
});

test("PRM has no jwks_uri; served at root + path-inserted (fix #2)", () => {
  const config = makeConfig();
  const prm = protectedResourceMetadata(config);
  assert.equal(prm.resource, "https://api.test/mcp");
  assert.deepEqual(prm.authorization_servers, ["https://auth.test"]);
  assert.equal("jwks_uri" in prm, false);
  const urls = protectedResourceMetadataUrls(config);
  assert.equal(urls.root, "https://api.test/.well-known/oauth-protected-resource");
  assert.equal(urls.pathInserted, "https://api.test/.well-known/oauth-protected-resource/mcp");
  assert.deepEqual(jwks(config).keys.length, 1);
});

test("registerClient (stateless) mints an RFC 7591 client", async () => {
  const ctx = setup();
  const reg = await registerClient({ config: ctx.config, clock: ctx.clock, audit: ctx.audit }, { redirectUris: [REDIRECT] });
  assert.match(reg.client_id, /^mcpdc_/);
  assert.equal(reg.token_endpoint_auth_method, "none");
  assert.deepEqual(reg.redirect_uris, [REDIRECT]);
  await ctx.store.close();
});

test("revoke is always-200 / no-op on unknown token (RFC 7009)", async () => {
  const ctx = setup();
  await assert.doesNotReject(ctx.token.revoke("rt.unknown.family-aaaaaaaaaaaaaaaa"));
  const initial = await exchangeCode(ctx, "rev-verifier-1234567890123456789012345678901234");
  await assert.doesNotReject(ctx.token.revoke(initial.refresh_token));
  // after revoke, refresh fails
  await assert.rejects(
    ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" }),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
  );
  await ctx.store.close();
});
