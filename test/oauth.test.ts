import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import {
  type BridgeConfig, AuthConfigError, createBridgeConfig, originOf, KNOWN_CONFIG_KEYS,
} from "../src/config.ts";
import { OAuthError, oauthErrorBody } from "../src/errors.ts";
import { assertAllowedRedirectUri, assertRedirectAllowedForClient } from "../src/redirect.ts";
import { pkceChallenge, sha256Hex, signAccessToken, verifyAccessToken } from "../src/crypto.ts";
import { requireScope } from "../src/scopes.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import {
  authorizationServerMetadata, jwks, protectedResourceMetadata, protectedResourceMetadataUrls,
} from "../src/metadata.ts";
import {
  type ApproveResult, type PreparedConsent, OAuthAuthorizationUseCase,
} from "../src/authorize.ts";
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

function makeConfig(opts: { redirectAllowlist?: string[]; scopeCatalog?: string[]; defaultScopes?: string[]; dcr?: BridgeConfig["dcr"]; dev?: boolean } = {}): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
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
  const clock = new FakeClock(NOW_MS);
  const store = new MemoryStore();
  const audit = new MemoryAudit();
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

test("refresh token rotates and replay revokes the family", async () => {
  const ctx = setup();
  const initial = await exchangeCode(ctx, "refresh-verifier-123456789012345678901234567890123");
  const rotated = await ctx.token.refresh({ grantType: "refresh_token", refreshToken: initial.refresh_token, clientId: "client-1" });
  assert.notEqual(rotated.refresh_token, initial.refresh_token);
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
  const verifier = "valid-verifier-123456789012345678901234567890123";
  const { code } = await approveCode(ctx, verifier, "mcp:read"); // real-key auth mints a valid code
  await assert.rejects(
    badToken.exchangeAuthorizationCode({ grantType: "authorization_code", code, redirectUri: REDIRECT, clientId: "client-1", codeVerifier: verifier }),
  );
  const events = ctx.audit.events.filter((e) => e.event === "oauth.token.authorization_code");
  assert.equal(events.length, 1, "exactly ONE audit event (the failure) — no success-then-failure");
  assert.equal(events[0]?.status, "failure");
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

test("verifier accepts an mcc_ sub only with sub==client_id AND the gty marker — pre-upgrade tokens can't masquerade as machine", async () => {
  const ctx = setup();
  const isInvalidToken = (e: unknown): boolean => e instanceof OAuthError && e.code === "invalid_token" && e.status === 401;
  // Pre-guard HUMAN token, mcc_ subject, foreign client_id: rejected.
  const forged = await signAccessToken({ subject: "mcc_impostor", clientId: "mcpdc_human1", scopes: ["mcp:read"] }, ctx.config, ctx.clock);
  await assert.rejects(verifyAccessToken(forged, ctx.config, ctx.clock), isInvalidToken);
  // Stateless-DCR masquerade: the client CHOSE client_id === the mcc_ subject, but no gty marker: rejected.
  const statelessForged = await signAccessToken({ subject: "mcc_alice", clientId: "mcc_alice", scopes: ["mcp:read"] }, ctx.config, ctx.clock);
  await assert.rejects(verifyAccessToken(statelessForged, ctx.config, ctx.clock), isInvalidToken);
  // A legitimate machine token (sub === client_id + the gty marker only the machine grant mints) verifies.
  const machine = await signAccessToken({ subject: "mcc_svc1", clientId: "mcc_svc1", scopes: ["mcp:read"], machine: true }, ctx.config, ctx.clock);
  assert.equal((await verifyAccessToken(machine, ctx.config, ctx.clock)).subject, "mcc_svc1");
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
    clientId: "client-1", subject: "mcc_legacy", scopes: ["mcp:read"], expiresAt: "2099-01-01T00:00:00.000Z",
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

test("config fail-closed: every redirectAllowlist entry validated at boot (§5/§10.1)", () => {
  const base = baseInput();
  const message = (input: Partial<BridgeConfig>): string => {
    try { createBridgeConfig({ ...base, ...input } as BridgeConfig); } catch (e) { return (e as Error).message; }
    return "";
  };

  // "*" is refused at boot rather than silently discarded by the matcher. This is
  // the issue-#104 case found in the wild: a production manifest carried
  // OAUTH_REDIRECT_ALLOWLIST="*" and nothing at boot or at request time said so.
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["*"] }), AuthConfigError);

  // Unanchored prefixes — refused for the same reason "*" is.
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["https://foo.*"] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["https://foo.test/cb*"] }), AuthConfigError);

  // The message must NAME the offending entry, so a deployer with several
  // origins configured does not have to bisect to find the bad one.
  const named = message({ redirectAllowlist: ["https://ok.test", "https://bad.*"] });
  assert.match(named, /https:\/\/bad\.\*/);
  assert.equal(/ok\.test/.test(named), false, "the message must name only the offending entry");

  // Unparseable, wrong-scheme, userinfo, fragment.
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["not a url"] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["javascript:alert(1)"] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["data:text/html,x"] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["https://u:p@ok.test"] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: ["https://ok.test/cb#frag"] }), AuthConfigError);

  // Wrong TYPE fails closed at boot. Before this rule a non-array reached the
  // matcher and threw a raw TypeError ("allowlist is not iterable") at REQUEST
  // time — a 500 on a live authorize instead of a boot failure.
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: "https://ok.test" as unknown as string[] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: undefined as unknown as string[] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, redirectAllowlist: [123 as unknown as string] }), AuthConfigError);

  // A path-bearing entry the matcher compares by exact string equality must be
  // CANONICAL, or it matches nothing and the deployer's configured callback
  // fails at authorization instead of at boot — the same silent-config failure
  // this issue exists to end. Each of these was accepted at boot and matched
  // nothing before the check.
  for (const nonCanonical of [
    "HTTPS://client.test/callback",
    "https://client.test:443/callback",
    "  https://client.test/callback  ",
    "https://client.test/a/../callback",
  ]) {
    assert.throws(
      () => createBridgeConfig({ ...base, redirectAllowlist: [nonCanonical] }),
      AuthConfigError,
      `expected a non-canonical entry to be rejected: ${nonCanonical}`,
    );
  }
  // The message shows the canonical form to paste back.
  assert.match(message({ redirectAllowlist: ["https://client.test:443/callback"] }), /https:\/\/client\.test\/callback/);

  // Origin-only entries have their own matcher branch (compared as
  // scheme://host, not by string equality), so they are NOT required to carry
  // the trailing slash `new URL` would render — and they still match.
  const originOnly = createBridgeConfig({ ...base, redirectAllowlist: ["https://a.test"] });
  assert.equal(assertAllowedRedirectUri("https://a.test/deep/cb", originOnly.redirectAllowlist), "https://a.test/deep/cb");

  // Empty stays VALID — the built-in §10 defaults are the common case — and the
  // defaults must still apply.
  const empty = createBridgeConfig({ ...base, redirectAllowlist: [] });
  assert.deepEqual(empty.redirectAllowlist, []);
  assert.equal(assertAllowedRedirectUri("https://claude.ai/cb", empty.redirectAllowlist), "https://claude.ai/cb");

  // Legitimate entries still pass, and still match at request time.
  const ok = createBridgeConfig({ ...base, redirectAllowlist: ["https://ok.test/cb", "http://localhost"] });
  assert.equal(assertAllowedRedirectUri("https://ok.test/cb", ok.redirectAllowlist), "https://ok.test/cb");
  assert.equal(assertAllowedRedirectUri("http://localhost:57312/cb", ok.redirectAllowlist), "http://localhost:57312/cb");
});

test("config fail-closed: the published redirectAllowlist is a frozen snapshot, not the caller's array", () => {
  const base = baseInput();
  // The boot check is only load-bearing if the array it validated is the array
  // read at request time. Publishing the caller's live array by reference would
  // let a validated allowlist grow an unvalidated entry after boot.
  const caller = ["https://ok.test/cb"];
  const config = createBridgeConfig({ ...base, redirectAllowlist: caller });
  assert.notEqual(config.redirectAllowlist, caller, "must not publish the caller's array by reference");
  assert.equal(Object.isFrozen(config.redirectAllowlist), true);

  caller.push("https://evil.test/cb");
  assert.deepEqual(config.redirectAllowlist, ["https://ok.test/cb"], "a post-boot push must not reach the config");
  assert.throws(
    () => assertAllowedRedirectUri("https://evil.test/cb", config.redirectAllowlist),
    (e: unknown) => e instanceof OAuthError && e.code === "invalid_redirect_uri",
  );
});

test("config publication: nested blocks are frozen snapshots, not the caller's objects (§5)", () => {
  const base = baseInput();
  // `Object.freeze` is SHALLOW. Publishing the caller's own nested blocks would
  // leave every validated security setting mutable after boot — and these are
  // read PER REQUEST, not captured at boot. Issue #100.
  const clientStore = new InMemoryClientStore();
  const evilStore = new InMemoryClientStore();
  const dcr: BridgeConfig["dcr"] = { mode: "stored", store: clientStore };
  const clientCredentials = { enabled: false };
  const config = createBridgeConfig({ ...base, dcr, clientCredentials });

  assert.notEqual(config.dcr, dcr, "dcr must not be published by reference");
  assert.equal(Object.isFrozen(config.dcr), true);
  assert.notEqual(config.clientCredentials, clientCredentials, "clientCredentials must not be published by reference");
  assert.equal(Object.isFrozen(config.clientCredentials), true);

  // Swapping the store post-boot would redirect client lookups and save() to an
  // attacker-chosen store — an authorization-decision input.
  (dcr as { store: ClientStore }).store = evilStore;
  assert.equal(config.dcr.mode === "stored" ? config.dcr.store : null, clientStore, "dcr.store must still be the boot-approved store");

  // Flipping the mode would change which registration path runs.
  (dcr as { mode: string }).mode = "stateless";
  assert.equal(config.dcr.mode, "stored");

  // Flipping `enabled` would switch on a deliberately disabled grant with no
  // restart, and change what AS metadata advertises.
  clientCredentials.enabled = true;
  assert.equal(config.clientCredentials?.enabled, false);

  // `store` is deliberately carried BY REFERENCE — it is a live port object with
  // methods. The snapshot closes swap-the-store, not the port itself.
  assert.equal(config.dcr.mode === "stored" ? config.dcr.store : null, clientStore);
});

test("config publication TOCTOU: an accessor-backed dcr/clientCredentials cannot publish a value boot never validated", () => {
  const base = baseInput();
  // The snapshot must be built from the values validation ALREADY read, never by
  // re-reading the caller's block. A getter returning one value at validation and
  // another at snapshot time would otherwise publish what boot never approved —
  // the same validate-then-copy TOCTOU the snapshot exists to close.
  const approved = new InMemoryClientStore();
  const attacker = new InMemoryClientStore();
  let storeReads = 0;
  const dcr = {
    mode: "stored" as const,
    get store(): ClientStore { storeReads++; return storeReads <= 1 ? approved : attacker; },
  };
  const config = createBridgeConfig({ ...base, dcr });
  assert.equal(
    config.dcr.mode === "stored" ? config.dcr.store : null, approved,
    "must publish the store validation saw, not a later getter result",
  );

  // Same rule for the grant flag: a getter reading false at validation and true
  // at snapshot time would pass the disabled-grant boot checks while publishing
  // the grant as ENABLED — AS metadata and /oauth/token would then expose a
  // grant boot validated as off.
  let enabledReads = 0;
  const clientCredentials = {
    get enabled(): boolean { enabledReads++; return enabledReads <= 1 ? false : true; },
  };
  const cfg2 = createBridgeConfig({
    ...base, dcr: { mode: "stored", store: approved }, clientCredentials,
  });
  assert.equal(cfg2.clientCredentials?.enabled, false, "must publish the boolean validation approved");
});

test("config publication: the signing JWK is a frozen snapshot (§5) — the most sensitive nested value", () => {
  const base = baseInput();
  // signingPrivateJwk was published BY REFERENCE while signKey()/publicJwk()
  // read it per use and crypto-keys.ts memoizes the imported key in a WeakMap
  // keyed by this object (its header called that a "stable (frozen)"
  // reference). A mutation before first import swapped the signing material; a
  // mutation after it desynchronized the cached signer from the published JWKS.
  const caller = { ...(base.signingPrivateJwk as Record<string, unknown>) } as typeof base.signingPrivateJwk;
  const config = createBridgeConfig({ ...base, signingPrivateJwk: caller });
  assert.notEqual(config.signingPrivateJwk, caller, "must not publish the caller's JWK by reference");
  assert.equal(Object.isFrozen(config.signingPrivateJwk), true);

  const originalKid = config.signingPrivateJwk.kid;
  (caller as Record<string, unknown>).kid = "SWAPPED";
  (caller as Record<string, unknown>).d = "TAMPERED";
  assert.equal(config.signingPrivateJwk.kid, originalKid, "a post-boot mutation must not reach the config");
  assert.notEqual(config.signingPrivateJwk.d, "TAMPERED");

  // Unknown members are dropped, not published (fail-closed, like KNOWN_CONFIG_KEYS).
  const withExtra = createBridgeConfig({
    ...base,
    signingPrivateJwk: { ...(base.signingPrivateJwk as Record<string, unknown>), backdoor: "x" } as typeof base.signingPrivateJwk,
  });
  assert.equal((withExtra.signingPrivateJwk as Record<string, unknown>).backdoor, undefined);

  // Array-valued members (key_ops) are CLONED and deep-frozen, never shared:
  // a shared array is the same by-reference hole one level down — mutating the
  // caller's array post-boot must not reach the published JWK.
  const callerOps = ["sign"];
  const withOps = createBridgeConfig({
    ...base,
    signingPrivateJwk: { ...(base.signingPrivateJwk as Record<string, unknown>), key_ops: callerOps } as typeof base.signingPrivateJwk,
  });
  const publishedOps = (withOps.signingPrivateJwk as Record<string, unknown>).key_ops as string[];
  assert.notEqual(publishedOps, callerOps, "key_ops must not be shared with the caller's array");
  assert.equal(Object.isFrozen(publishedOps), true, "nested members must be frozen too, not just the top level");
  callerOps.push("verify");
  assert.deepEqual(publishedOps, ["sign"], "a post-boot push into the caller's key_ops must not reach the config");
});

test("config publication: array fields are validated as string[] and frozen (§5)", () => {
  const base = baseInput();

  // A bare string is NOT a one-element list. `allowedOrigins` is consumed with
  // `.includes()`, which on a string is SUBSTRING matching — so a string
  // "https://auth.test" would admit the Origin "auth.test" (and "ttps://auth.tes"),
  // widening the consent-approve CSRF gate from a harmless-looking config typo.
  assert.throws(() => createBridgeConfig({ ...base, allowedOrigins: "https://auth.test" as unknown as string[] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, scopeCatalog: "mcp:read" as unknown as string[] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, defaultScopes: "mcp:read" as unknown as string[] }), AuthConfigError);
  // Non-string entries fail closed too.
  assert.throws(() => createBridgeConfig({ ...base, allowedOrigins: [123 as unknown as string] }), AuthConfigError);
  assert.throws(() => createBridgeConfig({ ...base, scopeCatalog: [{} as unknown as string] }), AuthConfigError);
  // `allowedOrigins: undefined` previously published `[]` silently.
  assert.throws(() => createBridgeConfig({ ...base, allowedOrigins: undefined as unknown as string[] }), AuthConfigError);

  // Each published array is a frozen snapshot: a post-boot push to the caller's
  // array must not widen what requests read.
  const scopeCatalog = ["mcp:read", "mcp:write"];
  const allowedOrigins = ["https://auth.test"];
  const config = createBridgeConfig({ ...base, scopeCatalog, defaultScopes: ["mcp:read"], allowedOrigins });
  assert.equal(Object.isFrozen(config.scopeCatalog), true);
  assert.equal(Object.isFrozen(config.allowedOrigins), true);

  scopeCatalog.push("mcp:admin");
  allowedOrigins.push("https://evil.test");
  assert.deepEqual(config.scopeCatalog, ["mcp:read", "mcp:write"], "a post-boot push must not widen the scope catalog");
  assert.deepEqual(config.allowedOrigins, ["https://auth.test"], "a post-boot push must not widen the Origin gate");
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
  assert.doesNotThrow(() => requireScope({ subject: "s", clientId: "c", scopes: ["mcp:read"] }, "mcp:read"));
  assert.throws(
    () => requireScope({ subject: "s", clientId: "c", scopes: ["mcp:read"] }, "mcp:write"),
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

test("registerClient stores the NORMALIZED redirect_uri, so a stored web client can authorize with it", async () => {
  // Sibling of the canonical-allowlist rule: §10.2 compares a presented
  // redirect_uri against the REGISTERED ones by exact string equality, against
  // an already-normalized href. Storing the raw input meant a client registering
  // a non-canonical (but allowlist-passing) URI could afterwards authorize with
  // NOTHING — not even the exact string it registered — and the breakage
  // surfaced at authorize rather than at registration.
  const ctx = setup({ dcr: { mode: "stored", store: new InMemoryClientStore() } });
  const stored = ctx.config.dcr.mode === "stored" ? ctx.config.dcr.store : null;
  assert.ok(stored, "stored-mode config must carry a ClientStore");

  const reg = await registerClient(
    { config: ctx.config, clock: ctx.clock, audit: ctx.audit },
    { redirectUris: ["https://client.test:443/callback"], applicationType: "web" },
  );
  const record = await stored.find(reg.client_id);
  assert.ok(record);
  assert.deepEqual(record.redirectUris, ["https://client.test/callback"], "must persist the normalized form");

  // The client can now actually use it — both the canonical form and the
  // equivalent it registered resolve to the same normalized URI.
  assert.equal(assertRedirectAllowedForClient("https://client.test/callback", record), "https://client.test/callback");
  assert.equal(assertRedirectAllowedForClient("https://client.test:443/callback", record), "https://client.test/callback");
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
