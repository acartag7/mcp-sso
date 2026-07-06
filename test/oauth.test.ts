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
import { pkceChallenge, verifyAccessToken } from "../src/crypto.ts";
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

function setup(opts: { redirectAllowlist?: string[]; dcr?: BridgeConfig["dcr"] } = {}): Ctx {
  const clientStore = opts.dcr?.mode === "stored" ? new InMemoryClientStore() : undefined;
  const config = makeConfig({ redirectAllowlist: opts.redirectAllowlist, dcr: opts.dcr ?? (clientStore ? { mode: "stored", store: clientStore } : undefined) });
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
