import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { generateRefreshToken, parseRefreshFamilyId, pkceChallenge, sha256Hex } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const LOOPBACK_REDIRECT = "http://127.0.0.1:49152/callback";
const SUBJECT = "agent@test";

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } advance(ms: number): void { this.ms += ms; } }
class MemoryAudit implements AuditPort { readonly events: AuthAuditEvent[] = []; async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); } }

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function config(redirectAllowlist: string[] = [REDIRECT]): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist, scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

interface Ctx { bridge: Bridge; audit: MemoryAudit; }
function setup(rateLimit?: RateLimitPort, redirectAllowlist?: string[]): Ctx {
  const audit = new MemoryAudit();
  return { bridge: new Bridge({ config: config(redirectAllowlist), store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit, rateLimit }), audit };
}
function req(partial: Partial<NormRequest> & { query?: NormRequest["query"]; body?: unknown }): NormRequest {
  return { query: partial.query ?? {}, body: partial.body, headers: partial.headers ?? {}, ip: partial.ip ?? "1.2.3.4" };
}
function extractConsentToken(html: string): string {
  const m = /name="consent_token" value="([^"]+)"/.exec(html);
  assert.ok(m?.[1], "consent_token not in page");
  return m[1];
}
async function saveRevocableToken(store: MemoryStore): Promise<string> {
  const token = generateRefreshToken();
  const familyId = parseRefreshFamilyId(token);
  assert.ok(familyId, "generated refresh token has a family id");
  await store.saveRefreshToken({
    tokenHash: sha256Hex(token), familyId, previousTokenHash: null,
    clientId: "client", subject: SUBJECT, resource: "https://api.test/mcp", scopes: ["mcp:read"],
    expiresAt: "2026-08-03T12:00:00.000Z",
  });
  return token;
}

test("bridge: full OAuth flow (metadata -> register -> authorize -> approve -> token -> refresh -> revoke)", async () => {
  const ctx = setup();
  const b = ctx.bridge;
  const m = await b.handleAuthorizationServerMetadata();
  assert.equal(m.status, 200);
  assert.equal((m.body as { issuer: string }).issuer, "https://auth.test");
  const k = await b.handleJwks();
  assert.equal((k.body as { keys: unknown[] }).keys.length, 1);

  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const reg = await b.handleRegister(req({ body: { redirect_uris: [REDIRECT] } }));
  assert.equal(reg.status, 201);
  const clientId = (reg.body as { client_id: string }).client_id;

  const page = await b.handleAuthorize(req({ query: { response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read mcp:write", state: "s1" } }), { subject: SUBJECT });
  assert.equal(page.status, 200);
  assert.equal(page.headers["cache-control"], "no-store", "consent JWT response is not cacheable");
  assert.match(String(page.body), /<html/);
  assert.match(String(page.body), /Approve/);
  assert.match(String(page.body), /Deny/); // fix #5: both buttons present

  const consentToken = extractConsentToken(String(page.body));
  const approve = await b.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: "https://auth.test" } }));
  assert.equal(approve.status, 302);
  assert.equal(approve.headers["cache-control"], "no-store", "code-bearing approval redirect is not cacheable");
  const code = new URL(approve.headers.location as string).searchParams.get("code");
  assert.ok(code);

  const token = await b.handleToken(req({ body: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier } }));
  assert.equal(token.status, 200);
  assert.match((token.body as { access_token: string }).access_token, /^[^.]+\.[^.]+\.[^.]+$/);
  const refreshToken = (token.body as { refresh_token: string }).refresh_token;

  const refreshed = await b.handleToken(req({ body: { grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId } }));
  assert.equal(refreshed.status, 200);
  assert.notEqual((refreshed.body as { refresh_token: string }).refresh_token, refreshToken);

  const revoked = await b.handleRevoke(req({ body: { token: refreshToken } }));
  assert.equal(revoked.status, 200);
});

test("bridge: handleRevoke maps an unexpected store throw to the §9.5 500 body (no internals leaked)", async () => {
  // Sibling of the HOTFIX HF.3 guarantee: hono/fastify send handleRevoke's
  // response verbatim (no wrapping catch), so a store outage on the revoke
  // path must produce the same non-leaking §9.5 shape as every other route —
  // never a framework-shaped body echoing the thrown message.
  const secret = "TOP_SECRET_INTERNAL_DETAIL";
  const store = new MemoryStore();
  store.findRefreshToken = async () => { throw new Error(secret); };
  const bridge = new Bridge({ config: config(), store, clock: new FakeClock(NOW_MS), audit: new MemoryAudit() });
  const res = await bridge.handleRevoke(req({ body: { token: "rt_anything" } }));
  assert.equal(res.status, 500);
  const body = res.body as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"]);
  assert.equal(body.error, "internal_error");
  assert.ok(!JSON.stringify(body).includes(secret), "thrown message must not leak into the response");

  // RFC 7009 semantics unchanged by the catch: an unrecognized token is still 200.
  const unrecognized = await setup().bridge.handleRevoke(req({ body: { token: "rt_unknown" } }));
  assert.equal(unrecognized.status, 200);
});

test("bridge: revoke limiter denies before token extraction, use case, store, or audit work", async () => {
  const keys: string[] = [];
  const store = new MemoryStore();
  const originalFind = store.findRefreshToken.bind(store);
  let findCalls = 0;
  store.findRefreshToken = async (hash) => { findCalls += 1; return originalFind(hash); };
  const audit = new MemoryAudit();
  const bridge = new Bridge({
    config: config(), store, clock: new FakeClock(NOW_MS), audit,
    rateLimit: { async check(key) { keys.push(key); return false; } },
  });
  let revokeUseCaseCalls = 0;
  (bridge as unknown as { token: { revoke(token?: string): Promise<void> } }).token = {
    async revoke() { revokeUseCaseCalls += 1; },
  };
  let tokenFieldReads = 0;
  const body = new Proxy({ token: "rt_not_hashed" }, {
    get(target, property, receiver) {
      if (property === "token") tokenFieldReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });

  const response = await bridge.handleRevoke(req({ body, ip: "203.0.113.9" }));
  assert.equal(response.status, 429);
  assert.equal((response.body as { error: string }).error, "temporarily_unavailable");
  assert.deepEqual(keys, ["revoke:203.0.113.9"]);
  assert.equal(tokenFieldReads, 0, "denial precedes token extraction and hashing");
  assert.equal(revokeUseCaseCalls, 0);
  assert.equal(findCalls, 0);
  assert.equal(audit.events.length, 0);
});

test("bridge: revoke limiter uses the shared unknown bucket when no adapter IP is available", async () => {
  const keys: string[] = [];
  const bridge = setup({ async check(key) { keys.push(key); return true; } }).bridge;
  const response = await bridge.handleRevoke({ query: {}, headers: {}, body: {}, ip: undefined });
  assert.equal(response.status, 200);
  assert.deepEqual(keys, ["revoke:unknown"]);
});

test("bridge: admitted unknown and already-revoked tokens retain RFC 7009 HTTP 200", async () => {
  const keys: string[] = [];
  const store = new MemoryStore();
  const token = await saveRevocableToken(store);
  const originalRevoke = store.revokeRefreshTokenFamily.bind(store);
  let revocationCalls = 0;
  store.revokeRefreshTokenFamily = async (familyId, revokedAt) => {
    revocationCalls += 1;
    await originalRevoke(familyId, revokedAt);
  };
  const audit = new MemoryAudit();
  const bridge = new Bridge({
    config: config(), store, clock: new FakeClock(NOW_MS), audit,
    rateLimit: { async check(key) { keys.push(key); return true; } },
  });

  const unknown = await bridge.handleRevoke(req({ body: { token: "rt_unknown" } }));
  const first = await bridge.handleRevoke(req({ body: { token } }));
  const alreadyRevoked = await bridge.handleRevoke(req({ body: { token } }));
  assert.equal(unknown.status, 200);
  assert.equal(first.status, 200);
  assert.equal(alreadyRevoked.status, 200);
  assert.deepEqual(keys, ["revoke:1.2.3.4", "revoke:1.2.3.4", "revoke:1.2.3.4"]);
  assert.equal(revocationCalls, 2);
  assert.equal(audit.events.filter((event) => event.event === "oauth.revoke").length, 3);
});

test("bridge: a throwing revoke limiter fails open and revocation proceeds", async () => {
  const keys: string[] = [];
  const store = new MemoryStore();
  const token = await saveRevocableToken(store);
  const originalRevoke = store.revokeRefreshTokenFamily.bind(store);
  let revocationCalls = 0;
  store.revokeRefreshTokenFamily = async (familyId, revokedAt) => {
    revocationCalls += 1;
    await originalRevoke(familyId, revokedAt);
  };
  const bridge = new Bridge({
    config: config(), store, clock: new FakeClock(NOW_MS), audit: new MemoryAudit(),
    rateLimit: { async check(key) { keys.push(key); throw new Error("redis unavailable"); } },
  });

  const response = await bridge.handleRevoke(req({ body: { token } }));
  assert.equal(response.status, 200);
  assert.deepEqual(keys, ["revoke:1.2.3.4"]);
  assert.equal(revocationCalls, 1);
});

test("bridge: pre-validation redirect error is a direct 400 (no Location)", async () => {
  const ctx = setup();
  const res = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: "https://evil.test/cb", code_challenge: pkceChallenge("v-123456789012345678901234567890123"), code_challenge_method: "S256" } }), { subject: SUBJECT });
  assert.equal(res.status, 400);
  assert.equal(res.redirect, undefined);
  assert.equal(res.headers.location, undefined);
  assert.equal(Object.hasOwn(res.body as object, "iss"), false);
});

test("bridge: post-validation scope error is a 302 to redirect_uri?error=invalid_scope", async () => {
  const ctx = setup();
  const res = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge("v-123456789012345678901234567890123"), code_challenge_method: "S256", scope: "mcp:admin", state: "s" } }), { subject: SUBJECT });
  assert.equal(res.status, 302);
  const u = new URL(res.headers.location as string);
  assert.equal(u.searchParams.get("error"), "invalid_scope");
  assert.equal(u.searchParams.get("iss"), ctx.bridge.config.issuer);
  assert.equal(u.searchParams.get("state"), "s");
});

test("bridge: missing, foreign, or ambiguous normalized approve Origin is a direct 403", async () => {
  const ctx = setup();
  for (const headers of [
    {},
    { origin: "null" },
    { origin: "https://evil.test" },
    { origin: ["https://auth.test"] },
    { origin: ["https://auth.test", "https://evil.test"] },
    { origin: ["https://evil.test", "https://auth.test"] },
    { Origin: "https://auth.test", origin: "https://evil.test" },
    { origin: "https://evil.test", Origin: "https://auth.test" },
  ]) {
    const res = await ctx.bridge.handleApprove(req({ body: { consent_token: "x", approved: "true" }, headers }));
    assert.equal(res.status, 403);
    assert.equal((res.body as { error: string }).error, "invalid_origin");
    assert.equal(res.redirect, undefined);
  }
});

test("bridge: Deny redirects access_denied (fix #5)", async () => {
  const ctx = setup();
  const verifier = "v-12345678901234567890123456789012345678";
  const page = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", state: "deny" } }), { subject: SUBJECT });
  const consentToken = extractConsentToken(String(page.body));
  const res = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "false" }, headers: { origin: "https://auth.test" } }));
  assert.equal(res.status, 302);
  assert.equal(res.headers["cache-control"], undefined, "deny redirect is outside the credential-bearing response rule");
  const u = new URL(res.headers.location as string);
  assert.equal(u.searchParams.get("error"), "access_denied");
  assert.equal(u.searchParams.get("iss"), ctx.bridge.config.issuer);
  assert.equal(u.searchParams.get("state"), "deny");
});

test("bridge: consent CSP permits both loopback callback redirects", async () => {
  for (const approved of ["true", "false"]) {
    const ctx = setup({ async check() { return true; } }, [REDIRECT, "http://127.0.0.1"]);
    const verifier = "v-12345678901234567890123456789012345678";
    const page = await ctx.bridge.handleAuthorize(req({ query: {
      response_type: "code", client_id: "c", redirect_uri: LOOPBACK_REDIRECT,
      code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
      state: approved,
    } }), { subject: SUBJECT });
    assert.equal(page.status, 200);
    assert.match(String(page.body), /<form method="POST" action="\/oauth\/authorize\/approve">/);
    assert.doesNotMatch(String(page.headers["content-security-policy"] ?? ""), /(?:^|;)\s*form-action\b/);

    const res = await ctx.bridge.handleApprove(req({
      body: { consent_token: extractConsentToken(String(page.body)), approved },
      headers: { origin: "https://auth.test" },
    }));
    assert.equal(res.status, 302);
    const callback = new URL(String(res.headers.location));
    assert.equal(callback.origin + callback.pathname, LOOPBACK_REDIRECT);
    assert.equal(callback.searchParams.get("iss"), ctx.bridge.config.issuer);
    if (approved === "true") {
      assert.ok(callback.searchParams.get("code"), "Approve returns a code to the loopback callback");
      assert.equal(callback.searchParams.get("error"), null);
    } else {
      assert.equal(callback.searchParams.get("error"), "access_denied");
      assert.equal(callback.searchParams.get("code"), null, "Deny returns no code");
    }
  }
});

test("bridge: approve WITHOUT an approved field is a Deny, never an auto-approve (§9.3 fail-closed)", async () => {
  const ctx = setup();
  const verifier = "v-12345678901234567890123456789012345678";
  const page = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", state: "noval" } }), { subject: SUBJECT });
  const consentToken = extractConsentToken(String(page.body));
  // No `approved` key at all — and a malformed one — must both deny.
  for (const body of [{ consent_token: consentToken }, { consent_token: consentToken, approved: "yes" }]) {
    const res = await ctx.bridge.handleApprove(req({ body, headers: { origin: "https://auth.test" } }));
    assert.equal(res.status, 302);
    const u = new URL(res.headers.location as string);
    assert.equal(u.searchParams.get("error"), "access_denied");
    assert.equal(u.searchParams.get("iss"), ctx.bridge.config.issuer);
    assert.equal(u.searchParams.get("code"), null, "no code minted");
  }
  // The explicit Approve still works afterwards (deny does not consume the jti).
  const ok = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: "https://auth.test" } }));
  assert.equal(ok.status, 302);
  assert.ok(new URL(ok.headers.location as string).searchParams.get("code"), "explicit approve mints a code");
});

test("bridge: rate-limit (fix #7) returns 429 when the port denies", async () => {
  const deny: RateLimitPort = { async check(): Promise<boolean> { return false; } };
  const ctx = setup(deny);
  const res = await ctx.bridge.handleRegister(req({ body: { redirect_uris: [REDIRECT] } }));
  assert.equal(res.status, 429);
  assert.equal((res.body as { error: string }).error, "temporarily_unavailable");
});

test("bridge: rate-limit fails OPEN when check() throws (§6.7/§17.10 — a Redis outage must not lock out auth)", async () => {
  const boom: RateLimitPort = { async check(): Promise<boolean> { throw new Error("redis down"); } };
  const ctx = setup(boom);
  const res = await ctx.bridge.handleRegister(req({ body: { redirect_uris: [REDIRECT] } }));
  assert.equal(res.status, 201); // not 429 — the bridge guard() caught the throw and allowed
});

test("bridge: authorize rate-limit denial precedes identity verification and audit", async () => {
  const keys: string[] = [];
  const ctx = setup({ async check(key) { keys.push(key); return false; } });
  let verifyCalls = 0;
  await assert.rejects(
    ctx.bridge.resolveIdentity({ async verify() {
      verifyCalls += 1;
      return { ok: true, identity: { subject: SUBJECT } };
    } }, "presented-credential", "1.2.3.4"),
    (error: unknown) => {
      const oauth = error as { code?: unknown; status?: unknown };
      return oauth.code === "temporarily_unavailable" && oauth.status === 429;
    },
  );
  assert.deepEqual(keys, ["authorize:1.2.3.4"]);
  assert.equal(verifyCalls, 0);
  assert.equal(ctx.audit.events.some((event) => event.event === "identity.verify"), false);
});

test("bridge: authorize rate-limit failure stays fail-open", async () => {
  const keys: string[] = [];
  const ctx = setup({ async check(key) { keys.push(key); throw new Error("limiter unavailable"); } });
  let verifyCalls = 0;
  const resolved = await ctx.bridge.resolveIdentity({ async verify() {
    verifyCalls += 1;
    return { ok: true, identity: { subject: SUBJECT } };
  } }, "presented-credential", "1.2.3.4");
  assert.deepEqual(keys, ["authorize:1.2.3.4"]);
  assert.equal(verifyCalls, 1);
  assert.equal(resolved.subject, SUBJECT);
});

test("bridge: the consent page is frame-blocked (threat row 36 — clickjacking would bypass row 17's user judgment)", async () => {
  const ctx = setup();
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const page = await ctx.bridge.handleAuthorize(
    req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "frame" } }),
    { subject: SUBJECT },
  );
  assert.equal(page.status, 200);
  assert.match(String(page.body), /Approve/, "this is the page that carries the Approve control");

  const csp = page.headers["content-security-policy"] ?? "";
  // `frame-ancestors` does NOT fall back to `default-src` under CSP3, so
  // `default-src 'none'` alone does NOT frame-block. Assert the directive
  // itself — asserting only that a CSP exists is what let this ship.
  assert.match(csp, /frame-ancestors 'none'/, "CSP must frame-block the consent page");
  assert.equal(page.headers["referrer-policy"], "same-origin",
    "the approval POST must retain its same-origin Origin without leaking a cross-origin Referer");
  // Belt-and-braces for agents predating CSP3 frame-ancestors support.
  assert.equal(page.headers["x-frame-options"], "DENY");
  // Pre-existing guarantees must survive the header change.
  assert.match(csp, /default-src 'none'/);
  assert.equal(page.headers["x-content-type-options"], "nosniff");
});

test("bridge: the deny/error HTML paths carry the same frame-blocking headers (no unprotected HTML sibling)", async () => {
  const ctx = setup();
  // Any 200 HTML response from the bridge is a potential framing target, not
  // just the happy path — a sibling that renders HTML without these headers
  // would reopen the same click.
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const page = await ctx.bridge.handleAuthorize(
    req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", state: "deny2" } }),
    { subject: SUBJECT },
  );
  const contentType = String(page.headers["content-type"] ?? "");
  if (contentType.includes("text/html")) {
    assert.match(String(page.headers["content-security-policy"] ?? ""), /frame-ancestors 'none'/);
    assert.equal(page.headers["x-frame-options"], "DENY");
  }
});
