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
import { pkceChallenge } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } advance(ms: number): void { this.ms += ms; } }
class MemoryAudit implements AuditPort { readonly events: AuthAuditEvent[] = []; async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); } }

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function config(): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

interface Ctx { bridge: Bridge; }
function setup(rateLimit?: RateLimitPort): Ctx {
  return { bridge: new Bridge({ config: config(), store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit: new MemoryAudit(), rateLimit }) };
}
function req(partial: Partial<NormRequest> & { query?: NormRequest["query"]; body?: unknown }): NormRequest {
  return { query: partial.query ?? {}, body: partial.body, headers: partial.headers ?? {}, ip: partial.ip ?? "1.2.3.4" };
}
function extractConsentToken(html: string): string {
  const m = /name="consent_token" value="([^"]+)"/.exec(html);
  assert.ok(m?.[1], "consent_token not in page");
  return m[1];
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
  assert.match(String(page.body), /<html/);
  assert.match(String(page.body), /Approve/);
  assert.match(String(page.body), /Deny/); // fix #5: both buttons present

  const consentToken = extractConsentToken(String(page.body));
  const approve = await b.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: "https://auth.test" } }));
  assert.equal(approve.status, 302);
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

test("bridge: pre-validation redirect error is a direct 400 (no Location)", async () => {
  const ctx = setup();
  const res = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: "https://evil.test/cb", code_challenge: pkceChallenge("v-123456789012345678901234567890123"), code_challenge_method: "S256" } }), { subject: SUBJECT });
  assert.equal(res.status, 400);
  assert.equal(res.redirect, undefined);
});

test("bridge: every duplicate-sensitive authorization parameter is rejected before redirect resolution", async () => {
  const duplicateSensitive = [
    "response_type", "client_id", "redirect_uri", "code_challenge",
    "code_challenge_method", "resource", "scope", "state",
  ] as const;
  const base = {
    response_type: "code",
    client_id: "c",
    redirect_uri: REDIRECT,
    code_challenge: pkceChallenge("v-123456789012345678901234567890123"),
    code_challenge_method: "S256",
    resource: "https://api.test/mcp",
    scope: "mcp:read",
    state: "client-state",
  };
  for (const key of duplicateSensitive) {
    const query: NormRequest["query"] = { ...base, [key]: [base[key], "duplicate"] };
    const res = await setup().bridge.handleAuthorize(req({ query }), { subject: SUBJECT });
    assert.equal(res.status, 400, `${key} duplicate was not rejected directly`);
    assert.equal(res.redirect, undefined, `${key} duplicate reached redirect resolution`);
    assert.equal((res.body as { error: string }).error, "invalid_request");
  }
});

test("bridge: post-validation scope error is a 302 to redirect_uri?error=invalid_scope", async () => {
  const ctx = setup();
  const res = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge("v-123456789012345678901234567890123"), code_challenge_method: "S256", scope: "mcp:admin", state: "s" } }), { subject: SUBJECT });
  assert.equal(res.status, 302);
  const u = new URL(res.headers.location as string);
  assert.equal(u.searchParams.get("error"), "invalid_scope");
  assert.equal(u.searchParams.get("state"), "s");
});

test("bridge: cross-origin approve is a direct 403 (no redirect)", async () => {
  const ctx = setup();
  const res = await ctx.bridge.handleApprove(req({ body: { consent_token: "x", approved: "true" }, headers: { origin: "https://evil.test" } }));
  assert.equal(res.status, 403);
  assert.equal(res.redirect, undefined);
});

test("bridge: Deny redirects access_denied (fix #5)", async () => {
  const ctx = setup();
  const verifier = "v-12345678901234567890123456789012345678";
  const page = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: "c", redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", state: "deny" } }), { subject: SUBJECT });
  const consentToken = extractConsentToken(String(page.body));
  const res = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "false" }, headers: { origin: "https://auth.test" } }));
  assert.equal(res.status, 302);
  const u = new URL(res.headers.location as string);
  assert.equal(u.searchParams.get("error"), "access_denied");
  assert.equal(u.searchParams.get("state"), "deny");
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

test("bridge: malformed registration members reject instead of being filtered", async () => {
  const ctx = setup();
  const bodies: unknown[] = [
    { redirect_uris: [REDIRECT, 7] },
    { redirect_uris: [REDIRECT], application_type: 7 },
    { redirect_uris: [REDIRECT], token_endpoint_auth_method: 7 },
    { redirect_uris: [REDIRECT], grant_types: ["authorization_code", 7] },
  ];
  for (const body of bodies) {
    const response = await ctx.bridge.handleRegister(req({ body }));
    assert.equal(response.status, 400);
  }
});
