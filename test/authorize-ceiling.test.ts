// Authorization scope-ceiling — contracts §17.4 core plumbing (S2a). A fake
// IdentityPort supplies allowedScopes; these tests prove the ceiling narrows at
// prepare, is re-intersected at approve against the verified consent token (so
// prior grants can't resurrect a ceiling-stripped scope), defaultScopes pass
// through the same intersection, an empty intersection is access_denied over the
// redirect channel, identities without a ceiling behave exactly as before, and
// the identity.verify audit event is emitted on success and failure.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { decodeJwt } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";
const ID_GOOD = "id-good";
const IP = "203.0.113.7";

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } }
class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); }
  identity(): AuthAuditEvent[] { return this.events.filter((e) => e.event === "identity.verify"); }
}
class InMemoryClientStore implements ClientStore {
  private readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function config(store: ClientStore, defaultScopes: string[] = ["mcp:read"]): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write", "mcp:admin"], defaultScopes,
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stored", store },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

interface Ctx { bridge: Bridge; audit: MemoryAudit; }
function setup(defaultScopes: string[] = ["mcp:read"]): Ctx {
  const audit = new MemoryAudit();
  const clientStore = new InMemoryClientStore();
  const bridge = new Bridge({ config: config(clientStore, defaultScopes), store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit });
  return { bridge, audit };
}

function req(partial: Partial<NormRequest> & { query?: NormRequest["query"]; body?: unknown }): NormRequest {
  return { query: partial.query ?? {}, body: partial.body, headers: partial.headers ?? {}, ip: partial.ip ?? IP };
}

/** IdentityPort stub: resolves SUBJECT with an optional allowedScopes ceiling for ID_GOOD. */
function fakeIdentity(allowedScopes?: string[]): IdentityPort {
  return { async verify(input: unknown) {
    return input === ID_GOOD ? { ok: true, identity: { subject: SUBJECT, allowedScopes } } : { ok: false, reason: "bad_token" };
  } };
}

function authorizeQuery(clientId: string, scope: string | undefined, verifier: string): NormRequest["query"] {
  const q: Record<string, string> = { response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256" };
  if (scope) q.scope = scope;
  return q;
}

function extractConsentToken(html: string): string | undefined { return /name="consent_token" value="([^"]+)"/.exec(html)?.[1]; }

/** resolve → authorize. Returns the authorize NormResponse (200 consent page, or 302 error redirect). */
async function resolveAndAuthorize(ctx: Ctx, identity: IdentityPort, clientId: string, scope: string | undefined, verifier: string): Promise<NormResponse> {
  const resolved = await ctx.bridge.resolveIdentity(identity, ID_GOOD, IP);
  return ctx.bridge.handleAuthorize(req({ query: authorizeQuery(clientId, scope, verifier) }), resolved);
}

/** resolve → authorize → approve → token exchange. Asserts each step succeeds and returns the granted scopes (sorted). */
async function grantScopes(ctx: Ctx, identity: IdentityPort, clientId: string, scope: string | undefined, verifier: string): Promise<string[]> {
  const page = await resolveAndAuthorize(ctx, identity, clientId, scope, verifier);
  assert.equal(page.status, 200, `authorize should render the consent page, got ${JSON.stringify(page)}`);
  const consentToken = extractConsentToken(String(page.body));
  assert.ok(consentToken, "consent token in page");
  const approve = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: "https://auth.test" } }));
  assert.equal(approve.status, 302);
  const code = new URL(approve.headers.location as string).searchParams.get("code");
  assert.ok(code, "code in approve redirect");
  const token = await ctx.bridge.handleToken(req({ body: { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier } }));
  assert.equal(token.status, 200, `token exchange failed: ${JSON.stringify(token.body)}`);
  return ((token.body as { scope: string }).scope ?? "").split(/\s+/).filter(Boolean).sort();
}

async function register(ctx: Ctx): Promise<string> {
  const reg = await ctx.bridge.handleRegister(req({ body: { redirect_uris: [REDIRECT], application_type: "web" } }));
  assert.equal(reg.status, 201);
  return (reg.body as { client_id: string }).client_id;
}

test("ceiling narrows requested scopes: token grants only the intersection", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // ceiling {mcp:read}; client requests mcp:read + mcp:write → only mcp:read granted.
  const scopes = await grantScopes(ctx, fakeIdentity(["mcp:read"]), clientId, "mcp:read mcp:write", "v-ceiling-narrow-0123456789abcdef0123456789");
  assert.deepEqual(scopes, ["mcp:read"]);
  // identity.verify was emitted once, success, with subject + ip.
  const id = ctx.audit.identity();
  assert.equal(id.length, 1);
  const ev = id[0]!;
  assert.equal(ev.status, "success");
  assert.equal(ev.subject, SUBJECT);
  assert.equal(ev.ip, IP);
});

test("ceiling narrows default scopes (defaultScopes pass through the intersection)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // no scope requested → defaults {mcp:read}; ceiling {mcp:read,mcp:write} → mcp:read.
  const scopes = await grantScopes(ctx, fakeIdentity(["mcp:read", "mcp:write"]), clientId, undefined, "v-default-through-0123456789abcdef01234567890");
  assert.deepEqual(scopes, ["mcp:read"]);
});

test("empty intersection (default outside ceiling) ⇒ access_denied over the redirect channel", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // no scope requested → defaults {mcp:read}; ceiling {mcp:write} → empty → access_denied.
  const page = await resolveAndAuthorize(ctx, fakeIdentity(["mcp:write"]), clientId, undefined, "v-empty-default-0123456789abcdef01234567890");
  assert.equal(page.status, 302);
  const u = new URL(page.headers.location as string);
  assert.equal(`${u.protocol}//${u.host}${u.pathname}`, REDIRECT);
  assert.equal(u.searchParams.get("error"), "access_denied");
  // identity resolved fine — the failure is the ceiling, not identity.
  const id = ctx.audit.identity();
  assert.equal(id.length, 1);
  assert.equal(id[0]!.status, "success");
});

test("empty intersection (explicit request outside ceiling) ⇒ access_denied redirect", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // ceiling {mcp:read}; client requests mcp:write → empty → access_denied.
  const page = await resolveAndAuthorize(ctx, fakeIdentity(["mcp:read"]), clientId, "mcp:write", "v-empty-request-0123456789abcdef0123456789012");
  assert.equal(page.status, 302);
  const u = new URL(page.headers.location as string);
  assert.equal(u.searchParams.get("error"), "access_denied");
});

test("prior grants cannot resurrect a ceiling-stripped scope (stored mode, §17.4 row 22)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // #1: ceiling {mcp:read,mcp:admin}; grant mcp:admin → active refresh token carries mcp:admin.
  const first = await grantScopes(ctx, fakeIdentity(["mcp:read", "mcp:admin"]), clientId, "mcp:admin", "v-resurrect-one-0123456789abcdef0123456789012");
  assert.deepEqual(first, ["mcp:admin"]);
  // #2: ceiling shrinks to {mcp:read}; request mcp:read. prior grant (mcp:admin) must NOT survive.
  const second = await grantScopes(ctx, fakeIdentity(["mcp:read"]), clientId, "mcp:read", "v-resurrect-two-0123456789abcdef0123456789012");
  assert.deepEqual(second, ["mcp:read"]);
  assert.ok(!second.includes("mcp:admin"), "a since-removed-group scope must not be resurrected by the prior grant");
});

test("identity without allowedScopes grants the full requested set (old behavior)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  const scopes = await grantScopes(ctx, fakeIdentity(undefined), clientId, "mcp:read mcp:write", "v-no-ceiling-0123456789abcdef0123456789012345");
  assert.deepEqual(scopes, ["mcp:read", "mcp:write"]);
});

test("identity.verify: failure is recorded with the port's reason and resolve throws access_denied 401", async () => {
  const ctx = setup();
  const port: IdentityPort = { async verify() { return { ok: false, reason: "entra_no_groups" }; } };
  await assert.rejects(
    ctx.bridge.resolveIdentity(port, ID_GOOD, IP),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401,
  );
  const id = ctx.audit.identity();
  assert.equal(id.length, 1);
  const ev = id[0]!;
  assert.equal(ev.status, "failure");
  assert.equal(ev.reason, "entra_no_groups"); // port reason carried (Entra-specific reasons land in S2b)
  assert.equal(ev.subject, undefined);
  assert.equal(ev.ip, IP, "failure events carry the source IP (forensic — §17.7)");
});

test("identity.verify: a thrown non-OAuth error records internal_error and propagates raw (HF.3)", async () => {
  const ctx = setup();
  const port: IdentityPort = { async verify() { throw new Error("boom"); } };
  await assert.rejects(ctx.bridge.resolveIdentity(port, ID_GOOD, IP), (e: unknown) => e instanceof Error && e.message === "boom");
  const id = ctx.audit.identity();
  assert.equal(id.length, 1);
  const ev = id[0]!;
  assert.equal(ev.status, "failure");
  assert.equal(ev.reason, "internal_error");
  assert.equal(ev.ip, IP, "failure events carry the source IP (forensic — §17.7)");
});

test("a present-but-malformed allowedScopes ceiling fails CLOSED (never widens — threat-model row 22)", async () => {
  const ctx = setup();
  // A port bug returns a string instead of an array. Treating that as "no
  // ceiling" would grant the FULL requested set (fail-open). It must deny.
  const port: IdentityPort = { async verify() { return { ok: true, identity: { subject: SUBJECT, allowedScopes: "mcp:read" as unknown as string[] } }; } };
  await assert.rejects(
    ctx.bridge.resolveIdentity(port, ID_GOOD, IP),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401,
  );
  const ev = ctx.audit.identity()[0]!;
  assert.equal(ev.status, "failure");
  assert.equal(ev.reason, "malformed_allowed_scopes");
  assert.equal(ev.ip, IP);
});

test("prepare fails closed on a malformed ceiling at the CORE boundary (direct/exported use-case — Codex P2)", async () => {
  // OAuthAuthorizationUseCase is exported, so a consumer can call prepare()
  // directly (or via a custom adapter that bypasses Bridge.resolveIdentity).
  // The fail-closed guarantee must hold there too — a malformed ceiling can't
  // widen to "no ceiling" (full requested/default scopes).
  const ctx = setup();
  const auth = new OAuthAuthorizationUseCase({ config: ctx.bridge.config, store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit: new MemoryAudit() });
  await assert.rejects(
    auth.prepare({ clientId: "c", redirectUri: REDIRECT, responseType: "code", codeChallenge: pkceChallenge("v-core-boundary-0123456789abcdef01234567"), codeChallengeMethod: "S256", subject: SUBJECT, allowedScopes: "mcp:read" as unknown as string[] }),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401,
  );
});

test("an empty-array ceiling denies all scopes (entitled to nothing ⇒ access_denied redirect)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  const page = await resolveAndAuthorize(ctx, fakeIdentity([]), clientId, "mcp:read", "v-empty-array-0123456789abcdef012345678901234");
  assert.equal(page.status, 302);
  assert.equal(new URL(page.headers.location as string).searchParams.get("error"), "access_denied");
});

test("no ceiling + empty defaultScopes + scopeless authorize is unchanged v0.1 behavior (200, not access_denied)", async () => {
  const ctx = setup([]);
  const clientId = await register(ctx);
  // defaultScopes:[] is a valid config; scopeless authorize is legitimate. With
  // NO ceiling this MUST stay v0.1's 200 (empty-scope consent), not access_denied.
  const page = await resolveAndAuthorize(ctx, fakeIdentity(undefined), clientId, undefined, "v-empty-defaults-0123456789abcdef012345678901");
  assert.equal(page.status, 200, "empty requested set with no ceiling renders the consent page (v0.1), not access_denied");
  assert.ok(extractConsentToken(String(page.body)), "consent page rendered");
});

test("the consent JWT carries the ceiling as an allowed_scopes claim (§17.4 item 5)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  const withCeiling = await resolveAndAuthorize(ctx, fakeIdentity(["mcp:read"]), clientId, "mcp:read mcp:write", "v-jwt-claim-one-0123456789abcdef0123456");
  assert.equal(decodeJwt(extractConsentToken(String(withCeiling.body))!).allowed_scopes, "mcp:read", "ceiling carried in the consent JWT");
  // no ceiling ⇒ the claim is absent (not an empty string)
  const noCeiling = await resolveAndAuthorize(ctx, fakeIdentity(undefined), clientId, "mcp:read", "v-jwt-claim-two-0123456789abcdef01234567");
  assert.equal(decodeJwt(extractConsentToken(String(noCeiling.body))!).allowed_scopes, undefined, "no ceiling ⇒ no allowed_scopes claim");
});

test("the minted access JWT carries the intersected scope claim (the RS-enforced set)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // ceiling {mcp:read}; request all three → the ACCESS JWT (what verifyAccessToken
  // enforces) must carry only mcp:read, not the requested set.
  const page = await resolveAndAuthorize(ctx, fakeIdentity(["mcp:read"]), clientId, "mcp:read mcp:write mcp:admin", "v-access-jwt-0123456789abcdef012345678901234");
  const approve = await ctx.bridge.handleApprove(req({ body: { consent_token: extractConsentToken(String(page.body))!, approved: "true" }, headers: { origin: "https://auth.test" } }));
  const code = new URL(approve.headers.location as string).searchParams.get("code")!;
  const token = await ctx.bridge.handleToken(req({ body: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: "v-access-jwt-0123456789abcdef012345678901234" } }));
  assert.deepEqual(String(decodeJwt((token.body as { access_token: string }).access_token).scope).split(/\s+/).sort(), ["mcp:read"]);
});

test("empty-intersection access_denied is computed AFTER redirect_uri validation (§17.4 ordering)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // untrusted redirect_uri + a ceiling that would empty-intersect: redirect
  // validation (pre-validation, DIRECT) must run first — never a 302 to an
  // untrusted URI. Proves the ceiling check is post-validation.
  const resolved = await ctx.bridge.resolveIdentity(fakeIdentity(["mcp:write"]), ID_GOOD, IP);
  const res = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: clientId, redirect_uri: "https://evil.test/cb", code_challenge: pkceChallenge("v-ordering-0123456789abcdef0123456789012345"), code_challenge_method: "S256" } }), resolved);
  assert.equal(res.status, 400, "direct pre-validation error, not a 302");
  assert.equal(res.redirect, undefined);
  assert.notEqual((res.body as { error: string }).error, "access_denied");
  assert.ok(!JSON.stringify(res.headers).includes("evil.test"), "no redirect to the untrusted URI");
});
