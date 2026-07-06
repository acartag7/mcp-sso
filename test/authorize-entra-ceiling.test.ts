// Entra group→scope authorization ceiling through the REAL authorize flow (S2b).
// Mirrors authorize-ceiling.test.ts but the IdentityPort is a real Entra verify:
// a synthetic RS256-signed id_token is fed through verifyEntraIdToken (the
// exported testable seam — addendum 12, no JWKS fetch), which calls the same
// validateEntraIdToken the live port uses. This proves the Entra ceiling
// PRODUCER composes correctly with the S2a IdP-agnostic ENGINE: groups map to a
// subset of scopeCatalog and the granted scopes are exactly the intersection;
// groups mapping to nothing ⇒ access_denied; an overage token fails closed;
// and a prior grant cannot resurrect a since-removed-group scope (row 22).

import assert from "node:assert/strict";
import { generateKeyPair, SignJWT, decodeJwt } from "jose";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { type EntraConfig, entraIssuer, verifyEntraIdToken } from "../src/identity/entra.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const NOW_SEC = Math.floor(NOW_MS / 1000);
const REDIRECT = "https://client.test/callback";
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
const SUBJECT_OID = "oid-ent-abc";
const IP = "203.0.113.9";
const TENANT = "11111111-2222-3333-4444-555555555555";
const ENTRA_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const READERS = "11111111-1111-1111-1111-111111111111";
const WRITERS = "22222222-2222-2222-2222-222222222222";
const ADMINS = "33333333-3333-3333-3333-333333333333";

// One RS256 key pair for every synthetic id_token (verifies via the testable
// verifyEntraIdToken seam, so no JWKS endpoint is ever contacted).
const { publicKey: PUBLIC_KEY, privateKey: PRIVATE_KEY } = await generateKeyPair("RS256");

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } }
class MemoryAudit implements AuditPort {
  private readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); }
  identity(): AuthAuditEvent[] { return this.events.filter((e) => e.event === "identity.verify"); }
}
class InMemoryClientStore implements ClientStore {
  private readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function bridgeConfig(store: ClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write", "mcp:admin"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stored", store },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

interface Ctx { bridge: Bridge; audit: MemoryAudit; entraConfig: EntraConfig; noGroupConfig: EntraConfig; }
function setup(): Ctx {
  const audit = new MemoryAudit();
  const clientStore = new InMemoryClientStore();
  const entraConfig: EntraConfig = {
    tenantId: TENANT, clientId: ENTRA_CLIENT_ID, redirectUri: "https://bridge.test/oauth/entra/callback",
    groupAuthorization: { mapping: { [READERS]: ["mcp:read"], [WRITERS]: ["mcp:write"], [ADMINS]: ["mcp:admin"] }, baseScopes: [] },
  };
  const noGroupConfig: EntraConfig = { tenantId: TENANT, clientId: ENTRA_CLIENT_ID, redirectUri: "https://bridge.test/oauth/entra/callback" };
  const bridge = new Bridge({ config: bridgeConfig(clientStore), store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit });
  return { bridge, audit, entraConfig, noGroupConfig };
}

/** Real Entra IdentityPort built on the testable verifyEntraIdToken seam. */
function entraPort(config: EntraConfig): IdentityPort {
  return { async verify(input: unknown) {
    if (typeof input !== "string" || !input) return { ok: false, reason: "entra_id_token_missing" };
    return verifyEntraIdToken(input, PUBLIC_KEY, config, { currentDate: new Date(NOW_MS) });
  } };
}

async function signIdToken(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(PRIVATE_KEY);
}
function entraPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: entraIssuer(TENANT), aud: ENTRA_CLIENT_ID, tid: TENANT, oid: SUBJECT_OID, exp: NOW_SEC + 3600, iat: NOW_SEC, ...overrides };
}

function req(partial: Partial<NormRequest> & { query?: NormRequest["query"]; body?: unknown }): NormRequest {
  return { query: partial.query ?? {}, body: partial.body, headers: partial.headers ?? {}, ip: partial.ip ?? IP };
}
function authorizeQuery(clientId: string, scope: string | undefined, verifier: string): NormRequest["query"] {
  const q: Record<string, string> = { response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256" };
  if (scope) q.scope = scope;
  return q;
}
function extractConsentToken(html: string): string | undefined { return /name="consent_token" value="([^"]+)"/.exec(html)?.[1]; }
/** PKCE verifier guaranteed ≥ 43 unreserved chars (RFC 7636) — unique per tag. */
const V = (tag: string): string => `ent-${tag}-pkce-verifier-0123456789abcdef0123456789abcdef`;

async function register(ctx: Ctx): Promise<string> {
  const reg = await ctx.bridge.handleRegister(req({ body: { redirect_uris: [REDIRECT], application_type: "web" } }));
  assert.equal(reg.status, 201);
  return (reg.body as { client_id: string }).client_id;
}

async function resolveAndAuthorize(ctx: Ctx, port: IdentityPort, idToken: string, clientId: string, scope: string | undefined, verifier: string): Promise<NormResponse> {
  const resolved = await ctx.bridge.resolveIdentity(port, idToken, IP);
  return ctx.bridge.handleAuthorize(req({ query: authorizeQuery(clientId, scope, verifier) }), resolved);
}

async function grantScopes(ctx: Ctx, port: IdentityPort, idToken: string, clientId: string, scope: string | undefined, verifier: string): Promise<string[]> {
  const page = await resolveAndAuthorize(ctx, port, idToken, clientId, scope, verifier);
  assert.equal(page.status, 200, `authorize should render the consent page, got ${JSON.stringify(page)}`);
  const consentToken = extractConsentToken(String(page.body));
  assert.ok(consentToken, "consent token in page");
  const approve = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: ISSUER } }));
  assert.equal(approve.status, 302);
  const code = new URL(approve.headers.location as string).searchParams.get("code");
  assert.ok(code, "code in approve redirect");
  const token = await ctx.bridge.handleToken(req({ body: { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier } }));
  assert.equal(token.status, 200, `token exchange failed: ${JSON.stringify(token.body)}`);
  return ((token.body as { scope: string }).scope ?? "").split(/\s+/).filter(Boolean).sort();
}

test("Entra groups ⊆ catalog: token grants exactly the intersection of requested and mapped scopes", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // groups {READERS, ADMINS} → ceiling {mcp:read, mcp:admin}; client requests all three.
  const scopes = await grantScopes(ctx, entraPort(ctx.entraConfig), await signIdToken(entraPayload({ groups: [READERS, ADMINS] })), clientId, "mcp:read mcp:write mcp:admin", V("intersect"));
  assert.deepEqual(scopes, ["mcp:admin", "mcp:read"]); // mcp:write is NOT mapped to either group
  // identity.verify success emitted with the verified subject + ip.
  const id = ctx.audit.identity();
  assert.equal(id.length, 1);
  assert.equal(id[0]!.status, "success");
  assert.equal(id[0]!.subject, SUBJECT_OID);
  assert.equal(id[0]!.ip, IP);
});

test("the minted access JWT carries only the Entra-intersected scope claim (the RS-enforced set)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  const port = entraPort(ctx.entraConfig);
  const verifier = V("accessjwt");
  const page = await resolveAndAuthorize(ctx, port, await signIdToken(entraPayload({ groups: [READERS] })), clientId, "mcp:read mcp:write mcp:admin", verifier);
  const approve = await ctx.bridge.handleApprove(req({ body: { consent_token: extractConsentToken(String(page.body))!, approved: "true" }, headers: { origin: ISSUER } }));
  const code = new URL(approve.headers.location as string).searchParams.get("code")!;
  const token = await ctx.bridge.handleToken(req({ body: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier } }));
  assert.deepEqual(String(decodeJwt((token.body as { access_token: string }).access_token).scope).split(/\s+/).sort(), ["mcp:read"]);
});

test("Entra groups mapping to nothing relevant ⇒ access_denied over the redirect channel", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // groups {WRITERS} → ceiling {mcp:write}; client requests mcp:read → empty intersection.
  const page = await resolveAndAuthorize(ctx, entraPort(ctx.entraConfig), await signIdToken(entraPayload({ groups: [WRITERS] })), clientId, "mcp:read", V("empty"));
  assert.equal(page.status, 302);
  assert.equal(new URL(page.headers.location as string).searchParams.get("error"), "access_denied");
  // identity resolved fine — the failure is the empty ceiling intersection, not identity.
  assert.equal(ctx.audit.identity()[0]!.status, "success");
});

test("an overage Entra token fails CLOSED: resolveIdentity throws access_denied 401 + identity.verify failure w/ entra_groups_overage", async () => {
  const ctx = setup();
  // groups absent + _claim_names.groups present ⇒ entra_groups_overage ⇒ {ok:false} ⇒ 401.
  const idToken = await signIdToken(entraPayload({ _claim_names: { groups: "src1" }, _claim_sources: { src1: { endpoint: "https://attacker.test/exfil" } } }));
  await assert.rejects(
    ctx.bridge.resolveIdentity(entraPort(ctx.entraConfig), idToken, IP),
    (e: unknown) => e instanceof OAuthError && e.code === "access_denied" && e.status === 401,
  );
  const ev = ctx.audit.identity()[0]!;
  assert.equal(ev.status, "failure");
  assert.equal(ev.reason, "entra_groups_overage");
  assert.equal(ev.ip, IP);
});

test("WITHOUT groupAuthorization, Entra behavior is unchanged: the full requested (catalog-valid) set is granted", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  // groups present but no mapping configured → no ceiling → v0.1 behavior.
  const scopes = await grantScopes(ctx, entraPort(ctx.noGroupConfig), await signIdToken(entraPayload({ groups: [READERS, ADMINS] })), clientId, "mcp:read mcp:write", V("nogroup"));
  assert.deepEqual(scopes, ["mcp:read", "mcp:write"]);
});

test("threat-model row 22: a prior Entra grant can't resurrect a since-removed-group scope (stored mode)", async () => {
  const ctx = setup();
  const clientId = await register(ctx);
  const port = entraPort(ctx.entraConfig);
  // #1: groups {ADMINS} → ceiling {mcp:admin}; grant mcp:admin → active refresh token carries mcp:admin.
  const first = await grantScopes(ctx, port, await signIdToken(entraPayload({ groups: [ADMINS] })), clientId, "mcp:admin", V("resurrect-one"));
  assert.deepEqual(first, ["mcp:admin"]);
  // #2: groups {READERS} → ceiling {mcp:read}; request mcp:read. The prior mcp:admin grant must NOT survive.
  const second = await grantScopes(ctx, port, await signIdToken(entraPayload({ groups: [READERS] })), clientId, "mcp:read", V("resurrect-two"));
  assert.deepEqual(second, ["mcp:read"]);
  assert.ok(!second.includes("mcp:admin"), "a since-removed-group scope must not be resurrected by the prior grant");
});
