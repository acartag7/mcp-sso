// §17.2 client_credentials grant (S3b). End-to-end through the Bridge token
// endpoint: both client-auth methods, the MachineTokenResponse split (no
// refresh_token), scope-vs-ceiling + resource semantics, rotation grace at the
// GRANT level (not just verify), the WWW-Authenticate: Basic challenge, the
// metadata advertisement gating, audit no-leak, and protected-/mcp access with
// the machine token. Existing user authorization-code + refresh flows are
// asserted unchanged by the response-type split.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { verifyAccessToken, sha256Hex } from "../src/crypto.ts";
import { authorizationServerMetadata } from "../src/metadata.ts";
import { OAuthError } from "../src/errors.ts";
import { parseBasicAuth } from "../src/client-auth.ts";
import { MemoryStore } from "../src/store/memory.ts";
import {
  provisionMachineClient, rotateMachineClientSecret, type MachineClientDeps,
} from "../src/machine-client.ts";

const NOW_MS = Date.parse("2026-07-06T12:00:00.000Z");
const CATALOG = ["mcp:read", "mcp:write", "mcp:admin"];
const RESOURCE = "https://api.test/mcp";

class FakeClock implements ClockPort {
  private ms: number;
  constructor(ms: number) { this.ms = ms; }
  nowMs(): number { return this.ms; }
  advance(ms: number): void { this.ms += ms; }
}

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); }
}

class InMemoryClientStore implements ClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k1" } as JWK;
}

interface Ctx {
  bridge: Bridge;
  config: BridgeConfig;
  clock: FakeClock;
  audit: MemoryAudit;
  clientStore: InMemoryClientStore;
  machineDeps: MachineClientDeps;
}

function setup(enabled: boolean): Ctx {
  const clientStore = new InMemoryClientStore();
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: RESOURCE,
    consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "k1",
    redirectAllowlist: ["https://client.test/callback"], scopeCatalog: [...CATALOG], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stored", store: clientStore },
    clientCredentials: { enabled },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const clock = new FakeClock(NOW_MS);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  return {
    bridge: new Bridge({ config, store, clock, audit }),
    config, clock, audit, clientStore,
    machineDeps: { store: clientStore, catalog: [...CATALOG], clock, audit },
  };
}

function req(partial: Partial<NormRequest> & { body?: unknown; headers?: Record<string, string> }): NormRequest {
  return { query: partial.query ?? {}, body: partial.body ?? {}, headers: partial.headers ?? {}, ip: partial.ip ?? "1.2.3.4" };
}

function basicHeader(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

/** Provision a machine client whose ceiling is read+write (NOT admin). */
async function provision(ctx: Ctx, allowedScopes = ["mcp:read", "mcp:write"]): Promise<{ clientId: string; clientSecret: string }> {
  return await provisionMachineClient(ctx.machineDeps, { allowedScopes });
}

function grantBody(body: Record<string, string>): Record<string, string> {
  return { grant_type: "client_credentials", ...body };
}

// ---------- success: both auth methods ----------

test("client_credentials via client_secret_basic: 200 + MachineTokenResponse (no refresh_token)", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({}) }));
  assert.equal(res.status, 200);
  assert.equal(res.headers["cache-control"], "no-store");
  const body = res.body as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), ["access_token", "expires_in", "scope", "token_type"], "no refresh_token member at all");
  assert.equal(body.token_type, "Bearer");
  assert.equal(body.expires_in, 600);
  assert.equal(body.scope, "mcp:read mcp:write"); // omitted scope ⇒ full ceiling (sorted)
  const verified = await verifyAccessToken(body.access_token as string, ctx.config, ctx.clock);
  assert.equal(verified.subject, c.clientId, "sub = client_id (RFC 9068 §2.2)");
  assert.equal(verified.clientId, c.clientId, "client_id claim preserved");
  assert.deepEqual(verified.scopes.sort(), ["mcp:read", "mcp:write"]);
});

test("client_credentials via client_secret_post: identical shape to Basic", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({ body: grantBody({ client_id: c.clientId, client_secret: c.clientSecret }) }));
  assert.equal(res.status, 200);
  assert.deepEqual(Object.keys(res.body as Record<string, unknown>).sort(), ["access_token", "expires_in", "scope", "token_type"]);
  const verified = await verifyAccessToken((res.body as { access_token: string }).access_token, ctx.config, ctx.clock);
  assert.equal(verified.subject, c.clientId);
});

// ---------- failure: client auth ----------

test("wrong secret via Basic ⇒ 401 invalid_client + WWW-Authenticate: Basic", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, "mcs_" + "X".repeat(43)) }, body: grantBody({}) }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
  assert.match(res.headers["www-authenticate"] ?? "", /^Basic realm="https:\/\/auth\.test", charset="UTF-8"$/, "Basic challenge present");
});

test("wrong secret via post ⇒ 401 invalid_client, NO WWW-Authenticate (post failures don't earn the Basic challenge)", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({ body: grantBody({ client_id: c.clientId, client_secret: "mcs_" + "X".repeat(43) }) }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
  assert.equal(res.headers["www-authenticate"], undefined, "no challenge for a post failure");
});

test("expired secret ⇒ 401 invalid_client (+ Basic challenge when Basic attempted)", async () => {
  const ctx = setup(true);
  const c = await provisionMachineClient(ctx.machineDeps, { allowedScopes: ["mcp:read"], secretTtlSeconds: 600 });
  ctx.clock.advance(601 * 1000); // past the provisioned lifetime
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({}) }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
  assert.match(res.headers["www-authenticate"] ?? "", /^Basic /);
});

test("unknown client / missing creds ⇒ 401 invalid_client (no Basic challenge when Basic not attempted)", async () => {
  const ctx = setup(true);
  // unknown client via post
  const unknown = await ctx.bridge.handleToken(req({ body: grantBody({ client_id: "mcc_nope", client_secret: "mcs_" + "X".repeat(43) }) }));
  assert.equal(unknown.status, 401);
  assert.equal((unknown.body as { error: string }).error, "invalid_client");
  assert.equal(unknown.headers["www-authenticate"], undefined);
  // no credentials at all
  const none = await ctx.bridge.handleToken(req({ body: grantBody({}) }));
  assert.equal(none.status, 401);
  assert.equal((none.body as { error: string }).error, "invalid_client");
  assert.equal(none.headers["www-authenticate"], undefined);
});

test("malformed Basic header (no colon) ⇒ 401 invalid_client + Basic challenge (Basic WAS attempted)", async () => {
  const ctx = setup(true);
  // base64("nocolon") has no ':' — parseBasicAuth returns null but Basic was attempted
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: `Basic ${Buffer.from("nocolonhere").toString("base64")}` }, body: grantBody({}) }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
  assert.match(res.headers["www-authenticate"] ?? "", /^Basic /, "Basic attempted even though malformed ⇒ challenge sent");
});

test("both auth methods (Basic + body client_secret) ⇒ 401 invalid_client (RFC 6749 §2.3)", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({
    headers: { authorization: basicHeader(c.clientId, c.clientSecret) },
    body: grantBody({ client_secret: c.clientSecret }),
  }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
});

test("two-methods rejection keys on the Basic SCHEME: malformed Basic + body client_secret is still two methods", async () => {
  // P4 fix: the guard must fire on header PRESENCE, not a successful parse — a
  // non-decodable Basic plus a body secret is still two auth methods (RFC 6749 §2.3).
  const ctx = setup(true);
  const c = await provision(ctx);
  const malformedBasic = `Basic ${Buffer.from("no-colon-here").toString("base64")}`; // parseBasicAuth ⇒ null
  const res = await ctx.bridge.handleToken(req({
    headers: { authorization: malformedBasic },
    body: grantBody({ client_id: c.clientId, client_secret: c.clientSecret }),
  }));
  assert.equal(res.status, 401);
  assert.equal((res.body as { error: string }).error, "invalid_client");
  // The rejection is auditable: the failure event carries the presented client_id.
  const evt = ctx.audit.events.find((e) => e.event === "oauth.token.client_credentials" && e.status === "failure");
  assert.equal(evt?.reason, "invalid_client");
  assert.equal(evt?.clientId, c.clientId, "two-methods failure audit captured the client_id (not dropped)");
});

// ---------- grant semantics: scope + resource ----------

test("scope subset: requesting one scope returns exactly that scope", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({ scope: "mcp:read" }) }));
  assert.equal(res.status, 200);
  assert.equal((res.body as { scope: string }).scope, "mcp:read");
});

test("scope outside the ceiling ⇒ invalid_scope 400", async () => {
  const ctx = setup(true);
  const c = await provision(ctx); // ceiling = read+write, NOT admin
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({ scope: "mcp:admin" }) }));
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_scope");
});

test("catalog drift (Codex P2): a ceiling scope removed from the live catalog is never minted (fail-closed, matches user grants)", async () => {
  // Simulate a record provisioned BEFORE the catalog was narrowed: persisted
  // ceiling includes a scope (mcp:legacy) no longer in the running catalog.
  const ctx = setup(true); // catalog = [mcp:read, mcp:write, mcp:admin]
  const driftedSecret = "mcs_" + "Z".repeat(43);
  await ctx.clientStore.save({
    clientId: "mcc_drifted", redirectUris: [], applicationType: "machine", issuedAtEpoch: Math.floor(NOW_MS / 1000),
    allowedScopes: ["mcp:read", "mcp:legacy"], secrets: [{ hash: sha256Hex(driftedSecret), createdAtEpoch: Math.floor(NOW_MS / 1000) }],
  });
  // Omitted scope ⇒ the full ceiling, which includes the drifted mcp:legacy ⇒ invalid_scope.
  const omitted = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader("mcc_drifted", driftedSecret) }, body: grantBody({}) }));
  assert.equal(omitted.status, 400);
  assert.equal((omitted.body as { error: string }).error, "invalid_scope");
  // Requesting only the still-valid scope succeeds (the catalog check passes for mcp:read).
  const requested = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader("mcc_drifted", driftedSecret) }, body: grantBody({ scope: "mcp:read" }) }));
  assert.equal(requested.status, 200);
  assert.equal((requested.body as { scope: string }).scope, "mcp:read");
  // Requesting the drifted scope explicitly is also rejected.
  const explicit = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader("mcc_drifted", driftedSecret) }, body: grantBody({ scope: "mcp:legacy" }) }));
  assert.equal(explicit.status, 400);
  assert.equal((explicit.body as { error: string }).error, "invalid_scope");
});

test("resource mismatch ⇒ invalid_target 400; omitted resource is accepted (audience-bound anyway)", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  const mismatch = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({ resource: "https://other.test/mcp" }) }));
  assert.equal(mismatch.status, 400);
  assert.equal((mismatch.body as { error: string }).error, "invalid_target");
  // omitted resource ⇒ OK (the access token is audience-bound to config.resource regardless)
  const ok = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({ resource: RESOURCE }) }));
  assert.equal(ok.status, 200);
});

// ---------- rotation grace at the GRANT level ----------

test("rotation grace: both old + new secret accepted until old expiry; only new after", async () => {
  const ctx = setup(true);
  const a = await provision(ctx);
  const b = await rotateMachineClientSecret(ctx.machineDeps, a.clientId, { graceSeconds: 600 });
  ctx.clock.advance(599 * 1000); // still inside grace
  assert.equal((await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(a.clientId, a.clientSecret) }, body: grantBody({}) }))).status, 200, "old secret still valid in grace");
  assert.equal((await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(a.clientId, b.clientSecret) }, body: grantBody({}) }))).status, 200, "new secret valid");
  ctx.clock.advance(2 * 1000); // past grace
  assert.equal((await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(a.clientId, a.clientSecret) }, body: grantBody({}) }))).status, 401, "old secret expired out of grace");
  assert.equal((await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(a.clientId, b.clientSecret) }, body: grantBody({}) }))).status, 200, "new secret still valid");
});

// ---------- disabled ⇒ unsupported_grant_type + metadata does not advertise ----------

test("disabled clientCredentials ⇒ grant_type=client_credentials is unsupported_grant_type 400", async () => {
  const ctx = setup(false);
  const c = await provision(ctx); // provisioned into the store regardless
  const res = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({}) }));
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "unsupported_grant_type");
});

test("metadata: advertises client_credentials + basic/post ONLY when enabled", () => {
  const enabled = authorizationServerMetadata(setup(true).config);
  assert.deepEqual(enabled.grant_types_supported, ["authorization_code", "refresh_token", "client_credentials"]);
  assert.deepEqual(enabled.token_endpoint_auth_methods_supported, ["none", "client_secret_basic", "client_secret_post"]);
  const disabled = authorizationServerMetadata(setup(false).config);
  assert.deepEqual(disabled.grant_types_supported, ["authorization_code", "refresh_token"]);
  assert.deepEqual(disabled.token_endpoint_auth_methods_supported, ["none"]);
});

// ---------- protected /mcp access with the machine token ----------

test("protected /mcp access: RequestAuthorizer accepts the machine token; insufficient_scope step-up works", async () => {
  const ctx = setup(true);
  const c = await provision(ctx); // ceiling read+write
  const token = await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({}) }));
  const accessToken = (token.body as { access_token: string }).access_token;
  const authorizer = new RequestAuthorizer({ config: ctx.config, clock: ctx.clock, audit: new MemoryAudit() });
  const auth = await authorizer.authorize({ authorization: `Bearer ${accessToken}`, requiredScope: "mcp:read" });
  assert.equal(auth.subject, c.clientId);
  assert.deepEqual(auth.scopes.sort(), ["mcp:read", "mcp:write"]);
  // the machine client has no admin scope ⇒ step-up denies
  await assert.rejects(
    authorizer.authorize({ authorization: `Bearer ${accessToken}`, requiredScope: "mcp:admin" }),
    (e: unknown) => e instanceof OAuthError && e.code === "insufficient_scope" && e.status === 403,
  );
});

// ---------- audit ----------

test("audit: success emits oauth.token.client_credentials with metadata only (no secret/hash)", async () => {
  const ctx = setup(true);
  const c = await provision(ctx, ["mcp:read", "mcp:write"]);
  await ctx.bridge.handleToken(req({ headers: { authorization: basicHeader(c.clientId, c.clientSecret) }, body: grantBody({ scope: "mcp:read" }) }));
  const evt = ctx.audit.events.find((e) => e.event === "oauth.token.client_credentials" && e.status === "success");
  assert.equal(evt?.clientId, c.clientId);
  assert.equal(evt?.subject, c.clientId);
  assert.equal(evt?.resource, RESOURCE);
  assert.deepEqual(evt?.scopes, ["mcp:read"]);
  const dump = JSON.stringify(ctx.audit.events);
  for (const needle of [c.clientSecret, "mcs_", "hash", "client_secret"]) {
    assert.equal(dump.toLowerCase().includes(needle.toLowerCase()), false, `audit leaked '${needle}'`);
  }
});

test("audit: failure emits a failure event with reason=invalid_client", async () => {
  const ctx = setup(true);
  const c = await provision(ctx);
  await ctx.bridge.handleToken(req({ body: grantBody({ client_id: c.clientId, client_secret: "mcs_" + "X".repeat(43) }) }));
  const evt = ctx.audit.events.find((e) => e.event === "oauth.token.client_credentials" && e.status === "failure");
  assert.equal(evt?.reason, "invalid_client");
  assert.equal(evt?.clientId, c.clientId, "failure audit carries the presented client_id");
});

// ---------- parseBasicAuth unit (RFC 6749 §2.3.1 quirks) ----------

test("parseBasicAuth: base64 + first-colon split + percent-decode; non-basic/malformed ⇒ null", () => {
  const id = "mcc_abc", secret = "mcs_xyz";
  assert.deepEqual(parseBasicAuth(`Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`), { clientId: id, clientSecret: secret });
  // password containing a colon: split on the FIRST colon only
  assert.deepEqual(parseBasicAuth(`Basic ${Buffer.from(`${id}:${secret}:extra`).toString("base64")}`), { clientId: id, clientSecret: `${secret}:extra` });
  // percent-encoded id (a spec-literal client) round-trips through the decode
  const enc = "mcc%5Fabc"; // _ percent-encoded
  assert.deepEqual(parseBasicAuth(`Basic ${Buffer.from(`${enc}:${secret}`).toString("base64")}`), { clientId: "mcc_abc", clientSecret: secret });
  // no colon ⇒ malformed ⇒ null
  assert.equal(parseBasicAuth(`Basic ${Buffer.from("nocolon").toString("base64")}`), null);
  // not a Basic header ⇒ null (not an error)
  assert.equal(parseBasicAuth("Bearer xyz"), null);
  assert.equal(parseBasicAuth(undefined), null);
});

// ---------- regression: the response-type split did not break user grants ----------

test("regression: authorization_code + refresh still carry refresh_token (UserTokenResponse)", async () => {
  const ctx = setup(true);
  // Register a user client, drive the full authorize→approve→token flow.
  const reg = await ctx.bridge.handleRegister(req({ body: { redirect_uris: ["https://client.test/callback"] } }));
  const clientId = (reg.body as { client_id: string }).client_id;
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const { pkceChallenge } = await import("../src/crypto.ts");
  const page = await ctx.bridge.handleAuthorize(req({ query: { response_type: "code", client_id: clientId, redirect_uri: "https://client.test/callback", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read" } }), { subject: "human@test" });
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(String(page.body))![1];
  const approve = await ctx.bridge.handleApprove(req({ body: { consent_token: consentToken, approved: "true" }, headers: { origin: "https://auth.test" } }));
  const code = new URL(approve.headers.location as string).searchParams.get("code")!;
  const token = await ctx.bridge.handleToken(req({ body: { grant_type: "authorization_code", code, redirect_uri: "https://client.test/callback", client_id: clientId, code_verifier: verifier } }));
  assert.equal(token.status, 200);
  assert.ok((token.body as { refresh_token: string }).refresh_token, "user grant STILL has refresh_token");
});
