import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { createPool, type PoolConnection } from "mysql2/promise";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { entraIssuer, entraJwksUrl, entraTokenEndpoint } from "../src/identity/entra.ts";
import { createEntraRedirectIdentity } from "../src/identity/entra-redirect.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { createMysqlStore } from "../src/store/mysql.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { boundedTestRateLimit } from "./support/bounded-rate-limit.ts";
import { attemptCleanup, fetchLoopbackOnly, http, mountStack, sdkPing, type HttpResponse } from "./lib/release-http-stack.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;
const ISSUER = "http://localhost", RESOURCE = "http://localhost/mcp", REDIRECT = "http://localhost:4321/callback";
const TENANT = "11111111-2222-3333-4444-555555555555", CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const GROUP = "99999999-8888-7777-6666-555555555555";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, structuredClone(client)); }
  async find(id: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(id) ?? null); }
}
class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(structuredClone(event)); }
}
function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}
function consentToken(response: HttpResponse): string {
  const value = /name="consent_token" value="([^"]+)"/.exec(response.body)?.[1]; assert.ok(value); return value;
}
function cookieValue(response: HttpResponse): string {
  const raw = response.headers["set-cookie"]; const header = Array.isArray(raw) ? raw[0] : raw;
  const value = /^mcp-sso-upstream=([^;]+)/.exec(header ?? "")?.[1]; assert.ok(value); return value;
}

releaseTest("RM.3 composes Express, MySQL, Entra redirect, stored DCR, ceiling, deny, SDK, refresh, replay, and revoke", async () => {
  assert.ok(process.env.MYSQL_URL);
  const lockPool = createPool(process.env.MYSQL_URL); let lock: PoolConnection | undefined;
  let store: Awaited<ReturnType<typeof createMysqlStore>> | undefined;
  let mounted: Awaited<ReturnType<typeof mountStack>> | undefined;
  const clientIds: string[] = [], jtis: string[] = [];
  const realFetch = globalThis.fetch;
  try {
    lock = await lockPool.getConnection();
    const [rows] = await lock.query("SELECT GET_LOCK(?, 120) AS ok", ["mcp_sso_oauth_lock"]);
    assert.equal((rows as Array<{ ok: number }>)[0]?.ok, 1);
    store = await createMysqlStore(process.env.MYSQL_URL);
    const clients = new Clients(), audit = new Audit(), clock = new SystemClock();
    const config = createBridgeConfig({ issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "e".repeat(40),
      signingPrivateJwk: signingJwk(), signingKeyId: "release", redirectAllowlist: [REDIRECT],
      scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
      dcr: { mode: "stored", store: clients }, dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
      refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
    const entraKeys = await generateKeyPair("RS256"); let nonce = "unset";
    const entraPublicJwk = { ...(await exportJWK(entraKeys.publicKey)), kid: "entra-release", alg: "RS256", use: "sig" };
    const providerCalls = { token: 0, jwks: 0 };
    globalThis.fetch = (async (input: URL | Request | string, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === entraJwksUrl(TENANT)) { providerCalls.jwks++; return new Response(JSON.stringify({ keys: [entraPublicJwk] }), {
        headers: { "content-type": "application/json" },
      }); }
      if (url === entraTokenEndpoint(TENANT)) {
        providerCalls.token++; const now = Math.floor(Date.now() / 1000);
        const idToken = await new SignJWT({ oid: "entra-release-user", tid: TENANT, nonce, groups: [GROUP] })
          .setProtectedHeader({ alg: "RS256", kid: "entra-release" }).setIssuer(entraIssuer(TENANT)).setAudience(CLIENT)
          .setIssuedAt(now).setExpirationTime(now + 3600).sign(entraKeys.privateKey);
        return new Response(JSON.stringify({ id_token: idToken }), { headers: { "content-type": "application/json" } });
      }
      return fetchLoopbackOnly(realFetch, input, init);
    }) as typeof fetch;
    const identity = createEntraRedirectIdentity({ tenantId: TENANT, clientId: CLIENT,
      redirectUri: `${ISSUER}/oauth/callback`, groupAuthorization: { mapping: { [GROUP]: ["mcp:read"] }, baseScopes: [] } }, {
      scopeCatalog: config.scopeCatalog,
    });
    const bridge = new Bridge({ config, store, clock, audit, rateLimit: boundedTestRateLimit() });
    const upstream = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit });
    mounted = await mountStack("express", bridge, new RequestAuthorizer({ config, clock, audit }), config, { upstream });
    const registration = await http.postJson(mounted.base, "/oauth/register", { redirect_uris: [REDIRECT], application_type: "native" });
    assert.equal(registration.status, 201); const clientId = JSON.parse(registration.body).client_id as string; clientIds.push(clientId);
    const verifier = "release-express-verifier-0123456789abcdef012345678901";
    const authorizeOnce = async (): Promise<string> => {
      const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
        code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read mcp:write", state: `s-${Date.now()}` });
      const authorize = await http.get(mounted!.base, `/oauth/authorize?${query}`); assert.equal(authorize.status, 302);
      const cookie = cookieValue(authorize); const claims = decodeJwt(cookie); nonce = claims.nonce as string;
      if (typeof claims.jti === "string") jtis.push(claims.jti);
      const callback = await http.get(mounted!.base, `/oauth/callback?code=local-code&state=${claims.state as string}`, { cookie: `mcp-sso-upstream=${cookie}` });
      assert.equal(callback.status, 200); const consent = consentToken(callback); const jti = decodeJwt(consent).jti; if (typeof jti === "string") jtis.push(jti);
      return consent;
    };
    const denied = await http.postForm(mounted.base, "/oauth/authorize/approve", { consent_token: await authorizeOnce(), approved: "false" }, { origin: ISSUER });
    assert.equal(denied.status, 302); assert.equal(new URL(String(denied.headers.location)).searchParams.get("error"), "access_denied");
    const approve = await http.postForm(mounted.base, "/oauth/authorize/approve", { consent_token: await authorizeOnce(), approved: "true" }, { origin: ISSUER });
    assert.equal(approve.status, 302); const code = new URL(String(approve.headers.location)).searchParams.get("code"); assert.ok(code);
    const token = await http.postForm(mounted.base, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
    assert.equal(token.status, 200); const first = JSON.parse(token.body) as { access_token: string; refresh_token: string };
    assert.equal(decodeJwt(first.access_token).scope, "mcp:read"); await sdkPing(mounted.base, first.access_token, "pong: entra-release-user");
    const refresh = await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: clientId });
    assert.equal(refresh.status, 200); const successor = JSON.parse(refresh.body).refresh_token as string;
    assert.ok(successor); assert.notEqual(successor, first.refresh_token, "refresh rotated to a distinct successor");
    assert.equal((await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: clientId })).status, 400);
    assert.equal((await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: successor, client_id: clientId })).status, 400);
    const revokeApprove = await http.postForm(mounted.base, "/oauth/authorize/approve", { consent_token: await authorizeOnce(), approved: "true" }, { origin: ISSUER });
    const revokeCode = new URL(String(revokeApprove.headers.location)).searchParams.get("code"); assert.ok(revokeCode);
    const revokeToken = await http.postForm(mounted.base, "/oauth/token", { grant_type: "authorization_code", code: revokeCode,
      redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
    assert.equal(revokeToken.status, 200);
    const revocable = JSON.parse(revokeToken.body).refresh_token as string;
    assert.ok(revocable); assert.notEqual(revocable, successor, "reauthorization minted a fresh revocable token");
    assert.equal((await http.postForm(mounted.base, "/oauth/revoke", { token: revocable })).status, 200);
    assert.equal((await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: revocable, client_id: clientId })).status, 400);
    assert.deepEqual(providerCalls, { token: 3, jwks: 1 }, "the composed flow used the controlled Entra token and JWKS seams");
  } finally {
    globalThis.fetch = realFetch;
    const errors: Error[] = [];
    await attemptCleanup("Express", async () => mounted?.close(), errors);
    await attemptCleanup("MySQL store", async () => store?.close(), errors);
    if (lock && clientIds.length > 0) {
      await attemptCleanup("MySQL refresh rows", async () => { await lock!.query(
        "DELETE f FROM oauth_refresh_token_families f JOIN oauth_refresh_tokens t ON t.family_id=f.family_id WHERE t.client_id IN (?)", [clientIds]); }, errors);
      await attemptCleanup("MySQL authorization codes", async () => { await lock!.query("DELETE FROM oauth_auth_codes WHERE client_id IN (?)", [clientIds]); }, errors);
    }
    if (lock && jtis.length > 0) await attemptCleanup("MySQL consent JTIs", async () => { await lock!.query(
      "DELETE FROM oauth_consent_jtis WHERE jti IN (?)", [jtis]); }, errors);
    if (lock) {
      await attemptCleanup("MySQL advisory lock", async () => { await lock!.query("SELECT RELEASE_LOCK(?)", ["mcp_sso_oauth_lock"]); }, errors);
      lock.release();
    }
    await attemptCleanup("MySQL lock pool", () => lockPool.end(), errors);
    if (errors.length > 0) throw new AggregateError(errors, "RM.3 cleanup failed");
  }
});
