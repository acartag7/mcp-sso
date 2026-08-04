import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, generateKeyPair, SignJWT, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { createGenericOidcRedirectIdentity } from "../src/identity/generic-oidc-redirect.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { http, mountStack, sdkPing, type HttpResponse } from "./lib/release-http-stack.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;
const ISSUER = "http://localhost", RESOURCE = "http://localhost/mcp", REDIRECT = "http://localhost:4321/callback";
const CIMD_ID = "https://client.release.test/cimd.json", OIDC_ISSUER = "https://oidc.release.test";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>(); saves = 0;
  async save(client: ClientRegistration): Promise<void> { this.saves++; this.rows.set(client.clientId, structuredClone(client)); }
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
function cookieValue(response: HttpResponse): string {
  const raw = response.headers["set-cookie"]; const header = Array.isArray(raw) ? raw[0] : raw;
  const value = /^mcp-sso-upstream=([^;]+)/.exec(header ?? "")?.[1]; assert.ok(value); return value;
}
function hidden(response: HttpResponse): string {
  const value = /name="consent_token" value="([^"]+)"/.exec(response.body)?.[1]; assert.ok(value); return value;
}
function failedStreamRequest(): Request {
  const stream = new ReadableStream<Uint8Array>({ start(controller) {
    controller.enqueue(new TextEncoder().encode("{")); controller.error(new Error("release stream failure"));
  } });
  return new Request(`${ISSUER}/oauth/token`, { method: "POST", headers: {
    "content-type": "application/json", "content-length": "64",
  }, body: stream, duplex: "half" } as RequestInit & { duplex: "half" });
}

releaseTest("RM.4 composes Hono Request, CIMD, generic OIDC, Memory, SDK, refresh, revoke, and failed-stream bounds", async () => {
  const clients = new Clients(), audit = new Audit(), clock = new SystemClock(), store = new MemoryStore();
  const config = createBridgeConfig({ issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "h".repeat(40),
    signingPrivateJwk: signingJwk(), signingKeyId: "release", redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER], dcr: { mode: "stored", store: clients },
    cimd: { enabled: true }, dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
  const counts = { dns: 0, cimd: 0, discovery: 0, token: 0 };
  const resolver: DnsResolver = { async resolve() { counts.dns++; return [{ address: "93.184.216.34", family: 4 }]; } };
  const cimdTransport: CimdTransport = { async connectAndGet() {
    counts.cimd++;
    async function* body(): AsyncGenerator<Uint8Array> {
      yield new TextEncoder().encode(JSON.stringify({ client_id: CIMD_ID, client_name: "Release CIMD client", redirect_uris: [REDIRECT] }));
    }
    return { status: 200, redirected: false, finalUrl: CIMD_ID, headersDistinct: { "content-type": ["application/json"] }, encodedBody: body() };
  } };
  const oidcKeys = await generateKeyPair("RS256"); let nonce = "unset";
  const identity = await createGenericOidcRedirectIdentity({ issuer: OIDC_ISSUER, clientId: "generic-release-client",
    clientSecret: "generic-release-secret", redirectUri: `${ISSUER}/oauth/callback`, endpoints: "discover" }, {
    discoveryFetch: { async get(url) {
      counts.discovery++; assert.equal(url, `${OIDC_ISSUER}/.well-known/openid-configuration`);
      return { status: 200, json: async () => ({ issuer: OIDC_ISSUER, authorization_endpoint: `${OIDC_ISSUER}/authorize`,
        token_endpoint: `${OIDC_ISSUER}/token`, jwks_uri: `${OIDC_ISSUER}/jwks`,
        id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic"] }) };
    } }, verifyKey: oidcKeys.publicKey,
    transport: { async postForm() {
      counts.token++; const now = Math.floor(Date.now() / 1000), upstreamAccess = "release-upstream-access";
      const idToken = await new SignJWT({ sub: "generic-user", nonce }).setProtectedHeader({ alg: "RS256" })
        .setIssuer(OIDC_ISSUER).setAudience("generic-release-client").setIssuedAt(now).setExpirationTime(now + 3600).sign(oidcKeys.privateKey);
      return { status: 200, text: async () => JSON.stringify({ id_token: idToken, access_token: upstreamAccess }) };
    } },
  });
  const bridge = new Bridge({ config, store, clock, audit, cimdTransport, cimdResolver: resolver });
  let tokenHandlerCalls = 0;
  const handleToken = bridge.handleToken.bind(bridge);
  bridge.handleToken = async (request) => { tokenHandlerCalls++; return handleToken(request); };
  const upstream = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, cimdTransport, cimdResolver: resolver });
  const mounted = await mountStack("hono", bridge, new RequestAuthorizer({ config, clock, audit }), config, { upstream });
  try {
    assert.ok(mounted.request); const auditBeforeStream = audit.events.length;
    const failed = await mounted.request(failedStreamRequest()); assert.equal(failed.status, 400);
    assert.deepEqual(await failed.json(), { error: "invalid_request", error_description: "Invalid request" });
    assert.equal(tokenHandlerCalls, 0, "failed under-cap stream reached no Bridge token handler");
    assert.equal(audit.events.length, auditBeforeStream, "failed under-cap stream reached no Bridge work");
    const verifier = "release-hono-verifier-0123456789abcdef01234567890123";
    const query = new URLSearchParams({ response_type: "code", client_id: CIMD_ID, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "release" });
    const authorize = await http.get(mounted.base, `/oauth/authorize?${query}`); assert.equal(authorize.status, 302);
    const cookie = cookieValue(authorize), claims = decodeJwt(cookie); nonce = claims.nonce as string;
    const callback = await http.get(mounted.base, `/oauth/callback?code=local-code&state=${claims.state as string}`, { cookie: `mcp-sso-upstream=${cookie}` });
    assert.equal(callback.status, 200);
    const approve = await http.postForm(mounted.base, "/oauth/authorize/approve", { consent_token: hidden(callback), approved: "true" }, { origin: ISSUER });
    assert.equal(approve.status, 302); const code = new URL(String(approve.headers.location)).searchParams.get("code"); assert.ok(code);
    const token = await http.postForm(mounted.base, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT,
      client_id: CIMD_ID, code_verifier: verifier });
    assert.equal(token.status, 200); const first = JSON.parse(token.body) as { access_token: string; refresh_token: string };
    await sdkPing(mounted.base, first.access_token, `pong: ${OIDC_ISSUER}|generic-user`);
    const refresh = await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: CIMD_ID });
    assert.equal(refresh.status, 200); const successor = JSON.parse(refresh.body).refresh_token as string;
    assert.ok(successor); assert.notEqual(successor, first.refresh_token, "refresh rotated to a distinct successor");
    assert.equal((await http.postForm(mounted.base, "/oauth/revoke", { token: successor })).status, 200);
    assert.equal((await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: successor, client_id: CIMD_ID })).status, 400);
    assert.deepEqual(counts, { dns: 1, cimd: 1, discovery: 1, token: 1 });
    assert.equal(clients.saves, 0, "HTTPS CIMD authorization created no DCR state");
  } finally { await mounted.close(); await store.close(); }
});
