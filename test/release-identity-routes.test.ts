import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import Fastify from "fastify";
import { decodeJwt, generateKeyPair, SignJWT } from "jose";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { verifyCloudflareAccessToken } from "../src/identity/cloudflare-access.ts";
import { entraIssuer, verifyEntraIdToken } from "../src/identity/entra.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";

const REDIRECT = "https://client.test/callback";
const TENANT = "11111111-2222-3333-4444-555555555555";
const ENTRA_CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function bridge(): Bridge {
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://resource.test/mcp",
    consentSigningSecret: "i".repeat(40), signingPrivateJwk: signingJwk(), signingKeyId: "release",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  return new Bridge({ config, store: new MemoryStore(), clock: { nowMs: () => Date.now() }, audit: { async writeAuthEvent() {} } });
}

async function reachesConsent(identity: IdentityPort, token: string, expectedSubject: string): Promise<void> {
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge: bridge(), identity, identityHeader: "x-release-identity" });
  try {
    const registration = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [REDIRECT], application_type: "web" }) });
    assert.equal(registration.statusCode, 201);
    const clientId = registration.json<{ client_id: string }>().client_id;
    const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge("release-identity-verifier-0123456789abcdef0123456789012"), code_challenge_method: "S256", scope: "mcp:read" });
    const response = await app.inject({ method: "GET", url: `/oauth/authorize?${query}`, headers: { "x-release-identity": token } });
    assert.equal(response.statusCode, 200);
    assert.match(response.body, /Authorize access/);
    const consent = /name="consent_token" value="([^"]+)"/.exec(response.body)?.[1];
    assert.ok(consent);
    assert.equal(decodeJwt(consent).sub, expectedSubject, "the verified identity reached the route-generated consent state");
  } finally { await app.close(); }
}

releaseTest("RM.5 direct, Cloudflare, and Entra header identities traverse a shipped authorization route", async () => {
  await reachesConsent({ async verify(input) {
    return input === "direct-token" ? { ok: true, identity: { subject: "direct-user" } } : { ok: false, reason: "bad" };
  } }, "direct-token", "direct-user");

  const cfKeys = await generateKeyPair("RS256");
  const now = Math.floor(Date.now() / 1000);
  const cfConfig = { audience: "cf-audience", certsUrl: "https://cf.test/certs", issuer: "https://cf.test" };
  const cfToken = await new SignJWT({ sub: "cf-user", email: "cf@example.test" }).setProtectedHeader({ alg: "RS256" })
    .setIssuer(cfConfig.issuer).setAudience(cfConfig.audience).setIssuedAt(now).setExpirationTime(now + 3600).sign(cfKeys.privateKey);
  await reachesConsent({ async verify(input) {
    return typeof input === "string" ? verifyCloudflareAccessToken(input, cfKeys.publicKey, cfConfig) : { ok: false, reason: "access_jwt_missing" };
  } }, cfToken, "cf-user");

  const entraKeys = await generateKeyPair("RS256");
  const entraConfig = { tenantId: TENANT, clientId: ENTRA_CLIENT, redirectUri: "https://auth.test/oauth/callback" };
  const entraToken = await new SignJWT({ oid: "entra-user", tid: TENANT }).setProtectedHeader({ alg: "RS256" })
    .setIssuer(entraIssuer(TENANT)).setAudience(ENTRA_CLIENT).setIssuedAt(now).setExpirationTime(now + 3600).sign(entraKeys.privateKey);
  await reachesConsent({ async verify(input) {
    return typeof input === "string" ? verifyEntraIdToken(input, entraKeys.publicKey, entraConfig) : { ok: false, reason: "entra_id_token_missing" };
  } }, entraToken, "entra-user");
});
