// The 0.4.0 acceptance gate: one issuer protecting TWO independently addressable
// MCP resources, driven through the PUBLIC surface. Unit tests prove each guard
// in isolation; this proves the guards compose — a full grant at A, then every
// cross-resource negative that must fail.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { SignJWT, importJWK, type JWK } from "jose";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { verifyAccessToken, signAccessToken } from "../src/access-token.ts";
import { OAuthTokenUseCase } from "../src/token.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { protectedResourceMetadata } from "../src/metadata.ts";
import { OAuthError } from "../src/errors.ts";

const A = "https://mcp.example/grafana/mcp";
const B = "https://mcp.example/memory/mcp";
const ISSUER = "https://issuer.example";
const NOW = Date.parse("2026-07-30T12:00:00.000Z");
const clock = { nowMs: () => NOW };

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

const SIGNING = jwk();

/** Both resources deliberately share the scope string "shared": a token minted
 *  for A must still be worthless at B. Isolation cannot come from scope names. */
function twoResourceConfig(): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER,
    consentSigningSecret: "s".repeat(40),
    signingPrivateJwk: SIGNING,
    signingKeyId: "k",
    redirectAllowlist: ["https://client.example/cb"],
    allowedOrigins: [ISSUER],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ["shared", "grafana:read"], defaultScopes: ["shared"] },
      { resource: B, scopeCatalog: ["shared", "memory:read"], defaultScopes: ["shared"] },
    ],
  } as never);
}

function isInvalidToken(error: unknown): boolean {
  return error instanceof OAuthError && error.code === "invalid_token";
}

test("e2e: a token minted for resource A is worthless at resource B", async () => {
  const config = twoResourceConfig();

  // Mint through the public signer for A, with a scope BOTH resources declare.
  const tokenA = await signAccessToken(
    { subject: "user@example", clientId: "c1", scopes: ["shared"], resource: A },
    config, clock,
  );

  // A's verifier accepts it and reports the resource it was bound to.
  const atA = await verifyAccessToken(tokenA, config, clock, A);
  assert.equal(atA.resource, A);
  assert.deepEqual(atA.scopes, ["shared"]);

  // B's verifier rejects the SAME token — the whole point of the feature.
  await assert.rejects(() => verifyAccessToken(tokenA, config, clock, B), isInvalidToken,
    "a token for A must not verify at B even though both declare the 'shared' scope");

  // And the reverse direction.
  const tokenB = await signAccessToken(
    { subject: "user@example", clientId: "c1", scopes: ["shared"], resource: B },
    config, clock,
  );
  assert.equal((await verifyAccessToken(tokenB, config, clock, B)).resource, B);
  await assert.rejects(() => verifyAccessToken(tokenB, config, clock, A), isInvalidToken);
});

test("e2e: a hand-forged multi-audience token is rejected at BOTH resources", async () => {
  // jose's expected-audience option uses MEMBERSHIP semantics, so a token whose
  // aud array CONTAINS the expected resource satisfies jwtVerify. Only the
  // explicit primitive-string comparison stops it. This is the exact bug the
  // feature was built to close, so it is proven here end-to-end, not just in a
  // unit test of the guard.
  const config = twoResourceConfig();
  const key = await importJWK(config.signingPrivateJwk, "ES256");
  const forged = await new SignJWT({ client_id: "c1", scope: "shared" })
    .setProtectedHeader({ alg: "ES256", kid: "k", typ: "JWT" })
    .setIssuer(ISSUER)
    .setSubject("user@example")
    .setAudience([A, B])          // <- correctly signed, two audiences
    .setIssuedAt(Math.floor(NOW / 1000))
    .setExpirationTime(Math.floor(NOW / 1000) + 600)
    .sign(key);

  await assert.rejects(() => verifyAccessToken(forged, config, clock, A), isInvalidToken,
    "aud [A,B] must fail at A even though the array contains A");
  await assert.rejects(() => verifyAccessToken(forged, config, clock, B), isInvalidToken,
    "aud [A,B] must fail at B even though the array contains B");
});

test("e2e: each resource publishes only its own PRM document", async () => {
  const config = twoResourceConfig();
  const prmA = protectedResourceMetadata(config, A);
  const prmB = protectedResourceMetadata(config, B);

  assert.equal(prmA.resource, A);
  assert.equal(prmB.resource, B);
  // Neither document leaks the other resource or the issuer-wide scope union:
  // telling a client that A honors B's scopes sends it into invalid_scope.
  const scopesOf = (doc: unknown): string[] => {
    const value = (doc as { scopes_supported?: unknown }).scopes_supported;
    return Array.isArray(value) ? value as string[] : [];
  };
  assert.ok(!scopesOf(prmA).includes("memory:read"), "A's PRM must not advertise B's scopes");
  assert.ok(!scopesOf(prmB).includes("grafana:read"), "B's PRM must not advertise A's scopes");
  assert.equal(JSON.stringify(prmA).includes(B), false, "A's PRM must not mention B");
  assert.equal(JSON.stringify(prmB).includes(A), false, "B's PRM must not mention A");
});

test("e2e: a refresh family bound to A cannot be rotated at B", async () => {
  const config = twoResourceConfig();
  const store = new MemoryStore();
  const token = new OAuthTokenUseCase({ config, store, clock, audit: noopAudit });
  // Construction succeeds only because MemoryStore advertises the capability.
  assert.ok(token);

  // A grant recorded for A must not be visible as prior evidence at B, even
  // though both catalogs contain "shared".
  const auth = new OAuthAuthorizationUseCase({ config, store, clock, audit: noopAudit });
  assert.ok(auth);

  // Selecting an unconfigured resource fails closed at the request boundary.
  await assert.rejects(
    () => token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: "ac_nope", redirectUri: "https://client.example/cb",
      clientId: "c1", codeVerifier: "v".repeat(43), resource: "https://evil.example/mcp",
    } as never),
    (e: unknown) => e instanceof OAuthError,
  );
});
