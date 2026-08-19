// F1 regression — both shipped composition roots must thread their operator
// limiter into createUpstreamRedirectFlow (§6.7: one port supplied to the Bridge
// AND the flow covers upstream:<ip> on authorize and the callback). The examples
// used to build the flow WITHOUT rateLimit, so upstream:<ip> silently defaulted
// to noop even when the operator supplied a full-coverage limiter to the
// composition — the register/token budgets were bounded while the upstream
// surface was not. The assertion is the limiter-key observation differential:
// the SAME port that charges register:<ip> must also charge upstream:<ip>.

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { buildApp } from "../examples/fastify-sqlite/app.ts";
import { buildGateway } from "../examples/api-key-gateway/app.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import type { RedirectIdentityPort } from "../src/ports/identity.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";
import { pkceChallenge } from "../src/crypto.ts";

const ISSUER = "https://bridge.test";
const CLIENT_REDIRECT = "https://app.test/callback";
const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";

function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

function upstreamConfig(): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER,
    resource: `${ISSUER}/mcp`,
    consentSigningSecret: randomBytes(32).toString("base64url"),
    signingPrivateJwk: signingJwk(),
    redirectAllowlist: [CLIENT_REDIRECT],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

function stubIdentity(): RedirectIdentityPort {
  return {
    redirectUri: `${ISSUER}/oauth/callback`,
    buildAuthorizationUrl({ state }) { return `https://idp.test/authorize?state=${state}`; },
    async exchangeAndVerify() { return { ok: true, identity: { subject: "upstream-user" } }; },
  };
}

function recordingLimiter(): RateLimitPort & { keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    async check(key: string): Promise<boolean> { keys.push(key); return true; },
  };
}

/** Register a client, then initiate the upstream authorize leg (the flow's 302 to
 *  the IdP). The passed limiter observes every key the composition charges. */
async function driveRegisterAndAuthorize(
  app: { inject(input: unknown): Promise<unknown> },
  limiter: RateLimitPort & { keys: string[] },
): Promise<void> {
  const reg = await app.inject({
    method: "POST",
    url: "/oauth/register",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT] }),
  }) as { statusCode: number; body: string };
  assert.equal(reg.statusCode, 201, "stateless DCR registration succeeds");
  const clientId = JSON.parse(reg.body).client_id as string;
  const q = new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: CLIENT_REDIRECT,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    scope: "mcp:read", state: "client-state",
  });
  const res = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` }) as { statusCode: number; headers: { location?: string } };
  assert.equal(res.statusCode, 302, "upstream authorize redirects to the IdP");
  assert.match(res.headers.location ?? "", /^https:\/\/idp\.test\/authorize\?/, "302 target is the stub IdP");
  // The differential: the port that charged the Bridge keys must have charged the
  // flow's key too — the gap this test pins is wiring, not capability.
  assert.ok(limiter.keys.some((k) => k.startsWith("register:")), "the operator limiter charges the Bridge register:<ip> key");
  assert.ok(limiter.keys.some((k) => k.startsWith("upstream:")), "the SAME limiter charges upstream:<ip> via the wired flow");
}

test("fastify-sqlite example: an operator-supplied limiter covers the upstream flow surface", async () => {
  const limiter = recordingLimiter();
  const built = await buildApp({ config: upstreamConfig(), upstream: { identity: stubIdentity() }, rateLimit: limiter });
  try {
    await driveRegisterAndAuthorize(built.app, limiter);
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("api-key-gateway example: an operator-supplied limiter covers the upstream flow surface", async () => {
  const limiter = recordingLimiter();
  const built = await buildGateway({
    config: upstreamConfig(),
    backendUrl: "http://127.0.0.1:1/mcp",
    getBackendCredential: () => "unused",
    upstream: { identity: stubIdentity() },
    rateLimit: limiter,
  });
  try {
    await driveRegisterAndAuthorize(built.app, limiter);
  } finally {
    await built.app.close();
    await built.close();
  }
});
