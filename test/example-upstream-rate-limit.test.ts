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
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { buildApp } from "../examples/fastify-sqlite/app.ts";
import { buildGateway, buildGatewayExample } from "../examples/api-key-gateway/app.ts";
import { FASTIFY_DCR_REGISTER_RATE_LIMIT } from "../examples/fastify-sqlite/registration-rate-limit.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import type { IdentityPort, RedirectIdentityPort } from "../src/ports/identity.ts";
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

async function proveDefaultUpstreamBudget(
  app: { inject(input: unknown): Promise<unknown> },
): Promise<void> {
  const q = new URLSearchParams({
    response_type: "code", client_id: "stateless-client", redirect_uri: CLIENT_REDIRECT,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    scope: "mcp:read", state: "client-state",
  });
  const authorize = async () => await app.inject({
    method: "GET", url: `/oauth/authorize?${q}`,
  }) as { statusCode: number; headers: { "set-cookie"?: string } };

  const first = await authorize();
  assert.equal(first.statusCode, 302, "the first authorize charge is admitted");
  const cookie = first.headers["set-cookie"]?.split(";", 1)[0];
  assert.ok(cookie, "authorize minted the upstream flow cookie");

  const callback = await app.inject({
    method: "GET", url: "/oauth/callback", headers: { cookie },
  }) as { statusCode: number };
  assert.equal(callback.statusCode, 400, "callback charge is admitted before its missing-parameter rejection");

  for (let index = 2; index < FASTIFY_DCR_REGISTER_RATE_LIMIT.max; index++) {
    assert.equal((await authorize()).statusCode, 302, `upstream charge ${index + 1} is admitted`);
  }
  assert.equal(
    (await authorize()).statusCode,
    429,
    "authorize and callback consumed the same default upstream:<ip> bucket",
  );
}

async function proveDefaultDirectAuthorizeBudget(
  app: { inject(input: unknown): Promise<unknown> },
  identityCalls: () => number,
): Promise<void> {
  const q = new URLSearchParams({
    response_type: "code", client_id: "stateless-client", redirect_uri: CLIENT_REDIRECT,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    scope: "mcp:read", state: "client-state",
  });
  for (let index = 0; index < FASTIFY_DCR_REGISTER_RATE_LIMIT.max; index++) {
    const response = await app.inject({
      method: "GET", url: `/oauth/authorize?${q}`,
      headers: { "cf-access-jwt-assertion": "identity-token" },
    }) as { statusCode: number };
    assert.equal(response.statusCode, 200, `direct authorize charge ${index + 1} is admitted`);
  }
  const denied = await app.inject({
    method: "GET", url: `/oauth/authorize?${q}`,
    headers: { "cf-access-jwt-assertion": "identity-token" },
  }) as { statusCode: number };
  assert.equal(denied.statusCode, 429, "the default authorize:<ip> bucket denies past its budget");
  assert.equal(identityCalls(), FASTIFY_DCR_REGISTER_RATE_LIMIT.max,
    "quota denial occurs before direct identity verification");
}

function directIdentity(calls: { value: number }): IdentityPort {
  return {
    async verify() {
      calls.value += 1;
      return { ok: true, identity: { subject: "direct-user" } };
    },
  };
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

test("fastify-sqlite example: default stateless authorize and callback charge upstream:<ip>", async () => {
  const built = await buildApp({ config: upstreamConfig(), upstream: { identity: stubIdentity() } });
  try {
    await proveDefaultUpstreamBudget(built.app);
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("api-key-gateway example: default stateless authorize and callback charge upstream:<ip>", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-gateway-default-limit-"));
  const dir = join(base, "state");
  const built = await buildGatewayExample({
    MCP_SSO_DIR: dir,
    OAUTH_ISSUER: ISSUER,
    OAUTH_RESOURCE: `${ISSUER}/mcp`,
    OAUTH_CONSENT_SIGNING_SECRET: randomBytes(32).toString("base64url"),
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(signingJwk()),
    OAUTH_REDIRECT_ALLOWLIST: CLIENT_REDIRECT,
    OIDC_ISSUER: "https://idp.test",
    OIDC_CLIENT_ID: "gateway-client",
    OIDC_REDIRECT_URI: `${ISSUER}/oauth/callback`,
  }, {
    backendUrl: "http://127.0.0.1:1/mcp",
    getBackendCredential: () => "unused",
    identityFactories: { async genericOidc() { return stubIdentity(); } },
  });
  try {
    await proveDefaultUpstreamBudget(built.app);
  } finally {
    await built.app.close();
    await built.store.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("fastify-sqlite example: default stateless direct authorize charges authorize:<ip>", async () => {
  const calls = { value: 0 };
  const built = await buildApp({ config: upstreamConfig(), identity: directIdentity(calls) });
  try {
    await proveDefaultDirectAuthorizeBudget(built.app, () => calls.value);
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("api-key-gateway example: default stateless direct authorize charges authorize:<ip>", async () => {
  const calls = { value: 0 };
  const built = await buildGateway({
    config: upstreamConfig(),
    backendUrl: "http://127.0.0.1:1/mcp",
    getBackendCredential: () => "unused",
    identity: directIdentity(calls),
  });
  try {
    await proveDefaultDirectAuthorizeBudget(built.app, () => calls.value);
  } finally {
    await built.app.close();
    await built.close();
  }
});
