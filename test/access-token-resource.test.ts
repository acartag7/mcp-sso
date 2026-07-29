import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, importJWK, SignJWT } from "jose";
import type { JWK } from "jose";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { signAccessToken, verifyAccessToken } from "../src/crypto.ts";
import { AuthConfigError, createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import { noopAudit } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ResourceDefinition } from "../src/resource.ts";
import { canonicalResource } from "../src/resource.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const NOW_MS = Date.parse("2026-07-29T12:00:00.000Z");
const clock: ClockPort = { nowMs: () => NOW_MS };
const A = "https://a.test/mcp";
const B = "https://b.test/mcp";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signingPrivateJwk = {
  ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "resource-test-key",
} as JWK;

function commonConfig() {
  return {
    issuer: "https://auth.test",
    consentSigningSecret: "resource-test-consent-secret-with-enough-entropy",
    signingPrivateJwk,
    signingKeyId: "resource-test-key",
    redirectAllowlist: [],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" as const },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 600,
    consentTokenTtlSeconds: 600,
    authorizationCodeTtlSeconds: 600,
  };
}

function singletonConfig(): BridgeConfig {
  return createBridgeConfig({
    ...commonConfig(), resource: A,
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
  });
}

function multiConfig(): BridgeConfig {
  const resources: ResourceDefinition[] = [
    { resource: A, scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"] },
    { resource: B, scopeCatalog: ["mcp:write"], defaultScopes: ["mcp:write"] },
  ];
  // The public BridgeConfig union activates in MR5; this slice consumes the
  // already-specified future shape through the MR1a catalog authority.
  return Object.freeze({ ...commonConfig(), resources }) as unknown as BridgeConfig;
}

function claims(resource: string) {
  return { subject: "operator", clientId: "client-1", scopes: ["mcp:read"], resource };
}

function invalidToken(error: unknown): boolean {
  return error instanceof OAuthError && error.code === "invalid_token" && error.status === 401;
}

async function multiAudienceToken(config: BridgeConfig): Promise<string> {
  const now = Math.floor(NOW_MS / 1000);
  const key = await importJWK(config.signingPrivateJwk, "ES256");
  return await new SignJWT({ client_id: "client-1", scope: "mcp:read" })
    .setProtectedHeader({ alg: "ES256", kid: config.signingKeyId, typ: "JWT" })
    .setIssuer(config.issuer)
    .setSubject("operator")
    .setAudience([A, B])
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTokenTtlSeconds)
    .sign(key);
}

test("access token signing requires an explicit resource even for a singleton", async () => {
  const config = singletonConfig();
  const missing = { subject: "operator", clientId: "client-1", scopes: ["mcp:read"] };
  await assert.rejects(
    signAccessToken(missing as ReturnType<typeof claims>, config, clock),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_target",
  );
});

test("access token round-trips one primitive-string audience and returns its resource", async () => {
  const config = singletonConfig();
  const token = await signAccessToken(claims(A), config, clock);
  assert.equal(decodeJwt(token).aud, A);
  const verified = await verifyAccessToken(token, config, clock);
  assert.equal(verified.resource, A);
  assert.deepEqual(verified, {
    subject: "operator", clientId: "client-1", scopes: ["mcp:read"],
    resource: A, credentialKind: "interactive",
  });
});

test("access token verification rejects a wrong resource and multi-catalog omission", async () => {
  const config = multiConfig();
  const token = await signAccessToken(claims(A), config, clock);
  await assert.rejects(verifyAccessToken(token, config, clock, B), invalidToken);
  await assert.rejects(verifyAccessToken(token, config, clock), invalidToken);
});

test("signed aud [A, B] is invalid at A and at B despite jose membership matching", async () => {
  const config = multiConfig();
  const token = await multiAudienceToken(config);
  await assert.rejects(verifyAccessToken(token, config, clock, A), invalidToken);
  await assert.rejects(verifyAccessToken(token, config, clock, B), invalidToken);
});

test("RequestAuthorizer pins one catalog resource at construction", async () => {
  const singleton = singletonConfig();
  assert.equal(new RequestAuthorizer({ config: singleton, clock, audit: noopAudit }).resource, A);

  const multi = multiConfig();
  assert.throws(
    () => new RequestAuthorizer({ config: multi, clock, audit: noopAudit }),
    (error: unknown) => error instanceof AuthConfigError,
  );
  assert.throws(
    () => new RequestAuthorizer({ config: multi, clock, audit: noopAudit, resource: "https://unknown.test/mcp" }),
    (error: unknown) => error instanceof AuthConfigError,
  );

  const authorizer = new RequestAuthorizer({ config: multi, clock, audit: noopAudit, resource: A });
  assert.match(
    buildUnauthorizedChallenge(multi, { resource: authorizer.resource }),
    /^Bearer resource_metadata="https:\/\/a\.test\/\.well-known\/oauth-protected-resource\/mcp"/,
  );
  const token = await signAccessToken(claims(A), multi, clock);
  const input = { authorization: `Bearer ${token}`, resource: B };
  const authorized = await authorizer.authorize(input);
  assert.equal(authorized.resource, A, "request data cannot repoint the constructed authorizer");
  await assert.rejects(
    new RequestAuthorizer({ config: multi, clock, audit: noopAudit, resource: B })
      .authorize({ authorization: `Bearer ${token}` }),
    invalidToken,
  );
});

const CANON = { allowInsecureLocalhost: false } as const;

test("the already-canonical fast path cannot widen the accepted audience", () => {
  // configuredResource() short-circuits when the caller's pinned resource is
  // already its own canonical form. That is safe only because canonicalResource
  // is IDEMPOTENT: a non-canonical string is never its own canonical form, so it
  // falls through to full catalog resolution instead of being trusted as-is.
  for (const raw of [
    "https://a.test/mcp", "https://a.test", "https://a.test/", "https://A.test/mcp",
    "https://a.test:443/mcp", "https://a.test/a/../mcp", "https://a.test/mcp/",
    "https://a.test//mcp", "https://a.test/%6dcp", "https://[::1]/mcp",
    "https://a.test:8443/mcp", "https://a.test./mcp",
  ]) {
    const once = canonicalResource(raw, CANON);
    assert.equal(canonicalResource(once, CANON), once, `not idempotent: ${raw}`);
    // The fast path fires iff the input already equals its canonical form.
    assert.equal(once === raw, raw === once, `fast-path condition diverged: ${raw}`);
  }
});
