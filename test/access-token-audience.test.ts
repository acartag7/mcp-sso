import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import { importJWK, SignJWT, type JWTPayload } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken, verifyAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const NOW = Date.parse("2026-08-26T12:00:00.000Z");
const clock = { nowMs: () => NOW };
const resource = "https://api.example.com/mcp";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const config = createBridgeConfig({
  issuer: "https://api.example.com", resource,
  consentSigningSecret: randomBytes(32).toString("hex"),
  signingPrivateJwk: privateKey.export({ format: "jwk" }), signingKeyId: "test-key",
  redirectAllowlist: ["https://client.example.com/callback"],
  scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
  allowedOrigins: ["https://api.example.com"], dcr: { mode: "stateless" },
  accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const key = await importJWK(config.signingPrivateJwk, "ES256");
const otherResource = "https://other.example.com/mcp";
const invalidAudiences: ReadonlyArray<readonly [string, unknown]> = [
  ["missing", undefined], ["null", null], ["false", false], ["true", true],
  ["number", 42], ["object", { resource }], ["empty string", ""],
  ["other resource", otherResource], ["case", resource.toUpperCase()],
  ["path", "https://api.example.com/other"], ["trailing slash", `${resource}/`],
  ["leading space", ` ${resource}`], ["trailing space", `${resource} `],
  ["empty array", []], ["foreign array", [otherResource]],
  ["singleton array", [resource]], ["matching first", [resource, otherResource]],
  ["matching last", [otherResource, resource]], ["duplicate matches", [resource, resource]],
  ["mixed members", [resource, 42, null, {}, [resource], false]],
  ["nested array", [[resource]]],
];

function identity(machine: boolean) {
  return machine ? { subject: "mcc_test", clientId: "mcc_test", machine: true }
    : { subject: "test-subject", clientId: "test-client" };
}

for (const machine of [false, true]) {
  const kind = machine ? "machine" : "interactive";
  test(`${kind} access token accepts the exact scalar resource`, async () => {
    const claims = { ...identity(machine), scopes: ["mcp:read"] };
    const token = await signAccessToken(claims, config, clock);
    const expected = { subject: claims.subject, clientId: claims.clientId,
      scopes: claims.scopes, credentialKind: kind };
    assert.deepEqual(await verifyAccessToken(token, config, clock), expected);
    const events: AuthAuditEvent[] = [];
    const authorizer = new RequestAuthorizer({ config, clock,
      audit: { async writeAuthEvent(event) { events.push(event); } } });
    assert.deepEqual(await authorizer.authorize({ authorization: `Bearer ${token}`, requiredScope: "mcp:read" }), expected);
    assert.equal(events.length, 1);
    assert.equal(events[0]?.status, "success");
  });

  for (const [name, aud] of invalidAudiences) {
    test(`${kind} access token rejects ${name} audience before scope or success audit`, async () => {
      const claims = identity(machine);
      const payload = { sub: claims.subject, client_id: claims.clientId, scope: "mcp:read",
        iss: config.issuer, aud, iat: NOW / 1000, exp: NOW / 1000 + 300,
        ...(machine ? { gty: "client_credentials" } : {}) };
      const token = await new SignJWT(payload as JWTPayload)
        .setProtectedHeader({ alg: "ES256", kid: config.signingKeyId, typ: "JWT" }).sign(key);
      const invalidToken = (error: unknown) => error instanceof OAuthError
        && error.code === "invalid_token" && error.status === 401;
      await assert.rejects(verifyAccessToken(token, config, clock), invalidToken);
      const events: AuthAuditEvent[] = [];
      const authorizer = new RequestAuthorizer({ config, clock,
        audit: { async writeAuthEvent(event) { events.push(event); } } });
      for (const requiredScope of [undefined, "mcp:read", "missing:scope"]) {
        await assert.rejects(authorizer.authorize({ authorization: `Bearer ${token}`, requiredScope }), invalidToken);
      }
      assert.deepEqual(events, Array.from({ length: 3 }, () => ({
        occurredAt: new Date(NOW).toISOString(), event: "auth.request", status: "failure", reason: "invalid_token",
      })));
    });
  }
}
