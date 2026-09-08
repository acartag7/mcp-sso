import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import { importJWK, SignJWT } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { verifyAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const now = Date.parse("2026-08-26T12:00:00.000Z");
const clock = { nowMs: () => now };
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const config = createBridgeConfig({
  issuer: "https://api.example.com", resource: "https://api.example.com/mcp",
  signingPrivateJwk: privateKey.export({ format: "jwk" }), signingKeyId: "test-key",
  consentSigningSecret: randomBytes(32).toString("hex"),
  redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
  scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
  allowedOrigins: ["https://api.example.com"], dcr: { mode: "stateless" },
  accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const key = await importJWK(config.signingPrivateJwk, "ES256");
const maxToken = "a".repeat(256);
const maxList = Array(128).fill(maxToken) as string[];
const punctuation = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~";
const good: Array<[string, string, string[]]> = [
  ["empty", "", []], ["catalog scope", "mcp:read", ["mcp:read"]],
  ["removed scope", "retired:read", ["retired:read"]],
  ["order and duplicates", "retired:write mcp:read retired:write", ["retired:write", "mcp:read", "retired:write"]],
  ["128 duplicate entries", Array(128).fill("mcp:read").join(" "), Array(128).fill("mcp:read")],
  ["256-byte token", maxToken, [maxToken]],
  ["32895-byte claim", maxList.join(" "), maxList],
  ["RFC punctuation", punctuation, [punctuation]],
];
const bad: Array<[string, unknown]> = [
  ["missing", undefined], ["null", null], ["false", false], ["true", true], ["number", 42],
  ["object", { scope: "mcp:read" }], ["empty array", []], ["array", ["mcp:read"]],
  ["nested array", [["mcp:read"]]], ["leading space", " mcp:read"], ["trailing space", "mcp:read "],
  ["repeated space", "mcp:read  retired:read"], ["space only", " "],
  ["tab separator", "mcp:read\tretired:read"], ["newline separator", "mcp:read\nretired:read"],
  ["vertical tab", "mcp:read\v"], ["form feed", "mcp:read\f"], ["carriage return", "mcp:read\r"],
  ["trailing newline", "mcp:read\n"], ["null byte", "mcp:read\u0000"], ["DEL", "mcp:read\u007f"],
  ["quote", 'mcp:"read'], ["backslash", "mcp:\\read"], ["non-ASCII", "mcp:rèad"],
  ["nonbreaking space", "mcp:read\u00a0retired:read"], ["line separator", "mcp:read\u2028"],
  ["129 duplicate entries", Array(129).fill("mcp:read").join(" ")],
  ["257-byte token", "a".repeat(257)], ["32896-byte claim", `${maxList.join(" ")}a`],
];
const invalidToken = (error: unknown) => error instanceof OAuthError && error.code === "invalid_token" && error.status === 401;
const insufficientScope = (error: unknown) => error instanceof OAuthError && error.code === "insufficient_scope" && error.status === 403;

async function signed(scope: unknown, machine: boolean): Promise<string> {
  return new SignJWT({
    sub: machine ? "mcc_test" : "test-subject", client_id: machine ? "mcc_test" : "test-client",
    ...(scope === undefined ? {} : { scope }), ...(machine ? { gty: "client_credentials" } : {}),
  }).setProtectedHeader({ alg: "ES256", kid: "test-key", typ: "JWT" })
    .setIssuer(config.issuer).setAudience(config.resource).setIssuedAt(now / 1000).setExpirationTime(now / 1000 + 300).sign(key);
}

for (const machine of [false, true]) {
  const kind = machine ? "machine" : "interactive";
  for (const [name, scope, expected] of good) {
    test(`${kind} scope accepts ${name} without catalog revalidation or normalization`, async () => {
      const token = await signed(scope, machine);
      const verified = await verifyAccessToken(token, config, clock);
      assert.deepEqual(verified.scopes, expected);
      assert.equal(verified.credentialKind, kind);
      const events: AuthAuditEvent[] = [];
      const authorizer = new RequestAuthorizer({ config, clock,
        audit: { async writeAuthEvent(event) { events.push(event); } } });
      assert.deepEqual((await authorizer.authorize({ authorization: `Bearer ${token}` })).scopes, expected);
      if (expected.length) {
        assert.deepEqual((await authorizer.authorize({ authorization: `Bearer ${token}`, requiredScope: expected[0] })).scopes, expected);
      }
      const successEvents = (expected.length ? [undefined, expected[0]] : [undefined]).map(reason => ({
        occurredAt: new Date(now).toISOString(), event: "auth.request", status: "success",
        subject: machine ? "mcc_test" : "test-subject", clientId: machine ? "mcc_test" : "test-client",
        scopes: expected, reason,
      }));
      assert.deepEqual(events, successEvents);
      await assert.rejects(authorizer.authorize({ authorization: `Bearer ${token}`, requiredScope: "absent:scope" }), insufficientScope);
      assert.deepEqual(events, [...successEvents, {
        occurredAt: new Date(now).toISOString(), event: "auth.request", status: "failure", reason: "insufficient_scope",
      }]);
    });
  }
  for (const [name, scope] of bad) {
    test(`${kind} scope rejects ${name} as 401 before scope checking and success audit`, async () => {
      const token = await signed(scope, machine);
      await assert.rejects(verifyAccessToken(token, config, clock), invalidToken);
      const events: AuthAuditEvent[] = [];
      const authorizer = new RequestAuthorizer({ config, clock,
        audit: { async writeAuthEvent(event) { events.push(event); } } });
      for (const requiredScope of [undefined, "mcp:read", "absent:scope"]) {
        await assert.rejects(authorizer.authorize({ authorization: `Bearer ${token}`, requiredScope }), invalidToken);
      }
      assert.deepEqual(events, Array.from({ length: 3 }, () => ({
        occurredAt: new Date(now).toISOString(), event: "auth.request", status: "failure", reason: "invalid_token",
      })));
    });
  }
  test(`${kind} removed scope is retained before expiry and rejected at expiry`, async () => {
    const token = await signed("retired:read", machine);
    assert.deepEqual((await verifyAccessToken(token, config, { nowMs: () => now + 299_999 })).scopes, ["retired:read"]);
    await assert.rejects(verifyAccessToken(token, config, { nowMs: () => now + 300_000 }), invalidToken);
  });
}
