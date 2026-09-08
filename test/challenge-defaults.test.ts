import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import { oauthErrorResponse } from "../src/adapters/http.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const config = createBridgeConfig({
  issuer: "https://auth.example.com", resource: "https://api.example.com/tools/mcp",
  consentSigningSecret: randomBytes(32).toString("hex"),
  signingPrivateJwk: privateKey.export({ format: "jwk" }), signingKeyId: "test-key",
  redirectAllowlist: ["https://client.example.com/callback"],
  scopeCatalog: ["mcp:write", "mcp:read"], defaultScopes: ["mcp:read"],
  allowedOrigins: ["https://auth.example.com"], dcr: { mode: "stateless" },
  accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const base = 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", scope="mcp:write mcp:read"';

test("omitted challenge options advertise the catalog at the resource origin", () => {
  assert.equal(buildUnauthorizedChallenge(config), base);
});
test("empty challenge options advertise the catalog", () => {
  assert.equal(buildUnauthorizedChallenge(config, {}), base);
});
test("an undefined scope option advertises the catalog", () => {
  assert.equal(buildUnauthorizedChallenge(config, { scope: undefined }), base);
});
test("the explicit catalog retains its order and values", () => {
  assert.equal(buildUnauthorizedChallenge(config, { scope: config.scopeCatalog }), base);
});

for (const error of ["invalid_token", "invalid_request", "insufficient_scope"]) {
  test(`${error} without a description retains the default catalog`, () => {
    assert.equal(buildUnauthorizedChallenge(config, { error }), `${base}, error="${error}"`);
  });
  test(`${error} with a description retains the default catalog`, () => {
    assert.equal(buildUnauthorizedChallenge(config, { error, errorDescription: "Authorization failed" }),
      `${base}, error="${error}", error_description="Authorization failed"`);
  });
}
test("a description without an error does not invent a rejection reason", () => {
  assert.equal(buildUnauthorizedChallenge(config, { errorDescription: "Description alone" }), base);
});
test("an empty error description is omitted", () => {
  assert.equal(buildUnauthorizedChallenge(config, { error: "invalid_token", errorDescription: "" }),
    `${base}, error="invalid_token"`);
});
test("known error descriptions escape quotes and backslashes", () => {
  assert.equal(buildUnauthorizedChallenge(config, {
    error: "insufficient_scope", errorDescription: 'Need "read" \\ "write"',
  }), `${base}, error="insufficient_scope", error_description="Need \\"read\\" \\\\ \\"write\\""`);
});
test("normalized OAuth errors with an empty challenge use the catalog", () => {
  const response = oauthErrorResponse(config, new OAuthError("invalid_token", "Bearer token is invalid", 401), {});
  assert.equal(response.status, 401);
  assert.equal(response.headers?.["www-authenticate"], `${base}, error="invalid_token", error_description="Bearer token is invalid"`);
});
test("normalized OAuth errors without a challenge stay on their own error channel", () => {
  const response = oauthErrorResponse(config, new OAuthError("invalid_token", "Bearer token is invalid", 401));
  assert.deepEqual(response.headers, {});
});
