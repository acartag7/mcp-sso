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

const overrides: Array<[string, string[], string]> = [
  ["empty", [], ""],
  ["subset", ["mcp:read"], ', scope="mcp:read"'],
  ["reordered", ["mcp:read", "mcp:write"], ', scope="mcp:read mcp:write"'],
  ["outside catalog", ["custom:scope"], ', scope="custom:scope"'],
  ["duplicates", ["mcp:read", "mcp:read"], ', scope="mcp:read mcp:read"'],
];
const metadata = 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"';
for (const [name, scope, suffix] of overrides) {
  for (const error of [undefined, "invalid_token", "invalid_request", "insufficient_scope"]) {
    test(`${name} scope override is retained with ${error ?? "no error"}`, () => {
      const expected = error ? `${metadata}${suffix}, error="${error}", error_description="Authorization failed"` : `${metadata}${suffix}`;
      assert.equal(buildUnauthorizedChallenge(config, { scope, error, errorDescription: "Authorization failed" }), expected);
    });
  }
  test(`normalized invalid-token error retains the ${name} scope override`, () => {
    const response = oauthErrorResponse(config, new OAuthError("invalid_token", "Authorization failed", 401), { scope });
    assert.equal(response.status, 401);
    assert.equal(response.headers["www-authenticate"], `${metadata}${suffix}, error="invalid_token", error_description="Authorization failed"`);
  });
}

const invalidOverrides: Array<[string, unknown]> = [
  ["null", null], ["boolean", false], ["number", 42], ["string", "mcp:read"], ["object", {}],
  ["sparse", Array(1)], ["undefined entry", [undefined]], ["null entry", [null]],
  ["boolean entry", [true]], ["number entry", [42]], ["nested array", [["mcp:read"]]],
  ["empty token", [""]], ["space", ["mcp:read mcp:write"]], ["quote", ['mcp:"read']],
  ["backslash", ["mcp:\\read"]], ["carriage return", ["mcp:read\r"]], ["newline", ["mcp:read\n"]],
  ["tab", ["mcp:read\t"]], ["null byte", ["mcp:read\u0000"]], ["DEL", ["mcp:read\u007f"]],
  ["non-ASCII", ["mcp:rèad"]], ["129 duplicates", Array(129).fill("mcp:read")],
  ["257-byte token", ["a".repeat(257)]], ["32896-byte claim", [...Array(127).fill("a".repeat(256)), "a".repeat(257)]],
  ["throwing length", new Proxy([], { get() { throw new Error("list unreadable"); } })],
];
const invalidScope = (error: unknown) => error instanceof OAuthError && error.code === "invalid_scope" && error.status === 400;
for (const [name, scope] of invalidOverrides) {
  test(`challenge rejects ${name} before resource URL rendering on both helper paths`, () => {
    let resourceReads = 0;
    const watchedConfig = new Proxy(config, { get(target, field, receiver) {
      if (field === "resource") resourceReads++;
      return Reflect.get(target, field, receiver);
    } });
    assert.throws(() => buildUnauthorizedChallenge(watchedConfig, { scope: scope as string[] }), invalidScope);
    assert.throws(() => oauthErrorResponse(watchedConfig,
      new OAuthError("invalid_token", "Authorization failed", 401), { scope: scope as string[] }), invalidScope);
    assert.equal(resourceReads, 0);
  });
}
for (const [name, scope] of [
  ["128 duplicates", Array(128).fill("mcp:read")], ["256-byte token", ["a".repeat(256)]],
  ["32895-byte list", Array(128).fill("a".repeat(256))],
  ["RFC punctuation", ["!#$%&'()*+,-./:;<=>?@[]^_`{|}~"]],
] as Array<[string, string[]]>) {
  test(`challenge retains the valid ${name} boundary`, () => {
    assert.equal(buildUnauthorizedChallenge(config, { scope }), `${metadata}, scope="${scope.join(" ")}"`);
  });
}
test("challenge uses one bounded list snapshot without the caller iterator", () => {
  let lengthReads = 0;
  let entryReads = 0;
  let iteratorReads = 0;
  const scope = new Proxy(["custom:scope"], { get(target, field, receiver) {
    if (field === "length") { lengthReads++; return lengthReads === 1 ? 1 : 129; }
    if (field === "0") { entryReads++; return entryReads === 1 ? "custom:scope" : 'bad"scope'; }
    if (field === Symbol.iterator) { iteratorReads++; throw new Error("caller iterator used"); }
    return Reflect.get(target, field, receiver);
  } });
  assert.equal(buildUnauthorizedChallenge(config, { scope }), `${metadata}, scope="custom:scope"`);
  assert.deepEqual({ lengthReads, entryReads, iteratorReads }, { lengthReads: 1, entryReads: 1, iteratorReads: 0 });
});
