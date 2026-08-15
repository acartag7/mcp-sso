import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { BridgeConfig } from "../src/config.ts";
import { AuthConfigError, createBridgeConfig } from "../src/config.ts";
import { validateAllowedOrigins } from "../src/allowed-origin.ts";
import { assertApproveOrigin } from "../src/authorize-internals.ts";
import {
  allowedOriginsFromEnv, buildExample, configFromEnv,
} from "../examples/fastify-sqlite/app.ts";
import { buildGatewayExample } from "../examples/api-key-gateway/app.ts";

function baseInput(): BridgeConfig {
  return {
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: { kty: "EC", crv: "P-256", d: "d", x: "x", y: "y" },
    signingKeyId: "key-1",
    redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  };
}

test("allowedOrigins accepts only exact canonical HTTP(S) browser origins", () => {
  const accepted = [
    "https://auth.test",
    "https://auth.test:8443",
    "http://localhost:3000",
    "http://insecure.test",
    "http://[::1]:3000",
  ];
  assert.deepEqual(validateAllowedOrigins(accepted), accepted);

  const rejected: Array<[string, RegExp]> = [
    ["null", /opaque browser origin/],
    ["", /must not be empty/],
    ["https://auth.test/", /trailing slash/],
    ["https://auth.test/path", /must not contain a path/],
    ["https://auth.test?x=1", /query delimiter/],
    ["https://auth.test#fragment", /fragment delimiter/],
    ["https://user:password@auth.test", /userinfo/],
    ["https://*.test", /must not contain '\*'/],
    ["https://auth.test\\other", /backslashes/],
    ["https://auth.test\n", /control characters/],
    ["https://auth .test", /whitespace/],
    ["ftp://auth.test", /scheme must be http or https/],
    ["HTTPS://AUTH.TEST", /canonical WHATWG origin spelling/],
    ["https://auth.test:443", /canonical WHATWG origin spelling/],
    ["https://bücher.test", /canonical WHATWG origin spelling/],
    ["https://allowed.test,https://foreign.test", /must not contain a path|parseable absolute origin|canonical WHATWG/],
  ];
  for (const [entry, reason] of rejected) {
    assert.throws(
      () => validateAllowedOrigins([entry]),
      (error: unknown) => error instanceof AuthConfigError && reason.test(error.message),
      `${JSON.stringify(entry)} must reject with its grammar reason`,
    );
  }
  assert.throws(() => validateAllowedOrigins("https://auth.test"), AuthConfigError);
  assert.throws(() => validateAllowedOrigins([7]), AuthConfigError);
  const huge = `https://${"a".repeat(2048)}.test`;
  let caught: unknown;
  assert.throws(() => validateAllowedOrigins([huge]), (error: unknown) => {
    caught = error;
    return error instanceof AuthConfigError && /2048 UTF-8 bytes/.test(error.message);
  });
  assert.ok((caught as Error).message.length < 300, "over-bound errors do not echo the full entry");
});

test("createBridgeConfig wires allowedOrigins grammar while issuer-origin and empty-list paths stay valid", () => {
  for (const entry of ["null", "https://auth.test/", "data:text/plain,opaque"]) {
    assert.throws(
      () => createBridgeConfig({ ...baseInput(), allowedOrigins: [entry] }),
      AuthConfigError,
      `${entry} must fail at the authoritative config boundary`,
    );
  }
  const config = createBridgeConfig({ ...baseInput(), allowedOrigins: [] });
  assert.deepEqual(config.allowedOrigins, []);
  assert.doesNotThrow(() => assertApproveOrigin(config, "https://auth.test"));
  assert.throws(() => assertApproveOrigin(config, "null"), /Origin not allowed/);
});

test("env composition derives the issuer origin and preserves an explicit empty allowlist", () => {
  const required = {
    OAUTH_ISSUER: "https://auth.test/tenant/",
    OAUTH_RESOURCE: "https://api.test/mcp",
    OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(baseInput().signingPrivateJwk),
  };
  assert.deepEqual(configFromEnv(required).allowedOrigins, ["https://auth.test"]);
  assert.deepEqual(configFromEnv({ ...required, OAUTH_ALLOWED_ORIGINS: "" }).allowedOrigins, []);
  assert.deepEqual(
    configFromEnv({ ...required, OAUTH_ALLOWED_ORIGINS: "https://one.test,https://two.test" }).allowedOrigins,
    ["https://one.test", "https://two.test"],
  );
});

test("env composition validates raw allowed-origin spellings before normalization", () => {
  for (const raw of [
    " https://trusted.test", "https://trusted.test ", "https://trusted.test,",
    ",https://trusted.test", "https://one.test,,https://two.test", " ",
  ]) {
    assert.throws(
      () => allowedOriginsFromEnv({ OAUTH_ALLOWED_ORIGINS: raw }, "https://auth.test/tenant/"),
      AuthConfigError,
      `${JSON.stringify(raw)} must not be trimmed or filtered into a valid allowlist`,
    );
  }
});

test("both zero-setup examples reject malformed origin config before state creation", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-origin-preflight-"));
  const targets = [
    {
      name: "fastify",
      dir: join(root, "fastify"),
      run: (dir: string) => buildExample({ MCP_SSO_DIR: dir, OAUTH_ALLOWED_ORIGINS: "null" }),
    },
    {
      name: "gateway",
      dir: join(root, "gateway"),
      run: (dir: string) => buildGatewayExample(
        { MCP_SSO_DIR: dir, OAUTH_ALLOWED_ORIGINS: "null" },
        { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" },
      ),
    },
  ];
  try {
    for (const target of targets) {
      await assert.rejects(target.run(target.dir), AuthConfigError, `${target.name} must reject`);
      assert.equal(existsSync(target.dir), false, `${target.name} must leave no state directory`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
