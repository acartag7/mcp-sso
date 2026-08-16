// RM.11 — `redirectAllowlistMode: "replace"` through a shipped Fastify route.
//
// This is a composition row, not a unit test. The mode is a security control
// whose whole purpose is that a private deployment can refuse the built-in
// hosted-client origins, and it is read in FOUR places: the DCR write path, the
// stateless authorize path, the stored-client re-validation leg, and consent
// approve. That count is four rather than three because review found `approve`
// unguarded AFTER the sweep was declared complete — so the release gate should
// prove the readers rather than trust that they were enumerated.
//
// Every assertion below runs against the shipped example app over real routes.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { AuthConfigError } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const BUILT_IN = "https://claude.ai/callback";
const OWN = "https://private.test/callback";
const VERIFIER = "release-redirect-mode-verifier-0123456789abcdef01";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function config(mode?: "extend" | "replace") {
  return createBridgeConfig({
    issuer: "http://localhost", resource: "http://localhost/mcp",
    consentSigningSecret: "r".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
    redirectAllowlist: [OWN],
    ...(mode ? { redirectAllowlistMode: mode } : {}),
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost"], dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

async function mount(mode?: "extend" | "replace") {
  return await buildApp({
    config: config(mode),
    identityHeader: "x-release-identity",
    identity: { async verify() { return { ok: true, identity: { subject: "release-user" } }; } },
    acknowledgeUnsafeStatelessDefaults: true,
  } as Parameters<typeof buildApp>[0]);
}

function authorizeQuery(clientId: string, redirectUri: string): string {
  return new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read",
  }).toString();
}

releaseTest("RM.11 replace mode refuses a built-in hosted origin at every shipped reader", async () => {
  const { app } = await mount("replace");
  try {
    // Reader 1 — DCR write. A hosted origin cannot even register.
    const rejected = await app.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [BUILT_IN], application_type: "web" }),
    });
    assert.notEqual(rejected.statusCode, 201, "replace must refuse a built-in origin at registration");
    assert.doesNotMatch(rejected.body, /client_id/, "no client may be minted for a refused origin");

    // The operator's own origin still registers — the mode narrows trust, it does
    // not disable registration.
    const accepted = await app.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [OWN], application_type: "web" }),
    });
    assert.equal(accepted.statusCode, 201, accepted.body);
    const clientId = accepted.json<{ client_id: string }>().client_id;

    // Reader 2 — stateless authorize. Even with a legitimately registered client,
    // presenting a built-in origin is refused, and refused DIRECTLY: a redirect
    // would use the untrusted origin to report that it is untrusted.
    const authz = await app.inject({
      method: "GET", url: `/oauth/authorize?${authorizeQuery(clientId, BUILT_IN)}`,
      headers: { "x-release-identity": "release-token" },
    });
    assert.notEqual(authz.statusCode, 200, "replace must refuse a built-in redirect at authorize");
    assert.equal(authz.headers.location, undefined, "a refused redirect_uri must never be redirected to");
    assert.ok(!authz.body.includes("claude.ai"), "the refused origin must not be echoed");

    // The operator's own origin still reaches consent.
    const ok = await app.inject({
      method: "GET", url: `/oauth/authorize?${authorizeQuery(clientId, OWN)}`,
      headers: { "x-release-identity": "release-token" },
    });
    assert.equal(ok.statusCode, 200, ok.body);
    assert.match(ok.body, /consent_token/, "the configured origin still reaches the consent page");
  } finally {
    await app.close();
  }
});

releaseTest("RM.11 extend remains the default, so an existing deployment is unchanged", async () => {
  // The whole compatibility promise of this feature: omitting the mode keeps the
  // published behavior. If this row ever fails, every deployment that never set
  // the option has silently changed.
  const { app } = await mount();
  try {
    const registered = await app.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [BUILT_IN], application_type: "web" }),
    });
    assert.equal(registered.statusCode, 201, registered.body);
    const clientId = registered.json<{ client_id: string }>().client_id;

    const authz = await app.inject({
      method: "GET", url: `/oauth/authorize?${authorizeQuery(clientId, BUILT_IN)}`,
      headers: { "x-release-identity": "release-token" },
    });
    assert.equal(authz.statusCode, 200, "the built-in origin still authorizes under the default mode");
  } finally {
    await app.close();
  }
});

releaseTest("RM.11 replace with an empty allowlist refuses to boot", async () => {
  // Fail-closed rather than a deployment that starts and rejects every client.
  assert.throws(
    () => createBridgeConfig({ ...config("extend"), redirectAllowlist: [], redirectAllowlistMode: "replace" }),
    (error: unknown) => {
      assert.ok(error instanceof AuthConfigError);
      assert.match(error.message, /requires at least one redirectAllowlist entry/);
      return true;
    },
  );
});
