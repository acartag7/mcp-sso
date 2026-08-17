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
import { Bridge } from "../src/adapters/bridge.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const BUILT_IN = "https://claude.ai/callback";
const OWN = "https://private.test/callback";
const VERIFIER = "release-redirect-mode-verifier-0123456789abcdef01";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function config(mode?: "extend" | "replace", signingPrivateJwk: JWK = jwk()) {
  return createBridgeConfig({
    issuer: "http://localhost", resource: "http://localhost/mcp",
    consentSigningSecret: "r".repeat(40), signingPrivateJwk, signingKeyId: "release",
    redirectAllowlist: [OWN],
    ...(mode ? { redirectAllowlistMode: mode } : {}),
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost"], dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

async function mount(mode?: "extend" | "replace", signingPrivateJwk?: JWK) {
  return await buildApp({
    config: config(mode, signingPrivateJwk),
    identityHeader: "x-release-identity",
    identity: { async verify() { return { ok: true, identity: { subject: "release-user" } }; } },
    acknowledgeUnsafeStatelessDefaults: true,
  } as Parameters<typeof buildApp>[0]);
}

function authorizeQueryFor(clientId: string, redirectUri: string): Record<string, string> {
  return {
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    scope: "mcp:read", state: "s",
  };
}

function authorizeQuery(clientId: string, redirectUri: string): string {
  return new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read",
  }).toString();
}

releaseTest("RM.11 readers 1 and 2: replace refuses a built-in origin at DCR write and stateless authorize", async () => {
  // Mint under the old/default policy, then restart with the same signing key
  // under replace. That gives reader 2 a client whose signed registration
  // genuinely permits BUILT_IN, so only the current global policy can refuse it.
  const signingKey = jwk();
  const { app: extendApp } = await mount("extend", signingKey);
  let builtInClientId: string;
  try {
    const registered = await extendApp.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [BUILT_IN], application_type: "web" }),
    });
    assert.equal(registered.statusCode, 201, registered.body);
    builtInClientId = registered.json<{ client_id: string }>().client_id;
  } finally {
    await extendApp.close();
  }

  const { app } = await mount("replace", signingKey);
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
    const ownClientId = accepted.json<{ client_id: string }>().client_id;

    // Reader 2 — stateless authorize. Even with a legitimately registered client,
    // presenting a built-in origin is refused, and refused DIRECTLY: a redirect
    // would use the untrusted origin to report that it is untrusted.
    const authz = await app.inject({
      method: "GET", url: `/oauth/authorize?${authorizeQuery(builtInClientId, BUILT_IN)}`,
      headers: { "x-release-identity": "release-token" },
    });
    assert.notEqual(authz.statusCode, 200, "replace must refuse a built-in redirect at authorize");
    assert.equal(authz.headers.location, undefined, "a refused redirect_uri must never be redirected to");
    assert.ok(!authz.body.includes("claude.ai"), "the refused origin must not be echoed");

    // The operator's own origin still reaches consent.
    const ok = await app.inject({
      method: "GET", url: `/oauth/authorize?${authorizeQuery(ownClientId, OWN)}`,
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

// --- readers 3 and 4: stored-client revalidation, and consent approve ---------
//
// The first case above covers the DCR write path and stateless authorize. The
// mode has FOUR readers, and the two below are the ones a name-only assertion
// misses — review found `approve` unguarded AFTER the sweep was called complete,
// so the gate proves them rather than trusting the enumeration.

class StoredClients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.rows.set(c.clientId, structuredClone(c)); }
  async find(id: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(id) ?? null); }
}

/** Stored DCR needs a bounded limiter since #253; supply one so boot succeeds. */
const boundedLimiter: RateLimitPort = { async check() { return true; } };

function storedConfig(mode: "extend" | "replace", clients: ClientStore) {
  return createBridgeConfig({
    issuer: "http://localhost", resource: "http://localhost/mcp",
    consentSigningSecret: "r".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
    redirectAllowlist: [OWN],
    ...(mode === "replace" ? { redirectAllowlistMode: "replace" as const } : {}),
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost"], dcr: { mode: "stored", store: clients },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

releaseTest("RM.11 reader 3: a client stored under extend stops authorizing under replace", async () => {
  // The stored-state sibling of the entry-point guard. Seeded directly, exactly
  // as a rolling upgrade would leave it: the record was legitimately written
  // while the built-ins were trusted.
  const clients = new StoredClients();
  await clients.save({
    clientId: "mcpdc_legacy_builtin", redirectUris: [BUILT_IN],
    applicationType: "web", issuedAtEpoch: 1_700_000_000,
  });

  const before = new Bridge({
    config: storedConfig("extend", clients), store: new MemoryStore(),
    clock: { nowMs: () => Date.parse("2026-08-17T12:00:00Z") },
    audit: { async writeAuthEvent() {} }, rateLimit: boundedLimiter,
  });
  const allowed = await before.handleAuthorize({
    query: authorizeQueryFor("mcpdc_legacy_builtin", BUILT_IN),
    body: undefined, headers: {}, ip: "127.0.0.1",
  }, { subject: "release-user" });
  assert.equal(allowed.status, 200, "under extend the stored built-in client still authorizes");

  const after = new Bridge({
    config: storedConfig("replace", clients), store: new MemoryStore(),
    clock: { nowMs: () => Date.parse("2026-08-17T12:00:00Z") },
    audit: { async writeAuthEvent() {} }, rateLimit: boundedLimiter,
  });
  const refused = await after.handleAuthorize({
    query: authorizeQueryFor("mcpdc_legacy_builtin", BUILT_IN),
    body: undefined, headers: {}, ip: "127.0.0.1",
  }, { subject: "release-user" });
  assert.notEqual(refused.status, 200, "a stored built-in registration must stop authorizing under replace");
  assert.equal(refused.redirect, undefined, "and must not be reported by redirecting to the disputed origin");
});

releaseTest("RM.11 reader 4: a consent token minted under extend is refused at approve under replace", async () => {
  // A consent token outlives the process that minted it, so approve is read at a
  // different time from every other reader. Without this, a flow begun seconds
  // before the trust change still delivers a code — or a Deny redirect — to the
  // removed origin.
  const clients = new StoredClients();
  const store = new MemoryStore();
  const clock = { nowMs: () => Date.parse("2026-08-17T12:00:00Z") };

  const reg = await new Bridge({
    config: storedConfig("extend", clients), store, clock,
    audit: { async writeAuthEvent() {} }, rateLimit: boundedLimiter,
  }).handleRegister({
    query: {}, body: { redirect_uris: [BUILT_IN], application_type: "web" },
    headers: { "content-type": "application/json" }, ip: "127.0.0.1",
  });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const clientId = (reg.body as { client_id: string }).client_id;

  const minted = await new Bridge({
    config: storedConfig("extend", clients), store, clock,
    audit: { async writeAuthEvent() {} }, rateLimit: boundedLimiter,
  }).handleAuthorize({
    query: authorizeQueryFor(clientId, BUILT_IN), body: undefined, headers: {}, ip: "127.0.0.1",
  }, { subject: "release-user" });
  assert.equal(minted.status, 200, "the consent page must render while extend is in force");
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(String(minted.body))?.[1];
  assert.ok(consentToken, "consent page must carry a consent token");

  // The restart into "replace" — same store, same consent token, new policy.
  const after = new Bridge({
    config: storedConfig("replace", clients), store, clock,
    audit: { async writeAuthEvent() {} }, rateLimit: boundedLimiter,
  });
  for (const [label, approved] of [["approve", "true"], ["deny", "false"]] as const) {
    const res = await after.handleApprove({
      query: {}, body: { consent_token: consentToken, approved },
      headers: { origin: "http://localhost", "content-type": "application/x-www-form-urlencoded" },
      ip: "127.0.0.1",
    });
    assert.notEqual(res.status, 302, `${label} must not redirect to the removed origin`);
    assert.equal((res.body as { error?: string }).error, "invalid_redirect_uri",
      `${label} must reach the current redirect-policy reader`);
    assert.match((res.body as { error_description?: string }).error_description ?? "", /redirect_uri is not allowed/,
      `${label} must fail for the removed origin, not token verification`);
    assert.equal(
      new URL(res.redirect ?? "http://localhost/none").searchParams.get("code"), null,
      `${label} must not deliver a code to the removed origin`,
    );
  }
});
