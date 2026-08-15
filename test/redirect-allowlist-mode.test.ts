// `redirectAllowlistMode` (contracts §5, §10.1). The built-in hosted-client
// origins are a convenience default, not a fixed part of the trust base: an
// operator running a private deployment can refuse them outright.
//
// The sibling axis here is the THREE places the global allowlist is consulted —
// DCR write, stateless authorize, and the stored-client re-validation leg. A
// mode threaded into one and missed in another is exactly this repo's recurring
// defect, so each leg gets its own behavioral proof rather than one unit test
// of the helper.
import assert from "node:assert/strict";
import { test } from "node:test";

import type { BridgeConfig } from "../src/config.ts";
import { AuthConfigError, createBridgeConfig } from "../src/config.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import { resolveOpaqueRedirect } from "../src/authorize-internals.ts";
import { registerClient } from "../src/register.ts";
import { assertAllowedRedirectUri } from "../src/redirect.ts";

const BUILT_IN = "https://claude.ai/callback";
const OWN = "https://private.test/callback";

class TestClientStore implements ClientStore {
  private readonly records = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> {
    this.records.set(client.clientId, client);
  }
  async find(clientId: string): Promise<ClientRegistration | null> {
    return this.records.get(clientId) ?? null;
  }
}

const clock: ClockPort = { nowMs: () => 1_700_000_000_000 };
const audit: AuditPort = { writeAuthEvent: async () => {} };

function baseInput(overrides: Partial<BridgeConfig> = {}): BridgeConfig {
  return {
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: { kty: "EC", crv: "P-256", d: "d", x: "x", y: "y" },
    signingKeyId: "key-1",
    redirectAllowlist: [OWN],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
    ...overrides,
  };
}

async function rejects(fn: () => Promise<unknown>, pattern: RegExp): Promise<void> {
  await assert.rejects(fn, (error: unknown) => {
    assert.match(String((error as Error).message), pattern);
    return true;
  });
}

// --- boot ------------------------------------------------------------------

test("the mode defaults to extend, preserving the published built-in trust", () => {
  const config = createBridgeConfig(baseInput());
  assert.equal(config.redirectAllowlistMode, "extend");
  assert.equal(assertAllowedRedirectUri(BUILT_IN, config.redirectAllowlist, config.redirectAllowlistMode), BUILT_IN);
});

test("an unknown mode is rejected rather than coerced", () => {
  // A typo must never fall back to "extend": that would silently restore the
  // exact trust the operator was trying to drop.
  for (const bad of ["Replace", "replace ", "", "none", true, null]) {
    assert.throws(
      () => createBridgeConfig(baseInput({ redirectAllowlistMode: bad as never })),
      (error: unknown) => {
        assert.ok(error instanceof AuthConfigError);
        assert.match(error.message, /redirectAllowlistMode must be "extend" or "replace"/);
        return true;
      },
      `expected ${JSON.stringify(bad)} to be rejected`,
    );
  }
});

test("replace with an empty allowlist is a boot failure, not a silent deny-all", () => {
  assert.throws(
    () => createBridgeConfig(baseInput({ redirectAllowlist: [], redirectAllowlistMode: "replace" })),
    (error: unknown) => {
      assert.ok(error instanceof AuthConfigError);
      assert.match(error.message, /requires at least one redirectAllowlist entry/);
      return true;
    },
  );
});

// --- leg 1: stateless authorize --------------------------------------------

test("replace drops built-in trust on the stateless authorize leg", async () => {
  const config = createBridgeConfig(baseInput({ redirectAllowlistMode: "replace" }));
  await rejects(
    () => resolveOpaqueRedirect(config, "client-1", BUILT_IN),
    /redirect_uri is not allowed/,
  );
  assert.equal(await resolveOpaqueRedirect(config, "client-1", OWN), OWN);
});

test("extend keeps built-in trust on the stateless authorize leg", async () => {
  const config = createBridgeConfig(baseInput());
  assert.equal(await resolveOpaqueRedirect(config, "client-1", BUILT_IN), BUILT_IN);
});

// --- leg 2: DCR write ------------------------------------------------------

async function register(config: BridgeConfig, redirectUri: string) {
  return await registerClient(
    { config, clock, audit },
    { redirectUris: [redirectUri], applicationType: "web" },
  );
}

test("replace drops built-in trust on the DCR write leg", async () => {
  const config = createBridgeConfig(baseInput({ redirectAllowlistMode: "replace" }));
  await rejects(() => register(config, BUILT_IN), /redirect_uri is not allowed/);
  assert.deepEqual((await register(config, OWN)).redirect_uris, [OWN]);
});

test("extend keeps built-in trust on the DCR write leg", async () => {
  const config = createBridgeConfig(baseInput());
  assert.deepEqual((await register(config, BUILT_IN)).redirect_uris, [BUILT_IN]);
});

// --- leg 3: stored-client re-validation -------------------------------------

test("replace drops built-in trust when re-validating an already-stored client", async () => {
  // The entry-point guard has a stored-state sibling: a registration written
  // while the built-ins were trusted must stop authorizing once the operator
  // drops them. Seeded directly, as a rolling upgrade would leave it.
  const store = new TestClientStore();
  await store.save({
    clientId: "legacy-1",
    redirectUris: [BUILT_IN],
    applicationType: "web",
    issuedAtEpoch: 1_700_000_000,
  });
  const config = createBridgeConfig(baseInput({
    redirectAllowlistMode: "replace",
    dcr: { mode: "stored", store },
  }));

  await rejects(
    () => resolveOpaqueRedirect(config, "legacy-1", BUILT_IN),
    /redirect_uri is not allowed/,
  );
});

test("extend still authorizes that same stored client", async () => {
  const store = new TestClientStore();
  await store.save({
    clientId: "legacy-1",
    redirectUris: [BUILT_IN],
    applicationType: "web",
    issuedAtEpoch: 1_700_000_000,
  });
  const config = createBridgeConfig(baseInput({ dcr: { mode: "stored", store } }));
  assert.equal(await resolveOpaqueRedirect(config, "legacy-1", BUILT_IN), BUILT_IN);
});
