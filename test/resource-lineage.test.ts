// MR3 resource-lineage tests (contracts §9.7, §11 0.4.0 amendment, §14
// invalid_target amendment). Covers the authorize `||` fail-open regression,
// multi-resource request selection, code-exchange lineage burn, prior-grant
// isolation, and token-endpoint empty-string rejection.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type {
  ActiveMachineClientRegistration, MachineClientMutationAudit, MachineClientStore,
  VersionedMachineClientRegistration,
} from "../src/ports/client-store.ts";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { OAuthError } from "../src/errors.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { INVALID_RESOURCE, resourceParam } from "../src/adapters/http.ts";
import { buildResourceCatalog, resolveResource } from "../src/resource.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { OAuthTokenUseCase } from "../src/token.ts";
import {
  generateRefreshToken, parseRefreshFamilyId, pkceChallenge, sha256Hex,
} from "../src/crypto.ts";
import { provisionMachineClient, type MachineClientDeps } from "../src/machine-client.ts";
import type { ResourceDefinition } from "../src/resource.ts";

const A = "https://a.test/mcp";
const B = "https://b.test/mcp";
const REDIRECT = "https://client.test/callback";
const VERIFIER = "resource-lineage-verifier-0123456789abcdef0";
const CHALLENGE = pkceChallenge(VERIFIER);
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const SIGNING_JWK = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "rl" } as JWK;

class TestClientStore implements ClientStore {
  private readonly records = new Map<string, ClientRegistration>();
  async save(record: ClientRegistration): Promise<void> { this.records.set(record.clientId, record); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.records.get(clientId) ?? null; }
}

function commonFields() {
  return {
    issuer: "https://auth.test",
    consentSigningSecret: "resource-lineage-test-secret-long-enough",
    signingPrivateJwk: SIGNING_JWK,
    signingKeyId: "rl",
    redirectAllowlist: [REDIRECT],
    allowedOrigins: ["https://auth.test"],
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  };
}

function singletonConfig(): BridgeConfig {
  return createBridgeConfig({
    ...commonFields(),
    resource: A,
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    dcr: { mode: "stateless" },
  });
}

/** Stored-DCR singleton: the branch where prior-scope accumulation is possible,
 *  so the resource-binding capability is required even with one resource. */
function storedDcrConfig(): BridgeConfig {
  return createBridgeConfig({
    ...commonFields(),
    resource: A,
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    dcr: { mode: "stored", store: new TestClientStore() },
  });
}

function multiConfig(dcrMode: "stateless" | "stored" = "stateless", store?: ClientStore): BridgeConfig {
  const resources: ResourceDefinition[] = [
    { resource: A, scopeCatalog: ["shared", "a:read"], defaultScopes: ["a:read"] },
    { resource: B, scopeCatalog: ["shared", "b:write"], defaultScopes: ["b:write"] },
  ];
  return Object.freeze({
    ...commonFields(),
    resources,
    ...(dcrMode === "stored" && store ? { dcr: { mode: "stored", store } } : { dcr: { mode: "stateless" } }),
  }) as unknown as BridgeConfig;
}

function invalidTarget(error: unknown): boolean {
  return error instanceof OAuthError && error.code === "invalid_target";
}

function futureIso(): string {
  return new Date(Date.now() + 60_000).toISOString();
}

function basePrepareInput(resource?: string, scope = "mcp:read"): {
  subject: string; clientId: string; redirectUri: string; responseType: string;
  codeChallenge: string; codeChallengeMethod: string; scope: string; resource?: string;
} {
  return {
    subject: "user-1", clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: CHALLENGE, codeChallengeMethod: "S256", scope,
    ...(resource !== undefined ? { resource } : {}),
  };
}

// ---------------------------------------------------------------------------
// A. Empty-string resource rejected at AUTHORIZE (the `||` fail-open regression)
// ---------------------------------------------------------------------------

test("authorize rejects an empty-string resource (singleton — the || fail-open regression)", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: singletonConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare(basePrepareInput("")),
    invalidTarget,
    "empty-string resource must not silently fall back to config.resource",
  );
});

test("authorize rejects an empty-string resource (multi-resource catalog)", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: multiConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare(basePrepareInput("", "a:read")),
    invalidTarget,
  );
});

// ---------------------------------------------------------------------------
// B. Unknown / repeated / array resource rejected
// ---------------------------------------------------------------------------

test("authorize rejects an unknown resource", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: multiConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare(basePrepareInput("https://evil.test/mcp", "shared")),
    invalidTarget,
  );
});

test("authorize rejects an array-valued resource (repeated parameter)", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: multiConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare({ ...basePrepareInput(undefined, "shared"), resource: [A, B] } as never),
    invalidTarget,
    "an array (repeated parameter) must not collapse to first/last wins",
  );
});

test("authorize rejects a malformed resource URL", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: multiConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare(basePrepareInput("not-a-url", "shared")),
    invalidTarget,
  );
});

// ---------------------------------------------------------------------------
// C. Omission: OK for one entry, invalid_target for multi
// ---------------------------------------------------------------------------

test("authorize resolves an omitted resource for a singleton catalog", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: singletonConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  const result = await auth.prepare(basePrepareInput());
  assert.equal(result.resource, A, "omitted resource resolved to the sole catalog entry");
});

test("authorize rejects an omitted resource when the catalog has two entries", async () => {
  const auth = new OAuthAuthorizationUseCase({
    config: multiConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    auth.prepare(basePrepareInput(undefined, "shared")),
    invalidTarget,
    "omission is ambiguous with two resources",
  );
});

// ---------------------------------------------------------------------------
// D. Code exchange mismatch BURNS the code and returns invalid_target
// ---------------------------------------------------------------------------

test("code exchange with a resource not in the catalog burns the code and returns invalid_target", async () => {
  const store = new MemoryStore();
  const token = new OAuthTokenUseCase({
    config: singletonConfig(), store, clock: new SystemClock(), audit: noopAudit,
  });
  const BOGUS = "https://evil.test/mcp";
  const rawCode = "lineage-mismatch-code";
  await store.saveAuthCode({
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "user-1",
    redirectUri: REDIRECT, resource: BOGUS, scopes: ["mcp:read"],
    codeChallenge: CHALLENGE, codeChallengeMethod: "S256",
    expiresAt: futureIso(), grantGeneration: null,
  });
  // First exchange: code is consumed (burned), resource recheck throws invalid_target.
  await assert.rejects(
    token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: rawCode, redirectUri: REDIRECT,
      clientId: "client-1", codeVerifier: VERIFIER,
    }),
    invalidTarget,
    "mismatched resource exchange returns invalid_target",
  );
  // Second exchange: the code is GONE (burned) → invalid_grant, not invalid_target.
  await assert.rejects(
    token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: rawCode, redirectUri: REDIRECT,
      clientId: "client-1", codeVerifier: VERIFIER,
    }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant",
    "code was burned by the first (failed) exchange",
  );
});

// ---------------------------------------------------------------------------
// E. Prior-grant isolation: a grant for A is not evidence at B
// ---------------------------------------------------------------------------

test("prior grants are isolated by resource even when both share a scope string", async () => {
  const clients = new TestClientStore();
  await clients.save({
    clientId: "stored-client", redirectUris: [REDIRECT],
    applicationType: "web", issuedAtEpoch: 1,
  });
  const config = multiConfig("stored", clients);
  const store = new MemoryStore();
  const auth = new OAuthAuthorizationUseCase({
    config, store, clock: new SystemClock(), audit: noopAudit,
  });

  // Seed an ACTIVE refresh-token family for resource A carrying scope "shared".
  const rawRefresh = generateRefreshToken();
  const familyId = parseRefreshFamilyId(rawRefresh);
  assert.ok(familyId);
  await store.saveRefreshToken({
    tokenHash: sha256Hex(rawRefresh), familyId, previousTokenHash: null,
    clientId: "stored-client", subject: "user-1", scopes: ["shared"],
    expiresAt: futureIso(), grantGeneration: STORED_DCR_GRANT_GENERATION,
    resource: A,
  });

  // Prepare for B: the A-grant must NOT contribute "shared" as a prior grant.
  const atB = await auth.prepare({
    subject: "user-1", clientId: "stored-client", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: CHALLENGE, codeChallengeMethod: "S256", resource: B, scope: "shared",
  });
  assert.deepEqual(atB.priorScopes, [], "grant for A is not prior-grant evidence at B");

  // Prepare for A: the A-grant DOES contribute "shared".
  const atA = await auth.prepare({
    subject: "user-1", clientId: "stored-client", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: CHALLENGE, codeChallengeMethod: "S256", resource: A, scope: "shared",
  });
  assert.deepEqual(atA.priorScopes, ["shared"], "grant for A is prior-grant evidence at A");
});

// ---------------------------------------------------------------------------
// F. Empty-string resource rejected at TOKEN (client_credentials grant)
//    — token.ts:173 was already fail-closed; this verifies it stays that way.
// ---------------------------------------------------------------------------

class MachineTestStore implements MachineClientStore {
  private readonly clients = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.clients.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
  async createMachineClient(c: ActiveMachineClientRegistration, _a: MachineClientMutationAudit): Promise<boolean> {
    if (this.clients.has(c.clientId)) return false;
    this.clients.set(c.clientId, c);
    return true;
  }
  async compareAndSwapMachineClient(
    ev: number, c: VersionedMachineClientRegistration, _a: MachineClientMutationAudit,
  ): Promise<boolean> {
    const cur = this.clients.get(c.clientId);
    if (!cur || cur.applicationType !== "machine") return false;
    const cv = "version" in cur ? cur.version : 0;
    if (cv !== ev) return false;
    this.clients.set(c.clientId, c);
    return true;
  }
}

test("client_credentials rejects an empty-string resource at the token endpoint", async () => {
  const clientStore = new MachineTestStore();
  const config = createBridgeConfig({
    ...commonFields(),
    resource: A,
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    dcr: { mode: "stored", store: clientStore },
    clientCredentials: { enabled: true },
  });
  const machineDeps: MachineClientDeps = {
    store: clientStore, catalog: config.scopeCatalog, clock: new SystemClock(), audit: noopAudit,
  };
  const provisioned = await provisionMachineClient(machineDeps, { allowedScopes: ["mcp:read"] });
  const token = new OAuthTokenUseCase({
    config, store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  });
  await assert.rejects(
    token.exchangeClientCredentials({
      grantType: "client_credentials",
      clientId: provisioned.clientId,
      clientSecret: provisioned.clientSecret,
      resource: "",
    }),
    invalidTarget,
    "empty-string resource must not silently match config.resource",
  );
});

test("a store without the resourceBinding marker is rejected at construction", () => {
  // The capability gate is what stops a custom store that silently IGNORES the
  // resource argument from participating in prior-scope accumulation. It must
  // fire at construction — before any store write, audit event, or route
  // registration — not on the first refresh.
  const narrow = new MemoryStore() as unknown as Record<string, unknown>;
  Object.defineProperty(narrow, "resourceBinding", { value: undefined, configurable: true });
  const deps = { store: narrow as never, clock: new SystemClock(), audit: noopAudit };

  // stored-DCR singleton: required because findGrantedScopes returns only scopes,
  // so the use-case cannot repair a store that ignored the resource predicate.
  assert.throws(
    () => new OAuthAuthorizationUseCase({ config: storedDcrConfig(), ...deps }),
    /resourceBinding 1 is required/,
  );
  assert.throws(
    () => new OAuthTokenUseCase({ config: storedDcrConfig(), ...deps }),
    /resourceBinding 1 is required/,
  );
  // The compliant reference store constructs fine.
  assert.ok(new OAuthAuthorizationUseCase({
    config: storedDcrConfig(), store: new MemoryStore(), clock: new SystemClock(), audit: noopAudit,
  }));
});

test("adapter boundary does not collapse an invalid resource into omission", () => {
  // The core resolver is fail-closed, but the HTTP boundary reached it FIRST:
  // queryString() returned value[0] for a repeated parameter and formField()
  // mapped "" and non-strings to undefined. Omission is MEANINGFUL for resource
  // (it selects the sole configured entry), so collapsing junk into omission
  // silently selected a resource the caller never asked for.
  assert.equal(resourceParam(undefined), undefined, "genuine omission stays omission");
  assert.equal(resourceParam(A), A, "a valid string passes through");
  assert.equal(resourceParam(""), INVALID_RESOURCE, "empty string is not omission");
  assert.equal(resourceParam([A, B]), INVALID_RESOURCE, "repeated parameter is not first-wins");
  assert.equal(resourceParam([A]), INVALID_RESOURCE, "even a single-element array is repeated syntax");
  assert.equal(resourceParam(42), INVALID_RESOURCE, "a non-string is not omission");
  assert.equal(resourceParam(null), INVALID_RESOURCE, "null is not omission");
  // The sentinel can never match a configured resource: it is non-canonical.
  const catalog = buildResourceCatalog(
    { resource: A, scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"] },
    { allowInsecureLocalhost: false },
  );
  assert.throws(() => resolveResource(catalog, INVALID_RESOURCE), invalidTarget);
});
