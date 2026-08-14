import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import {
  AuthConfigError, createBridgeConfig, type BridgeConfig,
  type ScopeHierarchyPolicy,
} from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { requireScope, type AuthorizedSubject } from "../src/scopes.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const RESOURCE = "https://api.test/mcp";
const CATALOG = ["mcp:read", "mcp:write", "mcp:admin"];

function privateJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "scope-key" } as JWK;
}

function config(
  overrides: Partial<BridgeConfig> = {},
  signingPrivateJwk: JWK = privateJwk(),
): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: RESOURCE,
    consentSigningSecret: "s".repeat(40), signingPrivateJwk, signingKeyId: "scope-key",
    redirectAllowlist: [], scopeCatalog: [...CATALOG], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 600,
    consentTokenTtlSeconds: 600, authorizationCodeTtlSeconds: 600,
    ...overrides,
  });
}

function hierarchy(): ScopeHierarchyPolicy {
  return {
    resource: RESOURCE,
    implications: [
      { granted: "mcp:admin", implies: ["mcp:write"] },
      { granted: "mcp:write", implies: ["mcp:read"] },
    ],
  };
}

function subject(scopes: string[]): AuthorizedSubject {
  return { subject: "user-1", clientId: "client-1", scopes, credentialKind: "interactive" };
}

function isInsufficient(error: unknown): boolean {
  return error instanceof OAuthError && error.code === "insufficient_scope" && error.status === 403;
}

test("scope hierarchy: direct helper is exact unless passed a validated policy", () => {
  const checked = config({ scopeHierarchy: hierarchy() });
  const admin = subject(["mcp:admin"]);
  assert.doesNotThrow(() => requireScope(admin, "mcp:admin"));
  assert.throws(() => requireScope(admin, "mcp:read"), isInsufficient);
  assert.doesNotThrow(() => requireScope(admin, "mcp:read", checked.scopeHierarchy));
  assert.throws(() => requireScope(subject(["mcp:read"]), "mcp:admin", checked.scopeHierarchy), isInsufficient);

  const unvalidatedClone = structuredClone(checked.scopeHierarchy) as ScopeHierarchyPolicy;
  assert.throws(() => requireScope(admin, "mcp:read", unvalidatedClone), isInsufficient);
  assert.doesNotThrow(() => requireScope(admin, "mcp:admin", unvalidatedClone));
});

test("scope hierarchy: RequestAuthorizer applies the configured graph without expanding token scopes", async () => {
  const key = privateJwk();
  const hierarchical = config({ scopeHierarchy: hierarchy() }, key);
  const exact = config({}, key);
  const token = await signAccessToken(
    { subject: "user-1", clientId: "client-1", scopes: ["mcp:admin"] },
    hierarchical,
    new SystemClock(),
  );
  const configured = new RequestAuthorizer({ config: hierarchical, clock: new SystemClock(), audit: noopAudit });
  const result = await configured.authorize({ authorization: `Bearer ${token}`, requiredScope: "mcp:read" });
  assert.deepEqual(result.scopes, ["mcp:admin"]);

  const flat = new RequestAuthorizer({ config: exact, clock: new SystemClock(), audit: noopAudit });
  await assert.rejects(
    flat.authorize({ authorization: `Bearer ${token}`, requiredScope: "mcp:read" }),
    isInsufficient,
  );
});

test("scope hierarchy: boot rejects malformed, ambiguous, unknown, and cyclic graphs", () => {
  const symbol = Symbol("hidden");
  const invalid: unknown[] = [
    null,
    [],
    { resource: RESOURCE },
    { resource: "https://other.test/mcp", implications: [] },
    { resource: RESOURCE, implications: [], extra: true },
    { resource: RESOURCE, implications: [], [symbol]: true },
    { resource: RESOURCE, implications: [null] },
    { resource: RESOURCE, implications: [{ granted: "mcp:admin", implies: [], extra: true }] },
    { resource: RESOURCE, implications: [{ granted: "mcp:admin", implies: [] }] },
    { resource: RESOURCE, implications: [{ granted: "mcp:unknown", implies: ["mcp:read"] }] },
    { resource: RESOURCE, implications: [{ granted: "mcp:admin", implies: ["mcp:unknown"] }] },
    { resource: RESOURCE, implications: [
      { granted: "mcp:admin", implies: ["mcp:read"] },
      { granted: "mcp:admin", implies: ["mcp:write"] },
    ] },
    { resource: RESOURCE, implications: [{ granted: "mcp:admin", implies: ["mcp:read", "mcp:read"] }] },
    { resource: RESOURCE, implications: [{ granted: "mcp:admin", implies: ["mcp:admin"] }] },
    { resource: RESOURCE, implications: [
      { granted: "mcp:admin", implies: ["mcp:write"] },
      { granted: "mcp:write", implies: ["mcp:read"] },
      { granted: "mcp:read", implies: ["mcp:admin"] },
    ] },
  ];
  for (const scopeHierarchy of invalid) {
    assert.throws(
      () => config({ scopeHierarchy: scopeHierarchy as ScopeHierarchyPolicy }),
      (error: unknown) => error instanceof AuthConfigError,
    );
  }
});

test("scope hierarchy: row and edge caps reject before unbounded traversal", () => {
  const scopes = Array.from({ length: 128 }, (_, index) => `scope:${index}`);
  const tooManyRows = Array.from({ length: 129 }, () => ({ granted: scopes[0]!, implies: [scopes[1]!] }));
  assert.throws(
    () => config({ scopeCatalog: scopes, defaultScopes: [], scopeHierarchy: { resource: RESOURCE, implications: tooManyRows } }),
    (error: unknown) => error instanceof AuthConfigError,
  );

  const dense: Array<{ granted: string; implies: string[] }> = [];
  for (let from = 0; from < scopes.length - 1; from += 1) {
    dense.push({ granted: scopes[from]!, implies: scopes.slice(from + 1) });
  }
  assert.throws(
    () => config({ scopeCatalog: scopes, defaultScopes: [], scopeHierarchy: { resource: RESOURCE, implications: dense } }),
    (error: unknown) => error instanceof AuthConfigError,
  );
});

test("scope hierarchy: boot snapshots, deeply freezes, and safely maps hostile accessors", () => {
  const targets = ["mcp:read"];
  const row = { granted: "mcp:write", implies: targets };
  const implications = [row];
  const input = { resource: RESOURCE, implications };
  const checked = config({ scopeHierarchy: input });
  row.granted = "mcp:admin";
  targets.push("mcp:admin");
  implications.push({ granted: "mcp:admin", implies: ["mcp:read"] });
  assert.deepEqual(checked.scopeHierarchy, {
    resource: RESOURCE,
    implications: [{ granted: "mcp:write", implies: ["mcp:read"] }],
  });
  assert.equal(Object.isFrozen(checked.scopeHierarchy), true);
  assert.equal(Object.isFrozen(checked.scopeHierarchy?.implications), true);
  assert.equal(Object.isFrozen(checked.scopeHierarchy?.implications[0]), true);
  assert.equal(Object.isFrozen(checked.scopeHierarchy?.implications[0]?.implies), true);

  const hostile = { resource: RESOURCE, implications: [] as ScopeHierarchyPolicy["implications"] };
  Object.defineProperty(hostile, "resource", { enumerable: true, get() { throw new Error("hostile"); } });
  assert.throws(
    () => config({ scopeHierarchy: hostile }),
    (error: unknown) => error instanceof AuthConfigError,
  );
});
