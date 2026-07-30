// The public overload set must accept the documented union, not just the two
// narrow shapes. A caller that picks singleton or multi-resource config at
// runtime holds `AnyBridgeConfig`; without a union overload TypeScript hides
// the implementation signature and the call fails TS2769 even though the
// implementation handles that exact type.
//
// This is a COMPILE-TIME contract: the assertions below are type-level, and the
// guard is `pnpm run typecheck` (tsconfig includes test/). The runtime test
// exists so the file is also exercised by `node --test`.

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { createBridgeConfig } from "../src/config.ts";
import type { AnyBridgeConfig, BridgeConfig, MultiResourceBridgeConfig } from "../src/config.ts";

declare const dynamicConfig: AnyBridgeConfig;
declare const singletonConfig: BridgeConfig;
declare const multiConfig: MultiResourceBridgeConfig;

// Union input compiles (the TS2769 regression this pins).
export type AcceptsUnion = ReturnType<typeof acceptsUnion>;
function acceptsUnion() { return createBridgeConfig(dynamicConfig); }

// The narrow overloads must still narrow — a union overload that swallowed
// these would lose the precise return type at every existing call site.
function keepsSingleton(): BridgeConfig { return createBridgeConfig(singletonConfig); }
function keepsMulti(): MultiResourceBridgeConfig { return createBridgeConfig(multiConfig); }

test("createBridgeConfig accepts a runtime-selected config union", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" };
  const common = {
    issuer: "https://auth.test",
    consentSigningSecret: "overload-test-consent-secret-with-entropy",
    signingPrivateJwk: jwk, signingKeyId: "k",
    redirectAllowlist: [], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" as const },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 600,
    consentTokenTtlSeconds: 600, authorizationCodeTtlSeconds: 600,
  };
  const chosen: AnyBridgeConfig = {
    ...common,
    resources: [{ resource: "https://api.test/alpha", scopeCatalog: ["a"], defaultScopes: ["a"] }],
  } as AnyBridgeConfig;
  const built = createBridgeConfig(chosen);
  assert.equal(built.issuer, "https://auth.test");
  assert.ok(Object.isFrozen(built), "the returned config is frozen");
  assert.equal(typeof keepsSingleton, "function");
  assert.equal(typeof keepsMulti, "function");
});
